// Package masque implements an RFC 9298 CONNECT-UDP (MASQUE) proxy client
// on top of HTTP/3. It is UDP-only; pair it with a TCP proxy via
// proxy.Split when TCP flows also need to be tunneled.
package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

const (
	defaultTemplate    = "https://%s/.well-known/masque/udp/{target_host}/{target_port}/"
	settingsTimeout    = 10 * time.Second
	dialTimeout        = 15 * time.Second
	defaultKeepAlive   = 20 * time.Second
	defaultMaxIdle     = 5 * time.Minute
	connectUDPProtocol = "connect-udp"
	h3RequestCancelled = 0x10c
)

func init() {
	proxy.RegisterProtocol("masque", Parse)
	proxy.RegisterProtocol("connect-udp", Parse)
}

var _ proxy.Proxy = (*Masque)(nil)

// Masque is a CONNECT-UDP proxy client. One instance owns a single
// persistent HTTP/3 connection to the proxy; each DialUDP opens a fresh
// extended-CONNECT request stream on that shared connection.
type Masque struct {
	proxyAddr string
	authority string
	tlsConf   *tls.Config
	quicConf  *quic.Config
	template  *uritemplate.Template
	authHdr   string // full "Basic <b64>" value, or "" if none

	mu      sync.Mutex
	conn    *http3.ClientConn
	rawConn *quic.Conn
	version uint64 // bumps on each (re)connect; used to avoid redial races
}

// Parse implements proxy.ParseFunc. Accepted URL shapes:
//
//	masque://[user:pass@]host:port
//	masque://[user:pass@]host:port/custom/{target_host}/{target_port}/path
//	masque://...?sni=foo&insecure=true&alpn=h3&cacert=/path/to/ca.pem
//
// Query parameters:
//
//	sni       — overrides tls.Config.ServerName (default: URL host)
//	insecure  — "true"/"1" disables certificate verification (testing only)
//	alpn      — comma-separated ALPN list (default: "h3")
//	cacert    — path to a PEM bundle appended to the system roots
//	template  — explicit URI template; alternative to putting it in the path
//	username  — overrides userinfo username
//	password  — overrides userinfo password
func Parse(u *url.URL) (proxy.Proxy, error) {
	if u.Host == "" {
		return nil, errors.New("masque: empty host")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		port = "443"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("masque: invalid port %q: %w", port, err)
	}
	addr := net.JoinHostPort(host, port)

	q := u.Query()

	sni := host
	if v := q.Get("sni"); v != "" {
		sni = v
	}
	alpn := []string{http3.NextProtoH3}
	if v := q.Get("alpn"); v != "" {
		alpn = strings.Split(v, ",")
	}
	rootCAs, err := loadSystemCAs()
	if err != nil {
		return nil, fmt.Errorf("masque: load CAs: %w", err)
	}
	if caPath := q.Get("cacert"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("masque: read cacert: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("masque: no certificates found in %s", caPath)
		}
	}
	tlsConf := &tls.Config{
		ServerName:         sni,
		RootCAs:            rootCAs,
		NextProtos:         alpn,
		InsecureSkipVerify: q.Get("insecure") == "true" || q.Get("insecure") == "1",
		MinVersion:         tls.VersionTLS13,
	}

	var rawTpl string
	if t := q.Get("template"); t != "" {
		rawTpl = t
	} else if u.Path != "" && u.Path != "/" {
		qq := url.Values{}
		for k, v := range q {
			switch k {
			case "sni", "insecure", "alpn", "cacert", "template", "username", "password":
				continue
			default:
				qq[k] = v
			}
		}
		rawTpl = fmt.Sprintf("https://%s%s", addr, u.Path)
		if enc := qq.Encode(); enc != "" {
			rawTpl += "?" + enc
		}
	} else {
		rawTpl = fmt.Sprintf(defaultTemplate, addr)
	}
	tpl, err := uritemplate.New(rawTpl)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid URI template %q: %w", rawTpl, err)
	}
	if !templateHas(tpl, "target_host") || !templateHas(tpl, "target_port") {
		return nil, fmt.Errorf("masque: template %q must contain {target_host} and {target_port}", rawTpl)
	}

	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if v := q.Get("username"); v != "" {
		user = v
	}
	if v := q.Get("password"); v != "" {
		pass = v
	}
	var authHdr string
	if user != "" || pass != "" {
		authHdr = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: defaultKeepAlive,
		MaxIdleTimeout:  defaultMaxIdle,
	}

	return &Masque{
		proxyAddr: addr,
		authority: addr,
		tlsConf:   tlsConf,
		quicConf:  quicConf,
		template:  tpl,
		authHdr:   authHdr,
	}, nil
}

// DialContext: MASQUE is UDP-only. tun2socks calls this for TCP flows;
// we refuse so the operator knows to wire up a TCP proxy via proxy.Split.
func (m *Masque) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	return nil, errors.New("masque: CONNECT-UDP is UDP-only; pair with a TCP proxy via --tcp-proxy")
}

// DialUDP opens a fresh CONNECT-UDP request stream on the shared HTTP/3
// connection and returns a net.PacketConn bound to that stream.
func (m *Masque) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	target := metadata.DestinationAddress()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("masque: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("masque: bad target port %q: %w", portStr, err)
	}

	vars := uritemplate.Values{}
	vars.Set("target_host", uritemplate.String(host))
	vars.Set("target_port", uritemplate.String(strconv.Itoa(port)))
	expanded, err := m.template.Expand(vars)
	if err != nil {
		return nil, fmt.Errorf("masque: expand template: %w", err)
	}
	rurl, err := url.Parse(expanded)
	if err != nil {
		return nil, fmt.Errorf("masque: expanded template is not a valid URL: %w", err)
	}

	targetAddr := &net.UDPAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		targetAddr.IP = ip
	}

	for attempt := 0; attempt < 2; attempt++ {
		cc, ver, err := m.getConn(context.Background())
		if err != nil {
			return nil, fmt.Errorf("masque: connect proxy: %w", err)
		}
		// Build a fresh request per attempt: quic-go's SendRequestHeader
		// canonicalizes and may mutate the request, so reusing it across
		// retries could send a different header set the second time.
		req := (&http.Request{
			Method: http.MethodConnect,
			Proto:  connectUDPProtocol,
			URL:    rurl,
			Host:   m.authority,
			Header: http.Header{
				http3.CapsuleProtocolHeader: []string{"?1"},
			},
		}).WithContext(context.Background())
		if m.authHdr != "" {
			req.Header.Set("Proxy-Authorization", m.authHdr)
		}
		pc, err := m.dialOnce(cc, req, targetAddr)
		if err == nil {
			return pc, nil
		}
		if attempt == 0 && isConnDead(err) {
			m.invalidate(ver)
			continue
		}
		return nil, err
	}
	return nil, errors.New("masque: unreachable")
}

func (m *Masque) dialOnce(cc *http3.ClientConn, req *http.Request, target *net.UDPAddr) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open request stream: %w", err)
	}

	// quic-go's SendRequestHeader ignores req.Context() and ReadResponse
	// is unbounded once the stream is open. Enforce the overall dial
	// timeout by cancelling the stream if ctx fires before we succeed.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rs.CancelRead(quic.StreamErrorCode(h3RequestCancelled))
			rs.CancelWrite(quic.StreamErrorCode(h3RequestCancelled))
		case <-done:
		}
	}()

	abort := func() {
		rs.CancelRead(quic.StreamErrorCode(h3RequestCancelled))
		rs.CancelWrite(quic.StreamErrorCode(h3RequestCancelled))
	}

	if err := rs.SendRequestHeader(req); err != nil {
		abort()
		return nil, fmt.Errorf("send CONNECT-UDP: %w", err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		abort()
		return nil, fmt.Errorf("read CONNECT-UDP response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		abort()
		return nil, fmt.Errorf("masque: proxy rejected CONNECT-UDP: %s", resp.Status)
	}

	pcCtx, pcCancel := context.WithCancel(context.Background())
	pc := &h3DatagramConn{
		rs:     rs,
		ctx:    pcCtx,
		cancel: pcCancel,
		target: target,
		done:   make(chan struct{}),
	}
	go drainCapsules(pc)
	return pc, nil
}

func (m *Masque) getConn(ctx context.Context) (*http3.ClientConn, uint64, error) {
	m.mu.Lock()
	if m.conn != nil {
		cc, ver := m.conn, m.version
		m.mu.Unlock()
		return cc, ver, nil
	}
	m.mu.Unlock()

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	qc, err := quic.DialAddrEarly(dctx, m.proxyAddr, m.tlsConf, m.quicConf)
	if err != nil {
		return nil, 0, fmt.Errorf("quic handshake: %w", err)
	}

	tr := &http3.Transport{
		TLSClientConfig: m.tlsConf,
		QUICConfig:      m.quicConf,
		EnableDatagrams: true,
	}
	cc := tr.NewClientConn(qc)

	sctx, scancel := context.WithTimeout(ctx, settingsTimeout)
	defer scancel()
	select {
	case <-cc.ReceivedSettings():
	case <-sctx.Done():
		_ = qc.CloseWithError(0, "settings timeout")
		return nil, 0, errors.New("masque: timed out waiting for HTTP/3 SETTINGS")
	}
	s := cc.Settings()
	if s == nil || !s.EnableExtendedConnect {
		_ = qc.CloseWithError(0, "no extended connect")
		return nil, 0, errors.New("masque: proxy missing SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08)")
	}
	if !s.EnableDatagrams {
		_ = qc.CloseWithError(0, "no h3 datagram")
		return nil, 0, errors.New("masque: proxy missing SETTINGS_H3_DATAGRAM (0x33)")
	}

	m.mu.Lock()
	if m.conn != nil {
		cc, ver := m.conn, m.version
		m.mu.Unlock()
		_ = qc.CloseWithError(0, "superseded")
		return cc, ver, nil
	}
	m.conn = cc
	m.rawConn = qc
	m.version++
	ver := m.version
	m.mu.Unlock()
	log.Infof("[MASQUE] connected to %s (conn#%d)", m.proxyAddr, ver)
	return cc, ver, nil
}

// invalidate drops the cached connection only if it still matches ver.
// This prevents two concurrent failing DialUDP calls from clobbering
// each other's freshly-redialled connection.
func (m *Masque) invalidate(ver uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.version != ver {
		return
	}
	if m.rawConn != nil {
		_ = m.rawConn.CloseWithError(0, "invalidating")
	}
	m.conn = nil
	m.rawConn = nil
}

// Close releases the shared HTTP/3 connection. In-flight PacketConns
// will observe the stream close on their next Read/Write.
func (m *Masque) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rawConn != nil {
		err := m.rawConn.CloseWithError(0, "client close")
		m.rawConn = nil
		m.conn = nil
		return err
	}
	return nil
}

func loadSystemCAs() (*x509.CertPool, error) {
	p, err := x509.SystemCertPool()
	if err != nil || p == nil {
		return x509.NewCertPool(), nil
	}
	return p, nil
}

func templateHas(t *uritemplate.Template, name string) bool {
	for _, v := range t.Varnames() {
		if v == name {
			return true
		}
	}
	return false
}

func isConnDead(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}
	var trErr *quic.TransportError
	if errors.As(err, &trErr) {
		return true
	}
	var idle *quic.IdleTimeoutError
	if errors.As(err, &idle) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection closed") ||
		strings.Contains(s, "use of closed") ||
		strings.Contains(s, "no recent network activity") ||
		strings.Contains(s, "Application error 0x")
}
