// masque-smoke is a one-shot test harness. It uses the branch's MASQUE
// client to CONNECT-UDP to 8.8.8.8:53 via a configured proxy, sends a
// DNS A query for example.com, and prints the response. Not wired into
// the build — run with `go run ./cmd/masque-smoke`.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy/masque"
)

func main() {
	proxyURL := flag.String("proxy", "", "masque:// proxy URL")
	target := flag.String("target", "8.8.8.8:53", "UDP target host:port")
	query := flag.String("name", "example.com", "DNS name to query")
	flag.Parse()
	if *proxyURL == "" {
		fmt.Fprintln(os.Stderr, "--proxy is required")
		os.Exit(2)
	}

	u, err := url.Parse(*proxyURL)
	if err != nil {
		die("parse proxy URL", err)
	}
	p, err := masque.Parse(u)
	if err != nil {
		die("masque.Parse", err)
	}
	defer p.(interface{ Close() error }).Close()

	host, portStr, err := net.SplitHostPort(*target)
	if err != nil {
		die("split target", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		die("parse port", err)
	}
	md := &M.Metadata{Network: M.UDP, DstPort: port}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			die("resolve target", err)
		}
		ip = ips[0]
	}
	if v4 := ip.To4(); v4 != nil {
		md.DstIP = netip.AddrFrom4([4]byte(v4))
	} else {
		md.DstIP = netip.AddrFrom16([16]byte(ip.To16()))
	}

	fmt.Printf("dialing MASQUE to target %s...\n", *target)
	t0 := time.Now()
	pc, err := p.DialUDP(md)
	if err != nil {
		die("DialUDP", err)
	}
	defer pc.Close()
	fmt.Printf("tunnel established in %v\n", time.Since(t0))

	q := buildDNSQuery(*query)
	if _, err := pc.WriteTo(q, nil); err != nil {
		die("WriteTo", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		die("ReadFrom", err)
	}
	fmt.Printf("got %d-byte DNS response\n", n)
	printDNSAnswers(buf[:n])
}

func buildDNSQuery(name string) []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, 0x1234)            // ID
	b = binary.BigEndian.AppendUint16(b, 0x0100)            // flags: RD
	b = binary.BigEndian.AppendUint16(b, 1)                 // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)                 // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)                 // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)                 // ARCOUNT
	for _, label := range splitLabels(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // QTYPE=A
	b = binary.BigEndian.AppendUint16(b, 1) // QCLASS=IN
	return b
}

func splitLabels(name string) []string {
	out := []string{}
	cur := ""
	for _, r := range name {
		if r == '.' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func printDNSAnswers(b []byte) {
	if len(b) < 12 {
		return
	}
	ancount := binary.BigEndian.Uint16(b[6:8])
	fmt.Printf("answers: %d\n", ancount)
	i := 12
	// skip question
	for i < len(b) && b[i] != 0 {
		i += int(b[i]) + 1
	}
	i += 1 + 4
	for a := 0; a < int(ancount) && i < len(b); a++ {
		// name (possibly compressed)
		for i < len(b) {
			if b[i]&0xc0 == 0xc0 {
				i += 2
				break
			}
			if b[i] == 0 {
				i++
				break
			}
			i += int(b[i]) + 1
		}
		if i+10 > len(b) {
			return
		}
		typ := binary.BigEndian.Uint16(b[i : i+2])
		rdlen := int(binary.BigEndian.Uint16(b[i+8 : i+10]))
		i += 10
		if i+rdlen > len(b) {
			return
		}
		if typ == 1 && rdlen == 4 {
			fmt.Printf("  A %d.%d.%d.%d\n", b[i], b[i+1], b[i+2], b[i+3])
		}
		i += rdlen
	}
}

func die(where string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", where, err)
	os.Exit(1)
}
