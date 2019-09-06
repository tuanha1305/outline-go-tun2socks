package intra
// TODO: Split doh and retrier into their own packages.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	Complete = iota // Transaction completed successfully
	SendFailed // Failed to send query
	HTTPError // Got a non-200 HTTP status
	BadQuery
	BadResponse // Response was invalid
	InternalError // Logic error
	Canceled // Request was canceled
)

// Summary of a DNS transaction, reported when it is complete.
type DNSSummary struct {
	Timestamp int64 // Seconds since the epoch at time of query
	Latency float64 // Response latency in seconds
	Query   []byte
	Response []byte
	Server     string
	Status int
}

type DNSListener interface {
	OnDNSTransaction(*DNSSummary)
}

// DNSTransport represents a query transport.
type DNSTransport interface {
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.
	Query(q []byte) ([]byte, error)
	// Accept multiple queries in DNS-over-TCP format on a net.Conn, and
	// reply in kind.
	Accept(c io.ReadWriteCloser)
}

type transport struct {
	DNSTransport
	url    string
	port   int
	addrs  []net.IP // Server addresses in preference order
	mu     sync.RWMutex // Lock protecting addrs
	client http.Client
	listener DNSListener
}

// hostname can be a domain name or an IP address.
func (t *transport) addAddrs(hostname string) {
	resolved, _ := net.LookupIP(hostname)
	t.addrs = append(t.addrs, resolved...)
}

// Get a copy of t.addrs.
func (t *transport) getAddrs() []net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]net.IP{}, t.addrs...)
}

// Update t.addrs so that addrs[i] is most preferred.
func (t *transport) preferAddr(addrs []net.IP, i int) {
	if i == 0 {
		// The selected address is already preferred.
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addrs[0] = addrs[i]
	copy(t.addrs[1:i+1], addrs[:i])
	copy(t.addrs[i+1:], addrs[i+1:])
}

func (t *transport) dial(network, addr string) (conn net.Conn, err error) {
	// addr is ignored because it is always the hostname
	// TODO: Try multiple addresses in parallel and prefer IPv6 (Happy Eyeballs).
	addrs := t.getAddrs()
	for i, addr := range addrs {
		tcpaddr := &net.TCPAddr{IP: addr, Port: t.port}
		conn, err = DialWithSplitRetry(network, tcpaddr, nil)
		if err == nil {
			t.preferAddr(addrs, i)
			return
		}
	}
	return
}

// NewDoHTransport returns a DoH DNSTransport, ready for use.
// This is a POST-only DoH implementation, so the DoH template should be a URL.
// addrs is a list of domains or IP addresses to use as fallback, if the hostname
// lookup fails or returns non-working addresses.
func NewDoHTransport(rawurl string, addrs []string, listener DNSListener) (DNSTransport, error) {
	parsedurl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if parsedurl.Scheme != "https" {
		return nil, fmt.Errorf("Bad scheme: %s", parsedurl.Scheme)
	}
	// Resolve the hostname and put those addresses first.
	portStr := parsedurl.Port()
	var port int
	if len(portStr) > 0 {
		port, err = strconv.Atoi(parsedurl.Port())
		if err != nil {
			return nil, err
		}
	} else {
		port = 443
	}
	t := &transport{url: rawurl, port: port, listener: listener}
	// Initialize d.addrs with the hostname's addresses, followed by
	// the fallback addresses.
	t.addAddrs(parsedurl.Hostname())
	for _, addr := range addrs {
		t.addAddrs(addr)
	}
	if len(t.addrs) == 0 {
		return nil, fmt.Errorf("No IP addresses for %s", parsedurl.Hostname())
	}

	// Override the dial function.
	t.client.Transport = &http.Transport{
		Dial:              t.dial,
		ForceAttemptHTTP2: true,
	}
	return t, nil
}

func (t *transport) doQuery(q []byte) (response []byte, status int, server string, err error) {
	if len(q) < 2 {
		status = BadQuery
		err = fmt.Errorf("Query length is %d", len(q))
		return
	}
	id0, id1 := q[0], q[1]
	// Zero out the query ID.
	q[0], q[1] = 0, 0
	req, err := http.NewRequest("POST", t.url, bytes.NewBuffer(q))
	if err != nil {
		status = InternalError
		return
	}

	// If GotConn is called, it will always be before the request completes or fails,
	// and therefore before this function returns.
    trace := httptrace.ClientTrace{
        GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if addr := info.Conn.RemoteAddr(); addr != nil {
				server, _, _ = net.SplitHostPort(addr.String())
			}
        },
    }
    req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))


	const mimetype = "application/dns-message"
	req.Header.Set("Content-Type", mimetype)
	req.Header.Set("Accept", mimetype)
	req.Header.Set("User-Agent", "Intra")
	httpResponse, err := t.client.Do(req)
	if err != nil {
		status = SendFailed
		return
	}
	if httpResponse.StatusCode != 200 {
		status = HTTPError
		return
	}
	response, err = ioutil.ReadAll(httpResponse.Body)
	// Restore the query ID.
	q[0], q[1] = id0, id1
	if len(response) >= 2 {
		response[0], response[1] = id0, id1
	}
	status = Complete
	return
}

func (t *transport) Query(q []byte) ([]byte, error) {
	queryTime := time.Now()
	response, status, server, err := t.doQuery(q)
	responseTime := time.Now()
	if t.listener != nil {
		latency := responseTime.Sub(queryTime)
		t.listener.OnDNSTransaction(&DNSSummary{
			Timestamp: queryTime.Unix(),
			Latency: latency.Seconds(),
			Query: q,
			Response: response,
			Server: server,
			Status: status,
		})
	}
	return response, err
}

func (t *transport) forwardQuery(q []byte, c io.ReadWriteCloser) {
	resp, err := t.Query(q)
	if err != nil {
		// Query error.  Close the socket.
		c.Close()
		return
	}
	rlen := len(resp)
	if rlen > math.MaxUint16 {
		// Impossibly huge response.
		c.Close()
		return
	}
	rlbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(rlbuf, uint16(rlen))
	// Use a combined write to put the length and response in a single
	// TCP segment, for efficiency.
	var combined net.Buffers = [][]byte{rlbuf, resp}
	n, err := combined.WriteTo(c)
	if err != nil || int(n) != rlen + 2 {
		// Failed or partial write.  Close the socket.
		c.Close()
	}
}

func (t *transport) Accept(c io.ReadWriteCloser) {
	defer c.Close()
	qlbuf := make([]byte, 2)
	for n, err := c.Read(qlbuf); err == nil && n == 2; n, err = c.Read(qlbuf) {
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if uint16(n) != qlen || err != nil {
			return
		}
		go t.forwardQuery(q, c)
	}
}
