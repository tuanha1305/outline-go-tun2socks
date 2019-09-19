package intra

// TODO: Split doh and retrier into their own packages.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"time"
)

const (
	// Complete : Transaction completed successfully
	Complete = iota
	// SendFailed : Failed to send query
	SendFailed
	// HTTPError : Got a non-200 HTTP status
	HTTPError
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
)

// DNSSummary is a summary of a DNS transaction, reported when it is complete.
type DNSSummary struct {
	Latency  float64 // Response (or failure) latency in seconds
	Query    []byte
	Response []byte
	Server   string
	Status   int
}

// DNSListener receives DNSSummaries.
type DNSListener interface {
	OnDNSTransaction(*DNSSummary)
}

// DNSTransport represents a query transport.  This interface is exported by gobind,
// so it has to be very simple.
type DNSTransport interface {
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.
	Query(q []byte) ([]byte, error)
	// Return the server URL used to initialize this transport.
	GetURL() string
}

// TODO: Keep a context here so that queries can be canceled.
type transport struct {
	DNSTransport
	url      string
	domain string
	port     int
	ips      []net.IP // Server addresses in preference order
	client   http.Client
	listener DNSListener
}

func (t *transport) dial(network, addr string) (net.Conn, error) {
	domain, _, _ := net.SplitHostPort(addr)
	if t.domain != domain {
		// Dialing a host other than the one specified in the URL.  This can happen if
		// the DoH server replies with a redirect.
		tcpaddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}
		return DialWithSplitRetry(network, tcpaddr, nil)
	}

	// TODO: Improve IP fallback strategy with preference learning, parallelism and
	// Happy Eyeballs.
	var err error
	var conn net.Conn
	for _, ip := range t.ips {
		tcpaddr := &net.TCPAddr{IP: ip, Port: t.port}
		if conn, err = DialWithSplitRetry(network, tcpaddr, nil); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

// Append any new IPs from src onto dest.
func add(dest, src []net.IP) []net.IP {
	for _, new := range src {
		found := false
		for _, old := range dest {
			if old.Equal(new) {
				found = true
				break	
			}
		}
		if !found {
			dest = append(dest, new)
		}
	}
	return dest
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
	t := &transport{
		url:      rawurl,
		domain: parsedurl.Hostname(),
		port:     port,
		listener: listener,
	}
	// Set t.ips to the hostname's addresses first, followed by the fallback addresses.
	t.ips, _ = net.LookupIP(parsedurl.Hostname())
	for _, addr := range addrs {
		ips, _ := net.LookupIP(addr)
		t.ips = add(t.ips, ips)
	}
	if len(t.ips) == 0 {
		return nil, fmt.Errorf("No IP addresses for %s", parsedurl.Hostname())
	}

	// Override the dial function.
	t.client.Transport = &http.Transport{
		Dial:              t.dial,
		ForceAttemptHTTP2: true,
	}
	return t, nil
}

type queryError struct {
	status int
	err    error
}

func (e *queryError) Error() string {
	return e.err.Error()
}

func (e *queryError) Unwrap() error {
	return e.err
}

// Given a raw DNS query (including the query ID), this function sends the
// query.  If the query is successful, it returns the response and a nil qerr.  Otherwise,
// it returns a nil response and a qerr with a status value indicating the cause.
// Independent of the query's success or failure, this function also returns the IP
// address of the server on a best-effort basis, returning the empty string if the address
// could not be determined.
func (t *transport) doQuery(q []byte) (response []byte, server string, qerr error) {
	if len(q) < 2 {
		qerr = &queryError{BadQuery, fmt.Errorf("Query length is %d", len(q))}
		return
	}
	id0, id1 := q[0], q[1]
	// Zero out the query ID.
	q[0], q[1] = 0, 0
	req, err := http.NewRequest("POST", t.url, bytes.NewBuffer(q))
	if err != nil {
		qerr = &queryError{InternalError, err}
		return
	}

	// Add a trace to the request in order to expose the server's IP address.
	// If GotConn is called, it will always be before the request completes or fails,
	// and therefore before this function returns.
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
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
		qerr = &queryError{SendFailed, err}
		return
	}
	if httpResponse.StatusCode != 200 {
		err := fmt.Errorf("HTTP request failed: %d", httpResponse.StatusCode)
		qerr = &queryError{HTTPError, err}
		return
	}
	response, err = ioutil.ReadAll(httpResponse.Body)
	// Restore the query ID.
	q[0], q[1] = id0, id1
	if len(response) >= 2 {
		response[0], response[1] = id0, id1
	}
	return
}

func (t *transport) Query(q []byte) ([]byte, error) {
	before := time.Now()
	response, server, err := t.doQuery(q)
	after := time.Now()
	if t.listener != nil {
		latency := after.Sub(before)
		status := Complete
		var qerr *queryError
		if errors.As(err, &qerr) && qerr != nil {
			status = qerr.status
		}
		t.listener.OnDNSTransaction(&DNSSummary{
			Latency:  latency.Seconds(),
			Query:    q,
			Response: response,
			Server:   server,
			Status:   status,
		})
	}
	return response, err
}

func (t *transport) GetURL() string {
	return t.url
}

// Perform a query using the transport, and send the response to the writer.
func forwardQuery(t DNSTransport, q []byte, c io.Writer) error {
	resp, err := t.Query(q)
	if err != nil {
		return err
	}
	rlen := len(resp)
	if rlen > math.MaxUint16 {
		return fmt.Errorf("Oversize response: %d", rlen)
	}
	// Use a combined write to ensure atomicity.  Otherwise, writes from two
	// responses could be interleaved.
	rlbuf := make([]byte, rlen+2)
	binary.BigEndian.PutUint16(rlbuf, uint16(rlen))
	copy(rlbuf[2:], resp)
	n, err := c.Write(rlbuf)
	if err != nil {
		return err
	}
	if int(n) != len(rlbuf) {
		return fmt.Errorf("Incomplete response write: %d < %d", n, len(rlbuf))
	}
	return nil
}

// Perform a query using the transport, send the response to the writer,
// and close the writer if there was an error.
func forwardQueryAndCheck(t DNSTransport, q []byte, c io.WriteCloser) {
	if forwardQuery(t, q, c) != nil {
		c.Close()
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func Accept(t DNSTransport, c io.ReadWriteCloser) {
	defer c.Close()
	qlbuf := make([]byte, 2)
	for n, err := c.Read(qlbuf); err == nil && n == 2; n, err = c.Read(qlbuf) {
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if uint16(n) != qlen || err != nil {
			return
		}
		go forwardQueryAndCheck(t, q, c)
	}
}
