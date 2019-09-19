package intra

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

var testURL = "https://dns.google/dns-query"
var ips = []string{
	"8.8.8.8",
	"8.8.4.4",
	"2001:4860:4860::8888",
	"2001:4860:4860::8844",
}

func TestNewTransport(t *testing.T) {
	_, err := NewDoHTransport(testURL, ips, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadUrl(t *testing.T) {
	_, err := NewDoHTransport("ftp://www.example.com", nil, nil)
	if err == nil {
		t.Error("Expected error")
	}
	_, err = NewDoHTransport("https://www.example", nil, nil)
	if err == nil {
		t.Error("Expected error")
	}
}

// Send a DoH query to an actual DoH server
func TestQueryIntegration(t *testing.T) {
	queryData := []byte{
		111, 222, // [0-1]   query ID
		1, 0, // [2-3]   flags, RD=1
		0, 1, // [4-5]   QDCOUNT (number of queries) = 1
		0, 0, // [6-7]   ANCOUNT (number of answers) = 0
		0, 0, // [8-9]   NSCOUNT (number of authoritative answers) = 0
		0, 0, // [10-11] ARCOUNT (number of additional records) = 0
		// Start of first query
		7, 'y', 'o', 'u', 't', 'u', 'b', 'e',
		3, 'c', 'o', 'm',
		0,    // null terminator of FQDN (DNS root)
		0, 1, // QTYPE = A
		0, 1, // QCLASS = IN (Internet)
	}

	doh, err := NewDoHTransport(testURL, ips, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err2 := doh.Query(queryData)
	if err2 != nil {
		t.Fatal(err2)
	}
	if resp[0] != queryData[0] || resp[1] != queryData[1] {
		t.Error("Query ID mismatch")
	}
	if len(resp) <= len(queryData) {
		t.Error("Response is short")
	}
}

type fakeConn struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (c *fakeConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *fakeConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *fakeConn) Close() error {
	e1 := c.r.Close()
	e2 := c.w.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func makePair() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &fakeConn{r1, w2}, &fakeConn{r2, w1}
}

type fakeTransport struct {
	DNSTransport
	query    chan []byte
	response chan []byte
	err      error
}

func (t *fakeTransport) Query(q []byte) ([]byte, error) {
	t.query <- q
	if t.err != nil {
		return nil, t.err
	}
	return <-t.response, nil
}

func (t *fakeTransport) GetURL() string {
	return "fake"
}

func (t *fakeTransport) Close() {
	t.err = errors.New("closed")
	close(t.query)
	close(t.response)
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		query:    make(chan []byte),
		response: make(chan []byte),
	}
}

// Test a successful query over TCP
func TestAccept(t *testing.T) {
	doh := newFakeTransport()
	client, server := makePair()

	// Start the forwarder running.
	go Accept(doh, server)

	lbuf := make([]byte, 2)
	// Send Query
	queryData := []byte{1, 2, 3, 4, 5}
	binary.BigEndian.PutUint16(lbuf, uint16(len(queryData)))
	n, err := client.Write(lbuf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Error("Length write problem")
	}
	n, err = client.Write(queryData)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(queryData) {
		t.Error("Query write problem")
	}

	// Read query
	queryRead := <-doh.query
	if !bytes.Equal(queryRead, queryData) {
		t.Error("Query mismatch")
	}

	// Send fake response
	responseData := []byte{5, 4, 3, 2, 1}
	doh.response <- responseData

	// Get Response
	n, err = client.Read(lbuf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Error("Length read problem")
	}
	rlen := binary.BigEndian.Uint16(lbuf)
	resp := make([]byte, int(rlen))
	n, err = client.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseData, resp) {
		t.Error("Response mismatch")
	}

	client.Close()
}

// Sends a TCP query that results in failure.  When a query fails,
// Accept should close the TCP socket.
func TestAcceptFail(t *testing.T) {
	doh := newFakeTransport()
	client, server := makePair()

	// Start the forwarder running.
	go Accept(doh, server)

	lbuf := make([]byte, 2)
	// Send Query
	queryData := []byte{1, 2, 3, 4, 5}
	binary.BigEndian.PutUint16(lbuf, uint16(len(queryData)))
	client.Write(lbuf)
	client.Write(queryData)

	// Indicate that the query failed
	doh.err = errors.New("fake error")

	// Read query
	queryRead := <-doh.query
	if !bytes.Equal(queryRead, queryData) {
		t.Error("Query mismatch")
	}

	// Accept should have closed the socket.
	n, _ := client.Read(lbuf)
	if n != 0 {
		t.Error("Expected to read 0 bytes")
	}
}

// Sends a TCP query, and closes the socket before the response is sent.
// This tests for crashes when a response cannot be delivered.
func TestAcceptClose(t *testing.T) {
	doh := newFakeTransport()
	client, server := makePair()

	// Start the forwarder running.
	go Accept(doh, server)

	lbuf := make([]byte, 2)
	// Send Query
	queryData := []byte{1, 2, 3, 4, 5}
	binary.BigEndian.PutUint16(lbuf, uint16(len(queryData)))
	client.Write(lbuf)
	client.Write(queryData)

	// Read query
	queryRead := <-doh.query
	if !bytes.Equal(queryRead, queryData) {
		t.Error("Query mismatch")
	}

	// Close the TCP connection
	client.Close()

	// Send fake response too late.
	responseData := []byte{5, 4, 3, 2, 1}
	doh.response <- responseData
}
