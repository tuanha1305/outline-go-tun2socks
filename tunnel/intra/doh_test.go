package intra

import (
	"testing"
)

var testURL = "https://dns.google/dns-query"
var ips = []string{
	"8.8.8.8",
	"8.8.4.4",
	"2001:4860:4860::8888",
	"2001:4860:4860::8844",
}
var queryData = []byte{
	111, 222,  // [0-1]   query ID
	1, 0,      // [2-3]   flags, RD=1
	0, 1,      // [4-5]   QDCOUNT (number of queries) = 1
	0, 0,      // [6-7]   ANCOUNT (number of answers) = 0
	0, 0,      // [8-9]   NSCOUNT (number of authoritative answers) = 0
	0, 0,      // [10-11] ARCOUNT (number of additional records) = 0
	// Start of first query
	7, 'y', 'o', 'u', 't', 'u', 'b', 'e',
	3, 'c', 'o', 'm',
	0,  // null terminator of FQDN (DNS root)
	0, 1,  // QTYPE = A
	0, 1,   // QCLASS = IN (Internet)
}

func TestNewTransport(t *testing.T) {
	_, err := NewDoHTransport(testURL, ips)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadUrl(t *testing.T) {
	_, err := NewDoHTransport("ftp://www.example.com", nil)
	if err == nil {
		t.Error("Expected error")
	}
	_, err = NewDoHTransport("https://www.example", nil)
	if err == nil {
		t.Error("Expected error")
	}
}

func TestQuery(t *testing.T) {
	doh, err := NewDoHTransport(testURL, ips)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doh.Query(queryData)
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != queryData[0] || resp[1] != queryData[1] {
		t.Error("Query ID mismatch")
	}
	if len(resp) <= len(queryData) {
		t.Error("Response is short")
	}
}