package ipmap

import (
	"math/rand"
	"net"
	"sync"
)

// IPMap maps hostnames to IPSets.
type IPMap interface {
	// Get creates an IPSet for this hostname populated with the IPs
	// discovered by resolving it.  Subsequent calls to Get return the
	// same IPSet.
	Get(hostname string) *IPSet
}

// NewIPMap returns a fresh IPMap.
func NewIPMap() IPMap {
	return &ipMap{m: make(map[string]*IPSet)}
}

type ipMap struct {
	sync.RWMutex
	m map[string]*IPSet
}

func (m *ipMap) Get(hostname string) *IPSet {
	m.RLock()
	s := m.m[hostname]
	m.RUnlock()
	if s != nil {
		return s
	}

	s = &IPSet{}
	// Don't hold the lock during blocking I/O.
	s.Add(hostname)

	m.Lock()
	s2 := m.m[hostname]
	if s2 == nil {
		m.m[hostname] = s
	} else {
		// Another pending call to Get populated m[hostname]
		// while we were building s.  Use the first one to ensure
		// consistency.
		s = s2
	}
	m.Unlock()

	return s
}

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	sync.RWMutex
	ips       []net.IP // All known IPs for the server.
	confirmed net.IP   // IP address confirmed to be working
}

// Add one or more IP addresses to the set.
// The hostname can be a domain name or an IP address.
func (s *IPSet) Add(hostname string) {
	resolved, _ := net.LookupIP(hostname)

	s.Lock()
	defer s.Unlock()

	// Set union
	has := func(ip net.IP) bool {
		for _, oldIP := range s.ips {
			if oldIP.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, ip := range resolved {
		if !has(ip) {
			s.ips = append(s.ips, ip)
		}
	}
}

// Empty reports whether the set is empty.
func (s *IPSet) Empty() bool {
	s.RLock()
	defer s.RUnlock()
	return len(s.ips) == 0
}

// GetAll returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) GetAll() []net.IP {
	s.RLock()
	c := append([]net.IP{}, s.ips...)
	s.RUnlock()
	rand.Shuffle(len(c), func(i, j int) {
		c[i], c[j] = c[j], c[i]
	})
	return c
}

// Confirmed returns the confirmed IP address, or nil if there is no such address.
func (s *IPSet) Confirmed() net.IP {
	s.RLock()
	defer s.RUnlock()
	return s.confirmed
}

// Confirm marks ipstr as the confirmed address, if it is a valid IP address.
func (s *IPSet) Confirm(ipstr string) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		s.Lock()
		s.confirmed = ip
		s.Unlock()
	}
}

// Disconfirm sets the confirmed address to nil if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip net.IP) {
	s.Lock()
	if ip.Equal(s.confirmed) {
		s.confirmed = nil
	}
	s.Unlock()
}
