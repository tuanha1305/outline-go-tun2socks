package intra

import (
	"math/rand"
	"net"
	"sync"
)

type ipMap struct {
	sync.Mutex
	m map[string]*ipSet
}

func (m *ipMap) get(hostname string) *ipSet {
	m.Lock()
	defer m.Unlock()
	if m.m[hostname] == nil {
		m.m[hostname] = &ipSet{}
		m.m[hostname].add(hostname)
	}
	return m.m[hostname]
}

// Heuristic IP set.  IPs are tried in random order until one is confirmed to
// be working.
type ipSet struct {
	sync.RWMutex
	ips       []net.IP // All known IPs for the server.
	confirmed net.IP   // IP address confirmed to be working
}

// hostname can be a domain name or an IP address.
func (s *ipSet) add(hostname string) {
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

func (s *ipSet) empty() bool {
	s.RLock()
	defer s.RUnlock()
	return len(s.ips) > 0
}

// Get a shuffled copy of t.addrs.
func (s *ipSet) getAll() []net.IP {
	s.RLock()
	c := append([]net.IP{}, s.ips...)
	s.RUnlock()
	rand.Shuffle(len(c), func(i, j int) {
		c[i], c[j] = c[j], c[i]
	})
	return c
}

func (s *ipSet) getConfirmed() net.IP {
	s.RLock()
	defer s.RUnlock()
	return s.confirmed
}

func (s *ipSet) confirm(ip string) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		s.Lock()
		s.confirmed = ip
		s.Unlock()
	}
}

func (s *ipSet) disconfirm(ip net.IP) {
	s.Lock()
	if ip.Equal(s.confirmed) {
		s.confirmed = nil
	}
	s.Unlock()
}
