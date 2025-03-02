package route

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/outbound"
	dns "github.com/sagernet/sing-dns"
)

type StaticDNS struct {
	entries          map[string]StaticDNSEntry
	internalDNSItems map[string]bool
	router           *Router
}

func NewStaticDNS(router *Router, staticIPs map[string][]string) *StaticDNS {
	s := &StaticDNS{
		internalDNSItems: make(map[string]bool),
		router:           router,
	}
	s.createEntries(staticIPs)
	if router == nil {
		return nil
	}
	for _, out := range router.Outbounds() {
		if urltest, ok := out.(*outbound.URLTest); ok && out.Type() == C.TypeURLTest && urltest != nil {
			for _, link := range urltest.Links() {
				domain := getDomainFromLink(link)
				if domain != "" && !IsIPv6(domain) && !IsIPv4(domain) {
					s.internalDNSItems[domain] = true
				}
			}
		}
	}

	return s
}

func getDomainFromLink(link string) string {
	url, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return url.Hostname()
}

type StaticDNSEntry struct {
	IPv4 []netip.Addr
	IPv6 []netip.Addr
}

func (s *StaticDNS) createEntries(items map[string][]string) {
	entries := make(map[string]StaticDNSEntry)

	for domain, ips := range items {
		entry := StaticDNSEntry{}

		for _, ipString := range ips {
			ip, err := netip.ParseAddr(ipString)
			if err != nil {
				fmt.Printf("Invalid IP address for domain %s: %s\n", domain, ipString)
				continue
			}

			if ip.Is4() {
				entry.IPv4 = append(entry.IPv4, ip)
			} else {
				entry.IPv6 = append(entry.IPv6, ip)
			}
		}
		entries[domain] = entry
	}

	s.entries = entries
}

func errorIfEmpty(addrs []netip.Addr) ([]netip.Addr, error) {
	if len(addrs) == 0 {
		return addrs, fmt.Errorf("NotFound")
	}
	return addrs, nil
}

func (s *StaticDNS) Add2staticDnsIfInternal(domain string, addrs []netip.Addr) {
	if s == nil || s.internalDNSItems == nil {
		// fmt.Println("StaticDNS or internalDNSItems is nil")
		return
	}

	if _, ok := s.internalDNSItems[domain]; !ok {
		return
	}

	if len(addrs) == 0 {
		// fmt.Println("No addresses provided for domain:", domain)
		return
	}

	s.add2staticDns(domain, addrs)
}

func (s *StaticDNS) add2staticDns(domain string, addrs []netip.Addr) {
	entry := StaticDNSEntry{}

	for _, ip := range addrs {
		if isBlocked(ip) {
			continue
		}
		if ip.Is4() {
			entry.IPv4 = append(entry.IPv4, ip)
		} else {
			entry.IPv6 = append(entry.IPv6, ip)
		}
	}
	if len(entry.IPv4) == 0 && len(entry.IPv6) == 0 {
		return
	}
	s.entries[domain] = entry
}

func (s *StaticDNS) IsInternal(domain string) bool {
	if _, ok := s.internalDNSItems[domain]; ok {
		return true
	}
	return false
}

func (s *StaticDNS) lookupStaticIP(domain string, strategy uint8, skipInternal bool) ([]netip.Addr, error) {
	if skipInternal && s.IsInternal(domain) {
		return nil, fmt.Errorf("Internal")
	}
	if staticDns, ok := s.entries[domain]; ok {
		switch strategy {
		case dns.DomainStrategyUseIPv4:
			return errorIfEmpty(staticDns.IPv4)

		case dns.DomainStrategyUseIPv6:

			return errorIfEmpty(staticDns.IPv6)

		case dns.DomainStrategyPreferIPv6:
			if len(staticDns.IPv6) == 0 {
				return errorIfEmpty(staticDns.IPv4)
			}
			return errorIfEmpty(append(staticDns.IPv6, staticDns.IPv4...))

		default:
			if len(staticDns.IPv4) == 0 {
				return errorIfEmpty(staticDns.IPv6)
			}
			return errorIfEmpty(append(staticDns.IPv4, staticDns.IPv6...))

		}
	} else {
		ip := getIpOfSslip(domain)
		if ip != "" {
			ipaddr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, err
			}
			return []netip.Addr{ipaddr}, nil
		}
		// if strings.Contains(domain, ",") {
		// 	entry := StaticDNSEntry{}
		// 	for _, ipString := range strings.Split(domain, ",") {
		// 		ip, err := netip.ParseAddr(ipString)
		// 		if err != nil {
		// 			fmt.Printf("Invalid IP address for domain %s: %s\n", domain, ipString)
		// 			continue
		// 		}

		// 		if ip.Is4() {
		// 			entry.IPv4 = append(entry.IPv4, ip)
		// 		} else {
		// 			entry.IPv6 = append(entry.IPv6, ip)
		// 		}
		// 	}
		// 	fmt.Println("Adding ",domain, entry)
		// 	router.staticDns[domain] = entry
		// 	return router.lookupStaticIP(domain, strategy)
		// }
		return nil, fmt.Errorf("NotFound")
	}
}

const (
	ipv4Pattern = `((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])[\.-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])).sslip.io$`
	ipv6Pattern = `((([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).sslip.io$`
)

var (
	ipv4Regex, _ = regexp.Compile(ipv4Pattern)
	ipv6Regex, _ = regexp.Compile(ipv6Pattern)
)

func IsIPv4(sni string) bool {
	return ipv4Regex.MatchString(sni)
}

func IsIPv6(sni string) bool {
	return ipv6Regex.MatchString(sni)
}

func getIpOfSslip(sni string) string {
	if !strings.HasSuffix(sni, ".sslip.io") {
		return ""
	}
	submatches := ipv4Regex.FindStringSubmatch(sni)
	if len(submatches) > 1 {
		return strings.ReplaceAll(submatches[1], "-", ".")
	} else {
		submatches := ipv6Regex.FindStringSubmatch(sni)
		if len(submatches) > 1 {
			return strings.ReplaceAll(submatches[1], "-", ":")
		}
	}
	return ""
}
