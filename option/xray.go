package option

import "github.com/xtls/xray-core/infra/conf"

type XrayOutboundOptions struct {
	DialerOptions
	Network    NetworkList        `json:"network,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XConfig    *conf.Config       `json:"xconfig"`
	XDebug     bool               `json:"xdebug"`
}
