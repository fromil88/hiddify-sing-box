package option

type XrayOutboundOptions struct {
	DialerOptions
	Network    NetworkList        `json:"network,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XConfig    *map[string]any    `json:"xconfig"`
	XDebug     bool               `json:"xdebug"`
}
