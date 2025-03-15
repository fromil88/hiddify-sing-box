package option

import "github.com/xtls/xray-core/infra/conf"

type XrayOutboundOptions struct {
	DialerOptions
	Network                    NetworkList        `json:"network,omitempty"`
	UDPOverTCP                 *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XConfig                    *map[string]any    `json:"xconfig,omitempty"`
	XDebug                     bool               `json:"xdebug,omitempty"`
	DeprecatedXrayOutboundJson *map[string]any    `json:"xray_outbound_raw,omitempty"`
	DeprecatedFragment         *conf.Fragment     `json:"xray_fragment,omitempty"`
	DeprecatedLogLevel         *string            `json:"xray_loglevel,omitempty"`
}
