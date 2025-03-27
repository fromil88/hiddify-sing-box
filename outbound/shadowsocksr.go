//go:build with_shadowsocksr

package outbound

import (
	"context"
	"os"

	"github.com/fromil88/sing-box/adapter"
	"github.com/fromil88/sing-box/log"
	"github.com/fromil88/sing-box/option"
)

var _ int = "ShadowsocksR is deprecated and removed in sing-box 1.6.0"

func NewShadowsocksR(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
	return nil, os.ErrInvalid
}
