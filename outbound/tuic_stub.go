//go:build !with_quic

package outbound

import (
	"context"

	"github.com/fromil88/sing-box/adapter"
	C "github.com/fromil88/sing-box/constant"
	"github.com/fromil88/sing-box/log"
	"github.com/fromil88/sing-box/option"
)

func NewTUIC(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	return nil, C.ErrQUICNotIncluded
}
