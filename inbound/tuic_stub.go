//go:build !with_quic

package inbound

import (
	"context"

	"github.com/fromil88/sing-box/adapter"
	C "github.com/fromil88/sing-box/constant"
	"github.com/fromil88/sing-box/log"
	"github.com/fromil88/sing-box/option"
)

func NewTUIC(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
	return nil, C.ErrQUICNotIncluded
}
