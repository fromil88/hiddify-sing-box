package outbound

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hiddify/ipinfo"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/batch"
)

func CheckOutbound(logger log.Logger, ctx context.Context, history *urltest.HistoryStorage, router adapter.Router, url string, outbound adapter.Outbound, ipbatch *batch.Batch[string]) uint16 {
	realTag := RealTag(outbound)
	testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	t, err := urltest.URLTest(testCtx, url, outbound)
	if outbound.Type() == C.TypeWireGuard { // double check for wireguard
		t1, err1 := urltest.URLTest(testCtx, url, outbound)
		if err1 == nil {
			t = t1
			err = err1
		}
	}
	if err != nil || t == 0 {
		t = TimeoutDelay
	}
	his := history.StoreURLTestHistory(realTag, &urltest.History{
		Time:  time.Now(),
		Delay: t,
	})

	if !isTimeout(his) {
		if ipbatch == nil {
			go CheckIP(logger, ctx, history, router, outbound)
		} else if his.IpInfo == nil {
			ipbatch.Go(realTag+"ip", func() (string, error) {
				CheckIP(logger, ctx, history, router, outbound)
				return "", nil
			})
		}
	}

	return t
}

func CheckIP(logger log.Logger, ctx context.Context, history *urltest.HistoryStorage, router adapter.Router, outbound adapter.Outbound) {
	if outbound == nil {
		return
	}
	if history == nil {
		return
	}
	realTag := RealTag(outbound)
	detour, loaded := router.Outbound(realTag)
	if !loaded {
		return
	}
	his := history.LoadURLTestHistory(realTag)
	if isTimeout(his) {
		return
	}
	if his.IpInfo != nil {
		// logger.Debug("ip already calculated ", fmt.Sprint(his.IpInfo))
		return
	}
	newip, t, err := ipinfo.GetIpInfo(logger, ctx, detour)
	if err != nil {
		// g.logger.Debug("outbound ", realTag, " IP unavailable (", t, "ms): ", err)
		// g.history.AddOnlyIpToHistory(realTag, &urltest.History{
		// 	Time:   time.Now(),
		// 	Delay:  TimeoutDelay,
		// 	IpInfo: &ipinfo.IpInfo{},
		// })
		return
	}
	// g.logger.Trace("outbound ", realTag, " IP ", fmt.Sprint(newip), " (", t, "ms): ", err)
	history.AddOnlyIpToHistory(realTag, &urltest.History{
		Time:   time.Now(),
		Delay:  t,
		IpInfo: newip,
	})
}
