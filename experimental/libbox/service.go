package libbox

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	runtimeDebug "runtime/debug"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/experimental/libbox/internal/procfs"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
)

type BoxService struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	instance              *box.Box
	pauseManager          pause.Manager
	urlTestHistoryStorage *urltest.HistoryStorage
	servicePauseFields
}

func NewService(configContent string, platformInterface PlatformInterface) (*BoxService, error) {
	options, err := parseConfig(configContent)
	if err != nil {
		return nil, err
	}
	runtimeDebug.FreeOSMemory()

	platformWrapper := &platformInterfaceWrapper{iif: platformInterface, useProcFS: platformInterface.UseProcFS()}

	return NewHService(box.Options{
		Options:           options,
		PlatformInterface: platformWrapper,
		PlatformLogWriter: platformWrapper,
	})
}

func WrapPlatformInterface(platformInterface PlatformInterface) platform.Interface {
	return &platformInterfaceWrapper{iif: platformInterface, useProcFS: platformInterface.UseProcFS()}
}

func NewHService(boptions box.Options) (*BoxService, error) {
	runtimeDebug.FreeOSMemory()
	parentctx := boptions.Context
	if parentctx == nil {
		parentctx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentctx)
	ctx = filemanager.WithDefault(ctx, sWorkingPath, sTempPath, sUserID, sGroupID)
	urlTestHistoryStorage := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
	ctx = service.ContextWith[deprecated.Manager](ctx, new(deprecatedManager))
	boptions.Context = ctx
	instance, err := box.New(boptions)
	if err != nil {
		cancel()
		return nil, E.Cause(err, "create service")
	}
	runtimeDebug.FreeOSMemory()
	return &BoxService{
		ctx:                   ctx,
		cancel:                cancel,
		instance:              instance,
		urlTestHistoryStorage: urlTestHistoryStorage,
		pauseManager:          service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *BoxService) UrlTestHistory() *urltest.HistoryStorage {
	return s.urlTestHistoryStorage
}

func (s *BoxService) Context() context.Context {
	return s.ctx
}

func (s *BoxService) Start() error {
	if sFixAndroidStack {
		var err error
		done := make(chan struct{})
		go func() {
			err = s.instance.Start()
			close(done)
		}()
		<-done
		return err
	} else {
		return s.instance.Start()
	}
}

func (s *BoxService) Close() error {
	s.cancel()
	s.urlTestHistoryStorage.Close()
	var err error
	done := make(chan struct{})
	go func() {
		err = s.instance.Close()
		close(done)
	}()
	select {
	case <-done:
		return err
	case <-time.After(C.FatalStopTimeout):
		os.Exit(1)
		return nil
	}
}

func (s *BoxService) NeedWIFIState() bool {
	return s.instance.Router().NeedWIFIState()
}

var (
	_ platform.Interface = (*platformInterfaceWrapper)(nil)
	_ log.PlatformWriter = (*platformInterfaceWrapper)(nil)
)

type platformInterfaceWrapper struct {
	iif       PlatformInterface
	useProcFS bool
	router    adapter.Router
}

func (w *platformInterfaceWrapper) Initialize(ctx context.Context, router adapter.Router) error {
	w.router = router
	return nil
}

func (w *platformInterfaceWrapper) UsePlatformAutoDetectInterfaceControl() bool {
	return w.iif.UsePlatformAutoDetectInterfaceControl()
}

func (w *platformInterfaceWrapper) AutoDetectInterfaceControl(fd int) error {
	return w.iif.AutoDetectInterfaceControl(int32(fd))
}

func (w *platformInterfaceWrapper) OpenTun(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	if len(options.IncludeUID) > 0 || len(options.ExcludeUID) > 0 {
		return nil, E.New("android: unsupported uid options")
	}
	if len(options.IncludeAndroidUser) > 0 {
		return nil, E.New("android: unsupported android_user option")
	}
	routeRanges, err := options.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	tunFd, err := w.iif.OpenTun(&tunOptions{options, routeRanges, platformOptions})
	if err != nil {
		return nil, err
	}
	options.Name, err = getTunnelName(tunFd)
	if err != nil {
		return nil, E.Cause(err, "query tun name")
	}
	dupFd, err := dup(int(tunFd))
	if err != nil {
		return nil, E.Cause(err, "dup tun file descriptor")
	}
	options.FileDescriptor = dupFd
	return tun.New(*options)
}

func (w *platformInterfaceWrapper) UsePlatformDefaultInterfaceMonitor() bool {
	return w.iif.UsePlatformDefaultInterfaceMonitor()
}

func (w *platformInterfaceWrapper) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return &platformDefaultInterfaceMonitor{
		platformInterfaceWrapper: w,
		defaultInterfaceIndex:    -1,
		logger:                   logger,
	}
}

func (w *platformInterfaceWrapper) UsePlatformInterfaceGetter() bool {
	return w.iif.UsePlatformInterfaceGetter()
}

func (w *platformInterfaceWrapper) Interfaces() ([]control.Interface, error) {
	interfaceIterator, err := w.iif.GetInterfaces()
	if err != nil {
		return nil, err
	}
	var interfaces []control.Interface
	for _, netInterface := range iteratorToArray[*NetworkInterface](interfaceIterator) {
		interfaces = append(interfaces, control.Interface{
			Index:     int(netInterface.Index),
			MTU:       int(netInterface.MTU),
			Name:      netInterface.Name,
			Addresses: common.Map(iteratorToArray[string](netInterface.Addresses), netip.MustParsePrefix),
			Flags:     linkFlags(uint32(netInterface.Flags)),
		})
	}
	return interfaces, nil
}

func (w *platformInterfaceWrapper) UnderNetworkExtension() bool {
	return w.iif.UnderNetworkExtension()
}

func (w *platformInterfaceWrapper) IncludeAllNetworks() bool {
	return w.iif.IncludeAllNetworks()
}

func (w *platformInterfaceWrapper) ClearDNSCache() {
	w.iif.ClearDNSCache()
}

func (w *platformInterfaceWrapper) ReadWIFIState() adapter.WIFIState {
	wifiState := w.iif.ReadWIFIState()
	if wifiState == nil {
		return adapter.WIFIState{}
	}
	return (adapter.WIFIState)(*wifiState)
}

func (w *platformInterfaceWrapper) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*process.Info, error) {
	var uid int32
	if w.useProcFS {
		uid = procfs.ResolveSocketByProcSearch(network, source, destination)
		if uid == -1 {
			return nil, E.New("procfs: not found")
		}
	} else {
		var ipProtocol int32
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			ipProtocol = syscall.IPPROTO_TCP
		case N.NetworkUDP:
			ipProtocol = syscall.IPPROTO_UDP
		default:
			return nil, E.New("unknown network: ", network)
		}
		var err error
		uid, err = w.iif.FindConnectionOwner(ipProtocol, source.Addr().String(), int32(source.Port()), destination.Addr().String(), int32(destination.Port()))
		if err != nil {
			return nil, err
		}
	}
	packageName, _ := w.iif.PackageNameByUid(uid)
	return &process.Info{UserId: uid, PackageName: packageName}, nil
}

func (w *platformInterfaceWrapper) DisableColors() bool {
	return runtime.GOOS != "android"
}

func (w *platformInterfaceWrapper) WriteMessage(level log.Level, message string) {
	w.iif.WriteLog(message)
}

func (w *platformInterfaceWrapper) SendNotification(notification *platform.Notification) error {
	return w.iif.SendNotification((*Notification)(notification))
}
