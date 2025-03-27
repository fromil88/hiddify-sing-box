package constant

import (
	F "github.com/sagernet/sing/common/format"
)

type InterfaceType uint8

func ReverseMap[K comparable, V comparable](m map[K]V) map[V]K {
	ret := make(map[V]K, len(m))
	for k, v := range m {
		ret[v] = k
	}
	return ret
}

const (
	InterfaceTypeWIFI InterfaceType = iota
	InterfaceTypeCellular
	InterfaceTypeEthernet
	InterfaceTypeOther
)

var (
	interfaceTypeToString = map[InterfaceType]string{
		InterfaceTypeWIFI:     "wifi",
		InterfaceTypeCellular: "cellular",
		InterfaceTypeEthernet: "ethernet",
		InterfaceTypeOther:    "other",
	}
	StringToInterfaceType = ReverseMap(interfaceTypeToString)
)

func (t InterfaceType) String() string {
	name, loaded := interfaceTypeToString[t]
	if !loaded {
		return F.ToString(int(t))
	}
	return name
}

type NetworkStrategy uint8

const (
	NetworkStrategyDefault NetworkStrategy = iota
	NetworkStrategyFallback
	NetworkStrategyHybrid
)

var (
	networkStrategyToString = map[NetworkStrategy]string{
		NetworkStrategyDefault:  "default",
		NetworkStrategyFallback: "fallback",
		NetworkStrategyHybrid:   "hybrid",
	}
	StringToNetworkStrategy = ReverseMap(networkStrategyToString)
)

func (s NetworkStrategy) String() string {
	name, loaded := networkStrategyToString[s]
	if !loaded {
		return F.ToString(int(s))
	}
	return name
}
