package GoIPQSDBReader;

type BinaryOption struct {
	Data Bit;
}

func (bm *BinaryOption) Has(flag Bit) bool {
	return bm.Data&flag != 0;
}

// Binary Option Bit One
const (
	IsProxy Bit = 1 << iota
	IsVPN
	IsTOR
	IsCrawler
	IsBot
	RecentAbuse
	IsBlacklisted
	IsPrivate
)

// Binary Option Bit Two
const (
	IsMobile Bit = 1 << iota
	HasOpenPorts
	IsHostingProvider
	ActiveVPN
	ActiveTOR
	PublicAccessPoint
	ReservedOne
	ReservedTwo
)

// Bimary Option Bit Three (Bit One In Files Without BinaryData)
const (
	ReservedThree Bit = 1 << iota
	ReservedFour
	ReservedFive
	ConnectionTypeOne
	ConnectionTypeTwo
	ConnectionTypeThree
	AbuseVelocityOne
	AbuseVelocityTwo
)