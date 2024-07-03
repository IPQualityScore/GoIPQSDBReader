package GoIPQSDBReader

type RecordType struct {
	Data Bit
}

const (
	IPv4Map Bit = 1 << iota
	IPv6Map
	IsBlacklistFile
	ReservedSeven
	ReservedEight
	ReservedNine
	ReservedTen
	BinaryData
)

const (
	ReservedEleven Bit = 1 << iota
	ReservedTwelve
	TreeData
	StringData
	SmallIntData
	IntData
	FloatData
	ReservedThirteen
)

func (bm *RecordType) Has(flag Bit) bool {
	return bm.Data&flag != 0
}

func (bm *RecordType) Set(flag Bit) {
	bm.Data = bm.Data | flag
}

func (bm *RecordType) ToString() string {
	if bm.Has(TreeData) {
		return "Tree"
	}

	if bm.Has(StringData) {
		return "String"
	}

	if bm.Has(SmallIntData) {
		return "Small Int"
	}

	if bm.Has(IntData) {
		return "Int"
	}

	if bm.Has(FloatData) {
		return "Float"
	}

	return "Unknown"
}
