package GoIPQSDBReader;

type RecordType struct {
	Data Bit;
}

const (
	IPv4Map Bit = 1 << iota
	IPv6Map
	TreeData
	StringData
	SmallIntData
	IntData
	FloatData
	BinaryData
)

func (bm *RecordType) Has(flag Bit) bool {
	return bm.Data&flag != 0;
}

func (bm *RecordType) Set(flag Bit) { 
	bm.Data = bm.Data | flag;
}

func (bm *RecordType) ToString() string {
	if(bm.Has(IPv4Map)){
		return "IPv4Map";
	}

	if(bm.Has(IPv6Map)){
		return "IPv6Map";
	}

	if(bm.Has(TreeData)){
		return "Tree";
	}

	if(bm.Has(StringData)){
		return "String";
	}

	if(bm.Has(SmallIntData)){
		return "Small Int";
	}

	if(bm.Has(IntData)){
		return "Int";
	}

	if(bm.Has(FloatData)){
		return "Float";
	}

	return "Unknown";
}