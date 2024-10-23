package GoIPQSDBReader;

type IPQSRecord struct {
	IsProxy bool
	IsVPN bool
	IsTOR bool
	IsCrawler bool
	IsBot bool
	RecentAbuse bool
	IsBlacklisted bool
	IsPrivate bool
	IsMobile bool
	HasOpenPorts bool
	IsHostingProvider bool
	ActiveVPN bool
	ActiveTOR bool
	PublicAccessPoint bool

	ConnectionType *ConnectionType
	AbuseVelocity *AbuseVelocity

	Country string
	City string
	Region string
	ISP string
	Organization string
	Zipcode string
	Hostname string
	ASN int
	Timezone string
	Latitude float32
	Longitude float32
	
	FraudScore *FraudScore

	Columns []*Column
}

type ConnectionType struct {
	Raw int
}

type AbuseVelocity struct {
	Raw int
}

type FraudScore struct {
	Strictness map[int]int
}

func (conn *ConnectionType) ToString() string {
	switch(conn.Raw){
		case 1:
			return "Residential";
		case 2:
			return "Mobile";
		case 3:
			return "Corporate";
		case 4:
			return "Data Center";
		case 5:
			return "Education";
		default:
			return "Unknown";
	}
}

func (av *AbuseVelocity) ToString() string {
	switch(av.Raw) {
		case 1:
			return "low";
		case 2:
			return "medium";
		case 3:
			return "high";
		default:
			return "none";
	}
}

func (record *IPQSRecord) processFirstByte(b *BinaryOption){
	if(b.Has(IsProxy)){
		record.IsProxy = true;
	}

	if(b.Has(IsVPN)){
		record.IsVPN = true;
	}

	if(b.Has(IsTOR)){
		record.IsTOR = true;
	}

	if(b.Has(IsCrawler)){
		record.IsCrawler = true;
	}

	if(b.Has(IsBot)){
		record.IsBot = true;
	}

	if(b.Has(RecentAbuse)){
		record.RecentAbuse = true;
	}

	if(b.Has(IsBlacklisted)){
		record.IsBlacklisted = true;
	}

	if(b.Has(IsPrivate)){
		record.IsPrivate = true;
	}
}

func (record *IPQSRecord) processSecondByte(b *BinaryOption){
	if(b.Has(IsMobile)){
		record.IsMobile = true;
	}

	if(b.Has(HasOpenPorts)){
		record.HasOpenPorts = true;
	}

	if(b.Has(IsHostingProvider)){
		record.IsHostingProvider = true;
	}

	if(b.Has(ActiveVPN)){
		record.ActiveVPN = true;
	}

	if(b.Has(ActiveTOR)){
		record.ActiveTOR = true;
	}

	if(b.Has(PublicAccessPoint)){
		record.PublicAccessPoint = true;
	}
}