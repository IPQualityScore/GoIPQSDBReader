package GoIPQSDBReader;

import (
	"os";
	"net";
	"fmt";
	"math";
	"strconv";
	"errors";
	"strings";
	"encoding/binary";
);

type FileReader struct {
	Handler *os.File;
	TotalBytes uint64;
	RecordBytes uint64;

	TreeStart int64;
	TreeEnd int64;

	IPv6 bool;
	Valid bool;
	BinaryData bool;
	Columns map[int]*Column;

	BlacklistFile bool;
}

func (file *FileReader) Fetch(ip string) (*IPQSRecord, error){
	record := &IPQSRecord{};

	if(file.IPv6 && strings.Contains(ip, ".")){
		return record, errors.New("Attemtped to look up IPv4 using IPv6 database file. Aborting.");
	} else if(!file.IPv6 && strings.Contains(ip, ":")){
		return record, errors.New("Attemtped to look up IPv6 using IPv4 database file. Aborting.");
	}

	position := 0;
	previous := make(map[int]int64);
	file_position := file.TreeStart + int64(5);
	literal := convertIPToBinaryLitteral(file.IPv6, ip);

	// Loop over tree. Will abort if we try too many times.
	for l:=0;l<257;l++ {
		previous[position] = file_position;

		// Read tree.
		if(len(literal) <= position){
			return record, errors.New("Invalid or nonexistant IP address specified for lookup. (EID: 8)");
		}
		
		read := make([]byte, 8);

		br, err := file.Handler.ReadAt(read, file_position);
		if(br == 0 || err != nil){
			return record, errors.New("Invalid or nonexistant IP address specified for lookup. (EID: 9)");
		}

		if(literal[position] == "0"){
			file_position = int64(binary.LittleEndian.Uint32(read[0:4]))
		} else {
			file_position = int64(binary.LittleEndian.Uint32(read[4:8]));
		}

		if(!file.BlacklistFile){
			if(file_position == 0){
				for i := 0; i <= position; i++ {
					if(literal[position-i] == "1"){
						literal[position-i] = "0";
						
						for n := (position - i + 1); n < len(literal); n++ {
							literal[n] = "1";
						}

						position = position - i;
						file_position = previous[position];
						break;
					}
				}

				continue;
			}
		}
		
		if(file_position < file.TreeEnd){
			if(file_position == 0){
				break;
			}
			
			position++;
			continue;
		}

		// In theory we're at a record.
		raw := make([]byte, file.RecordBytes);

		br, err = file.Handler.ReadAt(raw, file_position);
		if(br == 0 || err != nil){
			return record, errors.New("Invalid or nonexistant IP address specified for lookup. (EID: 11)");
		}

		return parseRecord(record, raw, file);
	}

	return record, errors.New("Invalid or nonexistant IP address specified for lookup. (EID: 12)");
}

func parseRecord(record *IPQSRecord, raw []byte, file *FileReader) (*IPQSRecord, error){
	current_byte := 0;
	if(file.BinaryData){
		// Handle first three bits.
		record.processFirstByte(&BinaryOption{Data: Bit(raw[0])});
		record.processSecondByte(&BinaryOption{Data: Bit(raw[1])});

		third := &BinaryOption{Data: Bit(raw[2])};
		record.ConnectionType = createConnectionType(third);
		record.AbuseVelocity = createAbuseVelocity(third);
		current_byte = 3;
	} else {
		// Handle first bit.
		first := &BinaryOption{Data: Bit(raw[0])};
		record.ConnectionType = createConnectionType(first);
		record.AbuseVelocity = createAbuseVelocity(first);
		current_byte = 1;
	}

	record.FraudScore = &FraudScore{Strictness: make(map[int]int)};
	
	// Handle columns.
	for i := 0; i < len(file.Columns); i++ {
		c, e0 := file.Columns[i];
		if(e0 == false){
			return record, errors.New("Invalid or nonexistant IP address specified for lookup. (EID: 12)");
		}

		var value string;
		var err error;
		switch(c.Name){
			case "ASN":
				i := int(binary.LittleEndian.Uint32(raw[current_byte:current_byte + 4]));
				record.ASN = i;
				value = strconv.Itoa(i);

				record.Columns = append(record.Columns, createColumn(c.Name, value, IntData));
				current_byte += 4;
			case "Latitude":
				f := math.Float32frombits(binary.LittleEndian.Uint32(raw[current_byte:current_byte + 4]));
				record.Latitude = f;
				value = fmt.Sprintf("%f", f);

				record.Columns = append(record.Columns, createColumn(c.Name, value, FloatData));
				current_byte += 4;
			case "Longitude":
				f := math.Float32frombits(binary.LittleEndian.Uint32(raw[current_byte:current_byte + 4]));
				record.Longitude = f;
				value = fmt.Sprintf("%f", f);
				
				record.Columns = append(record.Columns, createColumn(c.Name, value, FloatData));
				current_byte += 4;
			case "ZeroFraudScore":
				i := int(uint8(raw[current_byte]));
				record.FraudScore.Strictness[0] = i;
				value = strconv.Itoa(i);

				record.Columns = append(record.Columns, createColumn(c.Name, value, SmallIntData));
				current_byte++;
			case "OneFraudScore":
				i := int(uint8(raw[current_byte]));
				record.FraudScore.Strictness[1] = i;
				value = strconv.Itoa(i);

				record.Columns = append(record.Columns, createColumn(c.Name, value, SmallIntData));
				current_byte++;
			default:
				if(c.Type.Has(StringData)){
					value, err = getRangedStringValue(file, raw[current_byte:current_byte+4]);
					if(err != nil){
						return record, errors.New("Invalid string data. (EID: 12)");
					}

					record.Columns = append(record.Columns, createColumn(c.Name, value, StringData));
					current_byte += 4;
				}
		}

		switch(c.Name){
			case "Country":
				record.Country = value;
			case "City":
				record.City = value;
			case "Region":
				record.Region = value;
			case "ISP":
				record.ISP = value;
			case "Organization":
				record.Organization = value;
			case "Timezone":
				record.Timezone = value;
		}
	}

	return record, nil;
}



func createColumn(name string, value string, datatype Bit) *Column {
	return &Column{Name: name, RawValue: value, Type: &RecordType{Data: datatype}};
}

func getRangedStringValue(file *FileReader, pointer []byte) (string, error) {
	position := binary.LittleEndian.Uint32(pointer);
	sizeraw := make([]byte, 1);
	br, err := file.Handler.ReadAt(sizeraw, int64(position));
	if(br == 0 || err != nil){
		return "", err;
	}

	size := int(uint8(sizeraw[0]));
	raw := make([]byte, size);
	br, err = file.Handler.ReadAt(raw, int64(position) + int64(1));
	if(br == 0 || err != nil){
		return "", err;
	}

	return string(raw), nil;
}

func createConnectionType(data *BinaryOption) *ConnectionType {
	ct := &ConnectionType{};
	if(data.Has(ConnectionTypeThree)){
		if(data.Has(ConnectionTypeTwo)){
			ct.Raw = 3;
			return ct;
		}

		if(data.Has(ConnectionTypeOne)){
			ct.Raw = 5;
			return ct;
		}

		ct.Raw = 1;
		return ct;
	}

	if(data.Has(ConnectionTypeTwo)){
		ct.Raw = 2;
		return ct;
	}

	if(data.Has(ConnectionTypeOne)){
		ct.Raw = 4;
		return ct;
	}

    ct.Raw = 0;
	return ct;
}

func createAbuseVelocity(data *BinaryOption) *AbuseVelocity {
	av := &AbuseVelocity{};
	if(data.Has(AbuseVelocityTwo)){
		if(data.Has(AbuseVelocityOne)){
			av.Raw = 3;
			return av;
		}

		av.Raw = 1;
		return av;
	}

	if(data.Has(AbuseVelocityOne)){
		av.Raw = 2;
		return av;
	}

	av.Raw = 0;
	return av;
}

func convertIPToBinaryLitteral(ipv6 bool, ip string) []string {
	var result []string;
	if(ipv6){
		parts := "";
		for _, n := range net.IP.To16(net.ParseIP(ip)){
			parts = parts + fmt.Sprintf("%08b", n);
		}

		for i:=0;i<len(parts);i++ {
			result = append(result, string(parts[i]));
		}
	} else {
		parts := "";
		for _, n := range net.IP.To4(net.ParseIP(ip)){
			parts = parts + fmt.Sprintf("%08b", n);
		}

		for i:=0;i<len(parts);i++ {
			result = append(result, string(parts[i]));
		}
	}

	return result;
}
