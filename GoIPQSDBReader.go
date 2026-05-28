package GoIPQSDBReader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
)

func Open(filename string) (*FileReader, error) {
	file := &FileReader{Columns: make(map[int]*Column)}

	var ferr error
	f, ferr := os.Open(filename)
	if ferr != nil {
		return file, ferr
	}

	file.Handler = f

	header := make([]byte, 2)

	bl, err := file.Handler.Read(header)
	if err != nil {
		return file, err
	}

	fileheader := &BinaryOption{Data: Bit(header[0])}
	file.BinaryData = fileheader.Has(BinaryData)
	if fileheader.Has(IPv4Map) {
		file.Valid = true
		file.IPv6 = false
	}

	if fileheader.Has(IPv6Map) {
		file.Valid = true
		file.IPv6 = true
	}

	if fileheader.Has(IsBlacklistFile) {
		file.BlacklistFile = true
	}

	if file.Valid == false {
		return file, errors.New("Invalid file format, invalid first byte, EID 1.")
	}

	if header[1] != 0x01 && header[1] != 0x02 {
		return file, errors.New("Invalid file version, EID 1.")
	}
	file.Version = header[1]
	headersize := 11
	if file.Version == 0x02 {
		headersize = 16
	}
	headersize -= len(header)

	header = make([]byte, headersize) //-2 to offset for previous header load
	bl, err = file.Handler.Read(header)
	if err != nil {
		return file, err
	}
	bytedata, _ := binary.Uvarint(header[0:3]) //5-7
	if file.Version == 0x02 {
		bytedata, _ = binary.Uvarint(header[0:4]) //6-8

	}
	if bytedata == uint64(0) {
		return file, errors.New("Invalid file format, invalid header bytes, EID 2.")
	}

	file.RecordBytes, _ = binary.Uvarint(header[3:5])
	if file.Version == 0x02 {
		file.RecordBytes, _ = binary.Uvarint(header[4:6])
	}
	if file.RecordBytes == uint64(0) {
		return file, errors.New("Invalid file format, invalid record bytes, EID 3.")
	}

	file.TotalBytes = uint64(binary.LittleEndian.Uint32(header[5:9]))
	if file.Version == 0x02 {
		file.TotalBytes = uint64(binary.LittleEndian.Uint64(header[6:14]))

	}
	if file.TotalBytes == uint64(0) {
		return file, errors.New("Invalid file format, EID 4.")
	}

	file.TreeStart = int64(bytedata)

	headerbytes := 11
	if file.Version == 0x02 {
		headerbytes = 16
	}

	columns := make([]byte, bytedata-uint64(headerbytes))
	bl, err = file.Handler.Read(columns)
	if err != nil || bl != (int(bytedata)-headerbytes) {
		return file, err
	}

	for i := 0; i < ((int(bytedata) - headerbytes) / 24); i++ {
		file.Columns[i] = &Column{
			Name: string(bytes.Trim(columns[(i*24):((i+1)*24)-2], "\x00")),
			Type: &RecordType{Data: Bit(columns[(i*24)+23 : ((i + 1) * 24)][0])},
		}
	}

	if len(file.Columns) == 0 {
		return file, errors.New("File does not appear to be valid, no column data found. EID: 5")
	}

	treeheadersize := 5
	if file.Version == 0x02 {
		treeheadersize = 9
	}
	treeheader := make([]byte, treeheadersize)

	bl, err = file.Handler.Read(treeheader)
	if err != nil || bl != treeheadersize {
		return file, err
	}

	treetype := &RecordType{Data: Bit(treeheader[0])}

	if !treetype.Has(TreeData) {
		return file, errors.New("File does not appear to be valid, bad binary tree. EID: 6")
	}

	totaltree := uint64(binary.LittleEndian.Uint32(treeheader[1:5]))

	if file.Version == 0x02 {
		totaltree = uint64(binary.LittleEndian.Uint64(treeheader[1:9]))
	}
	if totaltree == 0 {
		return file, errors.New("File does not appear to be valid, tree size is too small. EID: 7")
	}

	file.TreeEnd = file.TreeStart + int64(totaltree)

	return file, nil
}
