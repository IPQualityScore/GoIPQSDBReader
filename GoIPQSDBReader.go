package GoIPQSDBReader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
)

var GOLANG_IPQS_READER_VERSION = byte(1)

func Open(filename string) (*FileReader, error) {
	file := &FileReader{Columns: make(map[int]*Column)}

	var ferr error
	file.Handler, ferr = os.Open(filename)
	if ferr != nil {
		return file, ferr
	}

	header := make([]byte, 11)
	bl, err := file.Handler.Read(header)
	if err != nil || bl != 11 {
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

	if header[1] != GOLANG_IPQS_READER_VERSION {
		return file, errors.New("Invalid file version, EID 1.")
	}

	bytedata, _ := binary.Uvarint(header[2:5])
	if bytedata == uint64(0) {
		return file, errors.New("Invalid file format, invalid header bytes, EID 2.")
	}

	file.RecordBytes, _ = binary.Uvarint(header[5:7])
	if file.RecordBytes == uint64(0) {
		return file, errors.New("Invalid file format, invalid record bytes, EID 3.")
	}

	file.TotalBytes = uint64(binary.LittleEndian.Uint32(header[7:11]))
	if file.TotalBytes == uint64(0) {
		return file, errors.New("Invalid file format, EID 4.")
	}

	file.TreeStart = int64(bytedata)
	columns := make([]byte, bytedata-11)
	bl, err = file.Handler.Read(columns)
	if err != nil || bl != (int(bytedata)-11) {
		return file, err
	}

	for i := 0; i < ((int(bytedata) - 11) / 24); i++ {
		file.Columns[i] = &Column{
			Name: string(bytes.Trim(columns[(i*24):((i+1)*24)-2], "\x00")),
			Type: &RecordType{Data: Bit(columns[(i*24)+23 : ((i + 1) * 24)][0])},
		}
	}

	if len(file.Columns) == 0 {
		return file, errors.New("File does not appear to be valid, no column data found. EID: 5")
	}

	treeheader := make([]byte, 5)
	bl, err = file.Handler.Read(treeheader)
	if err != nil || bl != 5 {
		return file, err
	}

	treetype := &RecordType{Data: Bit(treeheader[0])}

	if !treetype.Has(TreeData) {
		return file, errors.New("File does not appear to be valid, bad binary tree. EID: 6")
	}

	totaltree := uint64(binary.LittleEndian.Uint32(treeheader[1:5]))
	if totaltree == 0 {
		return file, errors.New("File does not appear to be valid, tree size is too small. EID: 7")
	}

	file.TreeEnd = file.TreeStart + int64(totaltree)

	return file, nil
}
