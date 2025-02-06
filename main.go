package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modkernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDriveStringsW = modkernel32.NewProc("GetLogicalDriveStringsW")
	procQueryDosDeviceW         = modkernel32.NewProc("QueryDosDeviceW")
)

func main() {
	path := "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"

	location, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		fmt.Printf("Error loading Polish timezone: %v\n", err)
		return
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		fmt.Printf("Error opening registry path %s: %v\n", path, err)
		return
	}
	defer key.Close()

	csvFile, err := os.Create("sbe_all.csv")
	if err != nil {
		fmt.Printf("Error creating CSV file: %v\n", err)
		return
	}
	defer csvFile.Close()
	writerCsv := csv.NewWriter(csvFile)
	defer writerCsv.Flush()

	txtFile, err := os.Create("sbe_paths.txt")
	if err != nil {
		fmt.Printf("Error creating TXT file: %v\n", err)
		return
	}
	defer txtFile.Close()
	writerTxt := bufio.NewWriter(txtFile)
	defer writerTxt.Flush()

	err = writerCsv.Write([]string{"FileName", "ExecutionTime", "User"})
	if err != nil {
		fmt.Printf("Error writing CSV header: %v\n", err)
		return
	}

	sids, _ := key.ReadSubKeyNames(-1)
	for _, sid := range sids {
		processSid(key, sid, location, writerCsv, writerTxt)
	}
}

func processSid(key registry.Key, sid string, location *time.Location, writerCsv *csv.Writer, writerTxt *bufio.Writer) {
	userKey, err := registry.OpenKey(key, sid, registry.QUERY_VALUE)
	if err != nil {
		fmt.Printf("Error opening SID subkey %s: %v\n", sid, err)
		return
	}
	defer userKey.Close()

	values, _ := userKey.ReadValueNames(-1)
	for _, value := range values {
		raw, _, err := userKey.GetBinaryValue(value)
		if err != nil || len(raw) < 8 {
			continue
		}

		execTime := decodeFileTime(raw[:8], location)
		user := translateSid(sid)

		diskLetter := ConvertHardDiskVolumeToLetter(value)

		var updatedValue string
		if strings.HasPrefix(value, `\Device\HarddiskVolume`) {
			updatedValue = diskLetter + value[23:]
		} else {
			updatedValue = value
		}

		err = writerCsv.Write([]string{updatedValue, execTime, user})
		if err != nil {
			fmt.Printf("Error writing to CSV file: %v\n", err)
		}

		if strings.Contains(updatedValue, ":\\") {
			_, err = writerTxt.WriteString(fmt.Sprintf(updatedValue + "\n"))
			if err != nil {
				fmt.Printf("Error writing to TXT file: %v\n", err)
			}
		}
	}
}

func decodeFileTime(raw []byte, location *time.Location) string {
	var fileTime int64
	binary.Read(bytes.NewReader(raw), binary.LittleEndian, &fileTime)
	execTime := time.Unix(0, (fileTime-116444736000000000)*100).In(location)
	return execTime.Format("2006-01-02 15:04:05")
}

func translateSid(sid string) string {
	sidObj, err := windows.StringToSid(sid)
	if err != nil {
		return "Unknown User"
	}

	account, domain, _, err := sidObj.LookupAccount("")
	if err != nil {
		return "Unknown User"
	}

	return fmt.Sprintf("%s\\%s", domain, account)
}

func ConvertHardDiskVolumeToLetter(path string) string {
	const maxPath = 260
	var drives [maxPath]uint16
	var volumeName [maxPath]uint16
	var driveLetter = []uint16{' ', ':', 0}
	ret, _, _ := procGetLogicalDriveStringsW.Call(uintptr(maxPath), uintptr(unsafe.Pointer(&drives[0])))
	if ret == 0 {
		return "?:"
	}

	for i := 0; drives[i] != 0; i += 4 {
		driveLetter[0] = drives[i]
		ret, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(&driveLetter[0])), uintptr(unsafe.Pointer(&volumeName[0])), uintptr(maxPath))
		if ret == 0 {
			continue
		}

		volName := syscall.UTF16ToString(volumeName[:])

		if strings.HasPrefix(path, volName) {
			return fmt.Sprintf("%c:", rune(driveLetter[0]))
		}
	}

	return "?:"
}
