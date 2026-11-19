package card

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Share files between this program and the vendor's tools (Smart Card Shell, sc-hsm-tool). The tests are skipped unless their variables are set: they need the other tool's file
// or its answer, made by hand (docs/tokens/smartcard-hsm.md says how).
//
//	HSMGATE_INTEROP_FILE_HEX or HSMGATE_INTEROP_FILE  the file a vendor tool wrote (hexadecimal, or a path)
//	HSMGATE_INTEROP_PASSWORD                          its password
//	HSMGATE_INTEROP_EXPECT                            the share it holds, in hexadecimal (when it is known: scsh was given it)
//
// TestInteropWriteOurFile prints a compatible file of the share in HSMGATE_INTEROP_EXPECT, for a vendor tool to open.

func TestInteropOpenVendorFile(t *testing.T) {
	pw := os.Getenv("HSMGATE_INTEROP_PASSWORD")
	var file []byte
	switch {
	case os.Getenv("HSMGATE_INTEROP_FILE_HEX") != "":
		var err error
		if file, err = hex.DecodeString(os.Getenv("HSMGATE_INTEROP_FILE_HEX")); err != nil {
			t.Fatal(err)
		}
	case os.Getenv("HSMGATE_INTEROP_FILE") != "":
		var err error
		if file, err = os.ReadFile(os.Getenv("HSMGATE_INTEROP_FILE")); err != nil {
			t.Fatal(err)
		}
	default:
		t.Skip("set HSMGATE_INTEROP_FILE or HSMGATE_INTEROP_FILE_HEX and HSMGATE_INTEROP_PASSWORD")
	}
	if f, ok := FormatOf(file); !ok || f != Compatible {
		t.Fatalf("the file of the vendor tool is not read as the compatible format: %v %v (%d bytes)", f, ok, len(file))
	}
	share, err := DecryptShare(file, []byte(pw))
	if err != nil {
		t.Fatalf("the file of the vendor tool was not opened: %v", err)
	}
	t.Logf("opened: %d bytes, the key check value %X", len(share), KCV(share))
	if want := os.Getenv("HSMGATE_INTEROP_EXPECT"); want != "" {
		if got := hex.EncodeToString(share); !strings.EqualFold(got, want) {
			t.Errorf("the share is %s, expected %s", got, want)
		}
	}
}

func TestInteropWriteOurFile(t *testing.T) {
	want := os.Getenv("HSMGATE_INTEROP_EXPECT")
	if want == "" || os.Getenv("HSMGATE_INTEROP_PASSWORD") == "" {
		t.Skip("set HSMGATE_INTEROP_EXPECT (a share in hexadecimal) and HSMGATE_INTEROP_PASSWORD")
	}
	share, err := hex.DecodeString(want)
	if err != nil || len(share) != ShareLen {
		t.Fatal("not a share")
	}
	file, err := EncryptShare(Compatible, share, []byte(os.Getenv("HSMGATE_INTEROP_PASSWORD")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptShare(file, []byte(os.Getenv("HSMGATE_INTEROP_PASSWORD"))); err != nil || !bytes.Equal(got, share) {
		t.Fatal("our file is not read back by us")
	}
	fmt.Printf("OUR-FILE-HEX=%X\n", file)
}
