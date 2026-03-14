package cracker

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func samplePDFPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "Lorem_Ipsum.pdf")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

func requireSamplePDF(t *testing.T) string {
	t.Helper()
	pdfPath := samplePDFPath(t)
	if _, err := os.Stat(pdfPath); err != nil {
		t.Skipf("sample PDF not available: %v", err)
	}
	return pdfPath
}

func TestCrack_WithWordlist(t *testing.T) {
	pdfPath := requireSamplePDF(t)

	wordlist := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(wordlist, []byte("password1\nAbXy\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	cfg := Config{
		PDFPath:  pdfPath,
		Wordlist: wordlist,
		Workers:  2,
	}

	res, err := Crack(context.Background(), cfg)
	if err != nil {
		t.Fatalf("crack: %v", err)
	}

	if res.Password != "AbXy" {
		t.Fatalf("expected AbXy, got %q", res.Password)
	}

	if res.Attempts == 0 {
		t.Fatalf("expected at least one attempt")
	}
}

func TestCrack_WithCharset(t *testing.T) {
	pdfPath := requireSamplePDF(t)

	cfg := Config{
		PDFPath:           pdfPath,
		Charset:           "AbXy",
		MinPasswordLength: 4,
		MaxPasswordLength: 4,
		Workers:           1,
	}

	res, err := Crack(context.Background(), cfg)
	if err != nil {
		t.Fatalf("crack: %v", err)
	}

	if res.Password != "AbXy" {
		t.Fatalf("expected AbXy from charset, got %q", res.Password)
	}

	if res.Attempts == 0 {
		t.Fatalf("expected at least one attempt")
	}
}

func TestParseEncryptionObject_WithIndirectStrings(t *testing.T) {
	pdfData := []byte(`
3 0 obj
<< /V 4 /R 4 /O 5 0 R /U 6 0 R /Length 128 /P -1020 >>
endobj
5 0 obj
<0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef>
endobj
6 0 obj
(abcdefghijklmnop)
endobj
`)

	obj := []byte("<< /V 4 /R 4 /O 5 0 R /U 6 0 R /Length 128 /P -1020 >>")
	dict, err := parseEncryptionObject(obj, pdfData)
	if err != nil {
		t.Fatalf("parse encryption object: %v", err)
	}

	expectedO, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if !bytes.Equal(dict.O, expectedO) {
		t.Fatalf("unexpected O value")
	}

	if got := string(dict.U); got != "abcdefghijklmnop" {
		t.Fatalf("unexpected U literal: %q", got)
	}
}

func TestCharsetIteratorPermutedIndex(t *testing.T) {
	it := &charsetIterator{
		total:          10,
		randomOrder:    true,
		permMultiplier: 3,
		permAdd:        7,
	}

	seen := make(map[int64]struct{})
	for seqIdx := int64(0); seqIdx < it.total; seqIdx++ {
		mapped := it.permutedIndex(seqIdx)
		if mapped < 0 || mapped >= it.total {
			t.Fatalf("mapped index %d out of bounds", mapped)
		}
		if _, ok := seen[mapped]; ok {
			t.Fatalf("duplicate mapped index %d for seq %d", mapped, seqIdx)
		}
		seen[mapped] = struct{}{}
	}

	if len(seen) != int(it.total) {
		t.Fatalf("expected %d unique indexes, got %d", it.total, len(seen))
	}
}
