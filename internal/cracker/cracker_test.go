package cracker

import (
	"context"
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
