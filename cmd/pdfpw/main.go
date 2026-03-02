package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/potaesm/go-pdf-password-retriever/internal/cracker"
)

func main() {
	pdfPath := flag.String("pdf", "Lorem_Ipsum.pdf", "path to the password-protected PDF file")
	wordlist := flag.String("wordlist", "", "path to a password wordlist (one password per line)")
	charset := flag.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "character set to build passwords from")
	minLen := flag.Int("min", 1, "minimum password length when generating candidates")
	maxLen := flag.Int("max", 4, "maximum password length when generating candidates")
	workers := flag.Int("workers", runtime.NumCPU(), "number of parallel workers")
	overcommit := flag.Float64("overcommit", 4, "multiplier for worker goroutines relative to -workers (must be >= 1)")
	timeout := flag.Duration("timeout", 0, "optional timeout for cracking (e.g., 30s, 2m)")
	checkpoint := flag.String("checkpoint", "", "path to the checkpoint file (default: <pdf>.checkpoint)")
	checkpointInterval := flag.Duration("checkpoint-interval", 10*time.Minute, "duration between checkpoint saves; set 0 to disable")
	progressInterval := flag.Duration("progress-interval", 5*time.Second, "duration between progress reports; set 0 to disable")

	flag.Parse()

	if *maxLen < *minLen {
		fmt.Fprintf(os.Stderr, "max length (%d) cannot be smaller than min length (%d)\n", *maxLen, *minLen)
		os.Exit(1)
	}

	pdfAbs, err := filepath.Abs(*pdfPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid PDF path:", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	cpPath := *checkpoint
	if cpPath == "" && *checkpointInterval > 0 {
		cpPath = pdfAbs + ".checkpoint"
	}

	var progressFn func(cracker.ProgressInfo)
	if *progressInterval > 0 {
		progressFn = func(info cracker.ProgressInfo) {
			eta := time.Duration(0)
			if info.Total > 0 && info.Attempts > 0 && info.Attempts < info.Total {
				rate := float64(info.Attempts) / math.Max(info.Elapsed.Seconds(), 1e-9)
				remaining := float64(info.Total - info.Attempts)
				if rate > 0 {
					eta = time.Duration(remaining/rate) * time.Second
				}
			}
			fmt.Printf("\rProgress: %d/%d (elapsed %s)%s",
				info.Attempts, info.Total, info.Elapsed.Truncate(time.Second), func() string {
					if eta > 0 {
						return fmt.Sprintf(" ETA %s", eta)
					}
					return ""
				}())
		}
	}

	cfg := cracker.Config{
		PDFPath:            pdfAbs,
		Wordlist:           *wordlist,
		Charset:            *charset,
		MinPasswordLength:  *minLen,
		MaxPasswordLength:  *maxLen,
		Workers:            *workers,
		Overcommit:         *overcommit,
		CheckpointPath:     cpPath,
		CheckpointInterval: *checkpointInterval,
		ProgressInterval:   *progressInterval,
		Progress:           progressFn,
	}

	start := time.Now()
	res, err := cracker.Crack(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error cracking PDF:", err)
		os.Exit(1)
	}

	if *progressInterval > 0 {
		fmt.Print("\n")
	}

	elapsed := time.Since(start)
	eta := time.Duration(0)
	if res.TotalCandidates > 0 && res.Attempts > 0 && res.Attempts < res.TotalCandidates {
		rate := float64(res.Attempts) / math.Max(elapsed.Seconds(), 1e-9)
		remaining := float64(res.TotalCandidates - res.Attempts)
		if rate > 0 {
			eta = time.Duration(remaining/rate) * time.Second
		}
	}

	fmt.Printf("Password found: %q (tried %d candidates in %s)\n", res.Password, res.Attempts, elapsed)
	if eta > 0 {
		fmt.Printf("Estimated completion time remaining: %s\n", eta)
	}
}
