package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/potaesm/go-pdf-password-retriever/internal/cracker"
)

const (
	warmupTrial     = 10 * time.Second
	warmupLongTrial = 15 * time.Second
)

var postTuneMultipliers = []float64{2, 3}
var warmupOvercommitMultipliers = []float64{1, 2, 4, 8}

type trackedIntFlag struct {
	value   int
	changed bool
}

func (f *trackedIntFlag) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	if v <= 0 {
		return fmt.Errorf("workers must be > 0")
	}
	f.value = v
	f.changed = true
	return nil
}

func (f *trackedIntFlag) String() string {
	return strconv.Itoa(f.value)
}

type trackedFloatFlag struct {
	value   float64
	changed bool
}

func (f *trackedFloatFlag) Set(s string) error {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	if v <= 0 {
		return fmt.Errorf("overcommit must be > 0")
	}
	f.value = v
	f.changed = true
	return nil
}

func (f *trackedFloatFlag) String() string {
	return strconv.FormatFloat(f.value, 'f', -1, 64)
}

type warmupCombo struct {
	workers    int
	overcommit float64
}

func main() {
	pdfPath := flag.String("pdf", "Lorem_Ipsum.pdf", "path to the password-protected PDF file")
	wordlist := flag.String("wordlist", "", "path to a password wordlist (one password per line)")
	charset := flag.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "character set to build passwords from")
	minLen := flag.Int("min", 1, "minimum password length when generating candidates")
	maxLen := flag.Int("max", 4, "maximum password length when generating candidates")
	var workersFlag trackedIntFlag
	workersFlag.value = runtime.NumCPU()
	flag.Var(&workersFlag, "workers", "number of parallel workers (omit to warm up/auto-tune)")
	var overcommitFlag trackedFloatFlag
	overcommitFlag.value = 1
	flag.Var(&overcommitFlag, "overcommit", "multiplier for worker goroutines relative to -workers (omit to warm up/auto-tune)")
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

	autoTune := !workersFlag.changed && !overcommitFlag.changed
	workersVal := workersFlag.value
	overcommitVal := overcommitFlag.value
	timeoutLeft := *timeout
	if autoTune {
		warmupCfg := cracker.Config{
			PDFPath:           pdfAbs,
			Wordlist:          *wordlist,
			Charset:           *charset,
			MinPasswordLength: *minLen,
			MaxPasswordLength: *maxLen,
			Workers:           runtime.NumCPU(),
			Overcommit:        1,
			ProgressInterval:  0,
			Progress:          nil,
		}
		printSample := func(prefix string, sample warmupSample) {
			if sample.Attempts == 0 {
				fmt.Printf("%s %d workers × %.1fx → no attempts (%v)\n",
					prefix, sample.combo.workers, sample.combo.overcommit, sample.Err)
				return
			}
			fmt.Printf("%s %d workers × %.1fx → %.0f attempts/s (%d attempts, %s)\n",
				prefix,
				sample.combo.workers,
				sample.combo.overcommit,
				sample.Rate,
				sample.Attempts,
				sample.Duration.Truncate(time.Millisecond))
		}
		logWarmup := func(sample warmupSample) {
			printSample("Warmup", sample)
		}
		bestWorkers, bestOvercommit, warmupElapsed, bestRate, anyAttempts, found, warmupRes, tuneErr := runWarmup(warmupCfg, runtime.NumCPU(), warmupTrial, logWarmup)
		if tuneErr != nil {
			fmt.Fprintln(os.Stderr, "warmup failed:", tuneErr)
			os.Exit(1)
		}
		if found {
			printResult(warmupRes, warmupElapsed)
			return
		}
		if !anyAttempts {
			fmt.Println("Warmup could not measure throughput; please rerun with explicit -workers/-overcommit.")
			os.Exit(1)
		}
		displayRate := bestRate
		if displayRate < 0 {
			displayRate = 0
		}
		fmt.Printf("Optimal parameters: -workers %d -overcommit %.1f (%.0f attempts/s warmup)\n", bestWorkers, bestOvercommit, displayRate)
		fmt.Printf("Re-run with `-workers %d -overcommit %.1f` to crack the PDF.\n", bestWorkers, bestOvercommit)
		return
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutLeft > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeoutLeft)
		defer cancel()
	}

	cpPath := *checkpoint
	if cpPath == "" && *checkpointInterval > 0 {
		cpPath = pdfAbs + ".checkpoint"
	}

	workerBase := workersVal
	if workerBase <= 0 {
		workerBase = runtime.NumCPU()
	}
	if workerBase < runtime.NumCPU() {
		workerBase = runtime.NumCPU()
	}
	workerOver := overcommitVal
	if workerOver < 1 {
		workerOver = 1
	}
	workerGoroutines := int(math.Ceil(float64(workerBase) * workerOver))
	const attemptsPerGoroutine = 5000.0
	baselineRate := float64(workerGoroutines) * attemptsPerGoroutine

	var progressFn func(cracker.ProgressInfo)
	if *progressInterval > 0 {
		var prevAttempts int64
		var prevElapsed time.Duration
		var smoothedRate float64
		progressFn = func(info cracker.ProgressInfo) {
			deltaAttempts := info.Attempts - prevAttempts
			deltaElapsed := info.Elapsed - prevElapsed
			prevAttempts = info.Attempts
			prevElapsed = info.Elapsed

			rateSample := 0.0
			if deltaElapsed > 0 {
				rateSample = float64(deltaAttempts) / math.Max(deltaElapsed.Seconds(), 1e-9)
			}

			sampleRate := math.Max(rateSample, baselineRate)
			if smoothedRate == 0 {
				smoothedRate = sampleRate
			} else {
				smoothedRate = smoothedRate*0.8 + sampleRate*0.2
			}

			eta := time.Duration(0)
			if info.Total > 0 && info.Attempts > 0 && info.Attempts < info.Total && smoothedRate > 0 {
				remaining := float64(info.Total - info.Attempts)
				eta = time.Duration(remaining/smoothedRate) * time.Second
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
		Workers:            workersVal,
		Overcommit:         workerOver,
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
	printResult(res, elapsed)
}

func printResult(res cracker.Result, elapsed time.Duration) {
	fmt.Printf("Password found: %q (tried %d candidates in %s)\n", res.Password, res.Attempts, elapsed)
	if res.TotalCandidates > 0 && res.Attempts > 0 && res.Attempts < res.TotalCandidates && res.Password == "" {
		rate := float64(res.Attempts) / math.Max(elapsed.Seconds(), 1e-9)
		remaining := float64(res.TotalCandidates - res.Attempts)
		if rate > 0 {
			eta := time.Duration(remaining/rate) * time.Second
			fmt.Printf("Estimated completion time remaining: %s\n", eta)
		}
	}
}

type warmupSample struct {
	combo    warmupCombo
	Attempts int64
	Rate     float64
	Duration time.Duration
	Err      error
}

func runWarmup(baseCfg cracker.Config, base int, trial time.Duration, logFn func(warmupSample)) (bestWorkers int, bestOvercommit float64, elapsed time.Duration, bestRate float64, anyAttempts bool, found bool, result cracker.Result, err error) {
	if base < 1 {
		base = 1
	}
	bestWorkers = base
	bestOvercommit = baseCfg.Overcommit
	bestRate = -1

	workerCandidates := []int{base}
	for _, factor := range []int{2, 4, 8} {
		workerCandidates = append(workerCandidates, base*factor)
	}

	for wIdx, workers := range workerCandidates {
		lastRate := -1.0
		for oIdx, mult := range warmupOvercommitMultipliers {
			combo := warmupCombo{workers: workers, overcommit: mult}
			trialDuration := trial
			if duration := comboTrialDuration(base, combo); duration > trialDuration {
				trialDuration = duration
			}
			sample, res, trialErr := runTrial(baseCfg, combo, trialDuration)
			elapsed += sample.Duration
			if logFn != nil {
				logFn(sample)
			}
			if sample.Attempts > 0 {
				anyAttempts = true
			}
			if trialErr == nil && res.Password != "" {
				return combo.workers, combo.overcommit, elapsed, sample.Rate, anyAttempts, true, res, nil
			}
			if trialErr != nil && !errors.Is(trialErr, context.DeadlineExceeded) && !errors.Is(trialErr, context.Canceled) && !errors.Is(trialErr, cracker.ErrPasswordNotFound) {
				return 0, 0, elapsed, 0, false, false, res, trialErr
			}
			if sample.Attempts > 0 && sample.Rate > bestRate {
				bestRate = sample.Rate
				bestWorkers = workers
				bestOvercommit = mult
			}
			if sample.Attempts == 0 {
				break
			}
			if lastRate >= 0 && sample.Rate < lastRate {
				break
			}
			lastRate = sample.Rate
			if oIdx < len(warmupOvercommitMultipliers)-1 {
				time.Sleep(10 * time.Second)
			}
		}
		if wIdx < len(workerCandidates)-1 {
			time.Sleep(10 * time.Second)
		}
	}

	if bestRate < 0 {
		bestRate = 0
	}

	return bestWorkers, bestOvercommit, elapsed, bestRate, anyAttempts, false, cracker.Result{}, nil
}

func runTrial(baseCfg cracker.Config, combo warmupCombo, trial time.Duration) (warmupSample, cracker.Result, error) {
	cfg := baseCfg
	cfg.Workers = combo.workers
	cfg.Overcommit = combo.overcommit
	ctx, cancel := context.WithTimeout(context.Background(), trial)
	defer cancel()
	start := time.Now()
	res, err := cracker.Crack(ctx, cfg)
	duration := time.Since(start)
	attempts := res.Attempts
	rate := float64(attempts) / math.Max(duration.Seconds(), 1e-9)
	return warmupSample{
		combo:    combo,
		Attempts: attempts,
		Rate:     rate,
		Duration: duration,
		Err:      err,
	}, res, err
}

func comboTrialDuration(base int, combo warmupCombo) time.Duration {
	if combo.workers >= base*4 || combo.overcommit >= 3 {
		return warmupLongTrial
	}
	return warmupTrial
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
