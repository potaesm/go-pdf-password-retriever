# Go PDF Password Retriever

## TLDR;
1. `go build -o bin/pdfpw ./cmd/pdfpw`
2. `./bin/pdfpw -pdf /path/to/go-pdf-password-retriever/Lorem_Ipsum.pdf -charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" -min 4 -max 4`
3. The shipped PDF unlocks with `AbXy` after the above run completes.

## What It Does
- Native Go brute force for AES/RC4 PDFs; it derives the `/Encrypt` dictionary, `/ID`, and padding per the PDF spec and checks candidates via parallel workers.
- Progress, ETA, and checkpoints print every few seconds and the checkpoint file is deleted when the session finishes.
- Supports wordlists (`-wordlist`) or deterministic charset generation (`-charset`, `-min`, `-max`) with configurable worker counts, timeout, and checkpoint interval.

## Build & Run
```bash
go build -o bin/pdfpw ./cmd/pdfpw
./bin/pdfpw -pdf /path/to/go-pdf-password-retriever/Lorem_Ipsum.pdf -charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" -min 4 -max 4
```
The command above targets the sample PDF with a four-character mixed-case password and runs as many goroutines as `runtime.NumCPU()` (and four overcommitted goroutines per worker) to keep all cores busy.

## Usage Flags
```bash
./bin/pdfpw -pdf <path> [-wordlist <file>] [-charset <set>] [-min <n>] [-max <n>] [-workers <n>] [-overcommit <n>] [-timeout <duration>] [-checkpoint <path>] [-checkpoint-interval <duration>] [-progress-interval <duration>]
```
Defaults include `Lorem_Ipsum.pdf`, an alphanumeric charset, length range `1-4`, `runtime.NumCPU()` workers, no checkpointing path, and 5 s progress updates.

## Testing
```bash
go test ./...
```
The tests cover both wordlist and charset paths against `Lorem_Ipsum.pdf` (password `AbXy`).
