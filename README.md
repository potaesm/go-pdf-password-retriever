# Go PDF Password Retriever

## TLDR;
1. `go build -o bin/pdfpw ./cmd/pdfpw`
2. Run the sample with a known charset/length (`[a-z][A-Z]`, four characters): `./bin/pdfpw -pdf ./Lorem_Ipsum.pdf -charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" -min 4 -max 4`
3. The shipped PDF unlocks with `AbXy` after the above run completes.

## What It Does
- Native Go brute force for AES/RC4 PDFs; it derives the `/Encrypt` dictionary, `/ID`, and padding per the PDF spec and checks candidates via parallel workers.
- Progress, ETA, and checkpoints print every few seconds and the checkpoint file is deleted when the session finishes.
- Defaults set both `-workers` and `-overcommit` to `numCPU×numCPU`. Omit them to run with that magic concurrency level immediately.
- Use `-discover` to run the warmup/discovery phase and exit with the recommended `-workers`/`-overcommit` combo before starting the full crack.
- Supports wordlists (`-wordlist`) or deterministic charset generation (`-charset`, `-min`, `-max`) with configurable worker counts, timeout, and checkpoint interval.

## Build & Run
```bash
# Linux/macOS
go build -o bin/pdfpw ./cmd/pdfpw

# Windows
GOOS=windows GOARCH=amd64 go build -o bin/pdfpw-windows.exe ./cmd/pdfpw

# macOS universal
GOOS=darwin GOARCH=amd64 go build -o bin/pdfpw-macos ./cmd/pdfpw
```
The command above targets the sample PDF with a four-character mixed-case password. Run it without `-discover` to crack using the default `numCPU^2` concurrency; run it with `-discover` if you want the warmup to recommend the fastest `-workers`/`-overcommit` pair first.

## Usage Flags
```bash
./bin/pdfpw -pdf <path> [-wordlist <file>] [-charset <set>] [-min <n>] [-max <n>] [-workers <n>] [-overcommit <n>] [-timeout <duration>] [-checkpoint <path>] [-checkpoint-interval <duration>] [-progress-interval <duration>]
```
Defaults include `Lorem_Ipsum.pdf`, an alphanumeric charset, length range `1-4`, `-workers=numCPU×numCPU`, `-overcommit=numCPU×numCPU`, no checkpointing path, and 5 s progress updates. Append `-discover` to perform the warmup discovery phase before committing to those defaults.

## Testing
```bash
go test ./...
```
The tests cover both wordlist and charset paths against `Lorem_Ipsum.pdf` (password `AbXy`).
