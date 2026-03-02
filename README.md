# Go PDF Password Retriever

High-performance, terminal-only brute-force for AES/RC4-encrypted PDFs. The tool parses the encryption dictionary, derives keys directly, and drives parallel workers to validate candidates using either a supplied wordlist or deterministic charset permutations. Run it from a shell to see live progress, ETA, and checkpoint updates; every successful or fully completed run removes the checkpoint file automatically.

## Features

- **Native Go implementation** with no Python dependencies; it derives the `/Encrypt` dictionary, file identifier (`/ID`), and padding per PDF spec.
- **Parallel workers** saturate available CPUs, avoid unnecessary heap copies, and report progress every few seconds (default is 5 s). ETA is computed from the observed attempt rate and shown both during the run and when the result returns.
- **Checkpoint / resume** persists the search state every configurable interval (default 10 minutes) so you can restart the process after a crash or interruption; the checkpoint file is removed as soon as a run finishes (successfully or after exhausting the candidate space).
- **Flexible input** accepts a wordlist or generates passwords via `-charset`, `-min`, and `-max`. Timeout controls and graceful cancellation ensure the utility can be composed inside automation pipelines.

## Prerequisites

- Go 1.24 or newer
- The encrypted PDF you want to inspect (this repo ships `Lorem_Ipsum.pdf`)

## Build & Install

```bash
go build -o bin/pdfpw ./cmd/pdfpw
```

macOS build (Intel/ARM compatible):

```bash
env GOOS=darwin GOARCH=amd64 go build -o bin/pdfpw-darwin-intel ./cmd/pdfpw
env GOOS=darwin GOARCH=arm64 go build -o bin/pdfpw-darwin-arm ./cmd/pdfpw
```

Windows build:

```bash
env GOOS=windows GOARCH=amd64 go build -o bin/pdfpw-windows.exe ./cmd/pdfpw
```

## Usage

```bash
./bin/pdfpw [flags]
```

| Flag | Description | Default |
| --- | --- | --- |
| `-pdf` | Path to the encrypted PDF | `Lorem_Ipsum.pdf` |
| `-wordlist` | Wordlist file; when set, charset generation is skipped | `` |
| `-charset` | Charset for deterministic generation when no wordlist is supplied | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` |
| `-min` | Minimum password length (inclusive) | `1` |
| `-max` | Maximum password length (inclusive) | `4` |
| `-workers` | Number of concurrent workers | `runtime.NumCPU()` |
| `-overcommit` | Multiplier that spawns additional goroutines per worker to keep more OS threads busy (`>= 1`) | `3` |
| `-timeout` | Optional stop duration (e.g., `30s`, `2m`) | `0` (no timeout) |
| `-checkpoint` | Checkpoint file path (defaults to `<pdf>.checkpoint` when checkpointing is enabled) | `` |
| `-checkpoint-interval` | How often to persist state; setting `0` disables checkpointing | `10m` |
| `-progress-interval` | How often to print the progress/ETA line; `0` silences updates | `5s` |

The runtime scheduler automatically sets `GOMAXPROCS` to the larger of `runtime.NumCPU()` and the total number of worker goroutines produced by `-workers` × `-overcommit`. With `-overcommit` set to `3` by default, the standard command (`./bin/pdfpw -pdf Lorem_Ipsum.pdf -charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" -min 4 -max 4`) launches enough goroutines to keep all CPU threads saturated without requiring any additional configuration.

### Examples

Use a wordlist and 8 workers:

```bash
./bin/pdfpw -pdf Lorem_Ipsum.pdf -wordlist ./passwords.txt -workers 8
```

When you already know the charset and length for `Lorem_Ipsum.pdf` (four mixed-case letters):

```bash
./bin/pdfpw -pdf Lorem_Ipsum.pdf -charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" -min 4 -max 4
```

The live progress line shows the number of attempts, elapsed time, and ETA. When you supply `-checkpoint-interval`, the resume file is overwritten every interval and deleted once the cracking attempt finishes (successfully or after trying every candidate).

## Testing

```bash
go test ./...
```

The automated tests exercise both the wordlist and charset paths using the repository’s `Lorem_Ipsum.pdf` sample (password `AbXy`).

## Design Notes

- The implementation pads passwords with the standard 32-byte padding string and derives the encryption key by hashing the padded password, owner entry, permissions, and file identifier.
- For revision 3 documents, `/U` is decrypted with 20 RC4 passes and matched against the MD5 hash of the padding string plus file ID.
- Checkpoint state tracks either the wordlist offset or the charset indices, letting the generator resume near the last saved combination.
