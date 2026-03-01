package cracker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	modeWordlist = "wordlist"
	modeCharset  = "charset"
)

var (
	ErrPasswordNotFound   = errors.New("password not found")
	errCheckpointMismatch = errors.New("checkpoint signature mismatch")
	passwordPadding       = []byte{0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
		0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A}
	defaultCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type Config struct {
	PDFPath            string
	Wordlist           string
	Charset            string
	MinPasswordLength  int
	MaxPasswordLength  int
	Workers            int
	CheckpointPath     string
	CheckpointInterval time.Duration
	ProgressInterval   time.Duration
	Progress           func(ProgressInfo)
}

type Result struct {
	Password        string
	Attempts        int64
	TotalCandidates int64
}

type ProgressInfo struct {
	Attempts int64
	Total    int64
	Elapsed  time.Duration
}

type charsetState struct {
	Length    int   `json:"length"`
	Indices   []int `json:"indices"`
	NextIndex int64 `json:"next_index,omitempty"`
}

type checkpointState struct {
	Signature      string        `json:"signature"`
	Mode           string        `json:"mode"`
	WordlistOffset int64         `json:"wordlist_offset,omitempty"`
	CharsetState   *charsetState `json:"charset_state,omitempty"`
	Attempts       int64         `json:"attempts"`
}

type checkpointSaver struct {
	path      string
	interval  time.Duration
	mu        sync.Mutex
	last      time.Time
	signature string
}

type encryptionDict struct {
	V         int
	R         int
	Length    int
	KeyLength int
	O         []byte
	U         []byte
	P         int32
	ID        []byte
}

func Crack(ctx context.Context, cfg Config) (Result, error) {
	if cfg.PDFPath == "" {
		return Result{}, errors.New("PDF path is required")
	}

	if cfg.Charset == "" {
		cfg.Charset = defaultCharset
	}

	if cfg.MinPasswordLength <= 0 {
		cfg.MinPasswordLength = 1
	}

	if cfg.MaxPasswordLength < cfg.MinPasswordLength {
		cfg.MaxPasswordLength = cfg.MinPasswordLength
	}

	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}

	if err := expectFile(cfg.PDFPath); err != nil {
		return Result{}, err
	}

	enc, err := readEncryptionDict(cfg.PDFPath)
	if err != nil {
		return Result{}, err
	}

	signature := runSignature(cfg)
	resume := checkpointState{}
	if cfg.CheckpointInterval > 0 && cfg.CheckpointPath != "" {
		resume, err = loadCheckpoint(cfg.CheckpointPath, signature)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				resume = checkpointState{}
			} else if errors.Is(err, errCheckpointMismatch) {
				_ = os.Remove(cfg.CheckpointPath)
				resume = checkpointState{}
			} else {
				return Result{}, err
			}
		}
	}

	saver := newCheckpointSaver(cfg.CheckpointPath, cfg.CheckpointInterval, signature)

	totalCandidates, err := computeTotalCandidates(cfg)
	if err != nil {
		return Result{}, err
	}

	start := time.Now()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)

	var passwordCh chan string
	if cfg.Wordlist != "" {
		passwordBuf := cfg.Workers * 8
		if passwordBuf < 4 {
			passwordBuf = 4
		}
		passwordCh = make(chan string, passwordBuf)
	}

	var charsetIter *charsetIterator
	if cfg.Wordlist == "" {
		resumeIndex := resumeCharsetIndex(resume.CharsetState, len(cfg.Charset), cfg.MinPasswordLength)
		var err error
		charsetIter, err = newCharsetIterator(cfg.Charset, cfg.MinPasswordLength, cfg.MaxPasswordLength, resumeIndex)
		if err != nil {
			return Result{}, err
		}
	}

	var attempts int64 = resume.Attempts

	var progressStop chan struct{}
	if cfg.Progress != nil && cfg.ProgressInterval > 0 {
		progressStop = make(chan struct{})
		ticker := time.NewTicker(cfg.ProgressInterval)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-progressStop:
					return
				case <-ticker.C:
					cfg.Progress(ProgressInfo{Attempts: atomic.LoadInt64(&attempts), Total: totalCandidates, Elapsed: time.Since(start)})
				}
			}
		}()
	}

	if cfg.Wordlist != "" {
		go func() {
			defer close(passwordCh)
			if err := streamWordlist(ctx, cfg.Wordlist, resume, &attempts, saver, passwordCh); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}()
	}

	found := make(chan string, 1)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				var (
					pw  string
					idx int64
					ok  bool
				)

				if cfg.Wordlist != "" {
					select {
					case <-ctx.Done():
						return
					case pw, ok = <-passwordCh:
						if !ok {
							return
						}
					}
				} else {
					pw, idx, ok = charsetIter.Next()
					if !ok {
						return
					}
				}

				atomic.AddInt64(&attempts, 1)
				key := encryptionKey(pw, enc)
				if key == nil {
					continue
				}

				if isValidUserPassword(key, enc) {
					select {
					case found <- pw:
						cancel()
					default:
					}
					return
				}

				if saver != nil && cfg.Wordlist == "" {
					state := checkpointState{
						Mode: modeCharset,
						CharsetState: &charsetState{
							NextIndex: idx + 1,
						},
						Attempts: atomic.LoadInt64(&attempts),
					}
					if err := saver.MaybeSave(state); err != nil {
						select {
						case errCh <- err:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	finish := func(res Result, retErr error) (Result, error) {
		if progressStop != nil {
			close(progressStop)
		}
		if cfg.Progress != nil {
			cfg.Progress(ProgressInfo{Attempts: atomic.LoadInt64(&attempts), Total: totalCandidates, Elapsed: time.Since(start)})
		}
		if saver != nil && cfg.CheckpointPath != "" {
			if retErr == nil || errors.Is(retErr, ErrPasswordNotFound) {
				_ = os.Remove(cfg.CheckpointPath)
			}
		}
		res.TotalCandidates = totalCandidates
		return res, retErr
	}

	select {
	case pw := <-found:
		return finish(Result{Password: pw, Attempts: atomic.LoadInt64(&attempts)}, nil)
	case <-done:
		return finish(Result{}, ErrPasswordNotFound)
	case err := <-errCh:
		return finish(Result{}, err)
	case <-ctx.Done():
		if ctx.Err() != nil {
			return finish(Result{}, ctx.Err())
		}
		return finish(Result{}, ErrPasswordNotFound)
	}
}

func runSignature(cfg Config) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%d|%d|%d", cfg.PDFPath, cfg.Wordlist, cfg.Charset, cfg.MinPasswordLength, cfg.MaxPasswordLength, cfg.Workers)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func newCheckpointSaver(path string, interval time.Duration, signature string) *checkpointSaver {
	if path == "" || interval <= 0 {
		return nil
	}
	return &checkpointSaver{path: path, interval: interval, signature: signature}
}

func (s *checkpointSaver) MaybeSave(state checkpointState) error {
	if s == nil || s.path == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.interval > 0 && !s.last.IsZero() && time.Since(s.last) < s.interval {
		return nil
	}

	state.Signature = s.signature

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}

	s.last = time.Now()
	return nil
}

func loadCheckpoint(path, signature string) (checkpointState, error) {
	if path == "" {
		return checkpointState{}, os.ErrNotExist
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return checkpointState{}, err
	}

	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return checkpointState{}, err
	}

	if state.Signature != signature {
		return checkpointState{}, fmt.Errorf("%w: got %s", errCheckpointMismatch, state.Signature)
	}

	return state, nil
}

func computeTotalCandidates(cfg Config) (int64, error) {
	if cfg.Wordlist != "" {
		return countWordlistLines(cfg.Wordlist)
	}
	return charsetTotal(len(cfg.Charset), cfg.MinPasswordLength, cfg.MaxPasswordLength), nil
}

func countWordlistLines(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	var count int64
	var last byte
	hasData := false

	for {
		n, err := file.Read(buf)
		if n > 0 {
			hasData = true
			count += int64(bytes.Count(buf[:n], []byte{'\n'}))
			last = buf[n-1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if hasData && last != '\n' {
		count++
	}

	return count, nil
}

func charsetTotal(base, minLen, maxLen int) int64 {
	if base <= 0 || minLen <= 0 {
		return 0
	}

	total := big.NewInt(0)
	limit := big.NewInt(math.MaxInt64)
	for length := minLen; length <= maxLen; length++ {
		if length <= 0 {
			continue
		}
		combos := new(big.Int).Exp(big.NewInt(int64(base)), big.NewInt(int64(length)), nil)
		total.Add(total, combos)
		if total.Cmp(limit) >= 0 {
			return math.MaxInt64
		}
	}

	if total.IsInt64() {
		return total.Int64()
	}
	return math.MaxInt64
}

func streamWordlist(ctx context.Context, path string, resume checkpointState, attempts *int64, saver *checkpointSaver, out chan<- string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	offset := resume.WordlistOffset
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	}

	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}

		if len(line) == 0 && err == io.EOF {
			break
		}

		password := strings.TrimSpace(line)
		offset += int64(len(line))

		if password != "" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- password:
			}
		}

		if saver != nil {
			state := checkpointState{Mode: modeWordlist, WordlistOffset: offset, Attempts: atomic.LoadInt64(attempts)}
			if err := saver.MaybeSave(state); err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
	}

	return nil
}

func newCharsetIterator(charset string, minLen, maxLen int, resumeIndex int64) (*charsetIterator, error) {
	if len(charset) == 0 {
		return nil, errors.New("charset cannot be empty")
	}

	ranges := make([]charsetRange, 0, maxLen-minLen+1)
	start := int64(0)
	for length := minLen; length <= maxLen; length++ {
		if length <= 0 {
			continue
		}

		count := powInt64(len(charset), length)
		if count <= 0 {
			count = math.MaxInt64
		}

		end := start + count
		if end < 0 || end < start {
			end = math.MaxInt64
		}

		ranges = append(ranges, charsetRange{
			length: length,
			start:  start,
			end:    end,
		})

		if math.MaxInt64-start < count {
			start = math.MaxInt64
		} else {
			start = end
		}
	}

	return &charsetIterator{
		charset: []byte(charset),
		base:    len(charset),
		ranges:  ranges,
		total:   start,
		next:    min(resumeIndex, start),
	}, nil
}

func powInt64(base, exp int) int64 {
	result := int64(1)
	for i := 0; i < exp; i++ {
		if result > math.MaxInt64/int64(base) {
			return math.MaxInt64
		}
		result *= int64(base)
	}
	return result
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

type charsetIterator struct {
	charset []byte
	base    int
	ranges  []charsetRange
	total   int64
	next    int64
}

type charsetRange struct {
	length int
	start  int64
	end    int64
}

func resumeCharsetIndex(state *charsetState, base, minLen int) int64 {
	if state == nil {
		return 0
	}
	if state.NextIndex > 0 {
		return state.NextIndex
	}
	if state.Length < minLen || len(state.Indices) == 0 {
		return 0
	}
	index := int64(0)
	for length := minLen; length < state.Length; length++ {
		index += powInt64(base, length)
	}
	value := int64(0)
	for _, digit := range state.Indices {
		value = value*int64(base) + int64(digit)
	}
	index += value
	if index < 0 {
		return 0
	}
	return index
}

func (it *charsetIterator) Next() (string, int64, bool) {
	idx := atomic.AddInt64(&it.next, 1) - 1
	if idx >= it.total {
		return "", 0, false
	}
	return it.passwordAt(idx)
}

func (it *charsetIterator) passwordAt(idx int64) (string, int64, bool) {
	var rng *charsetRange
	for i := range it.ranges {
		if idx >= it.ranges[i].start && idx < it.ranges[i].end {
			rng = &it.ranges[i]
			break
		}
	}
	if rng == nil {
		return "", 0, false
	}

	offset := idx - rng.start
	pass := make([]byte, rng.length)
	for i := rng.length - 1; i >= 0; i-- {
		pass[i] = it.charset[offset%int64(it.base)]
		offset /= int64(it.base)
	}

	return string(pass), idx, true
}

func encryptionKey(password string, dict encryptionDict) []byte {
	padded := padPassword([]byte(password))
	buf := make([]byte, 0, len(padded)+len(dict.O)+4+len(dict.ID))
	buf = append(buf, padded...)
	buf = append(buf, dict.O...)
	pBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pBytes, uint32(dict.P))
	buf = append(buf, pBytes...)
	buf = append(buf, dict.ID...)

	sum := md5.Sum(buf)
	key := sum[:]

	if dict.R >= 3 {
		for i := 0; i < 50; i++ {
			sum = md5.Sum(key[:dict.KeyLength])
			key = sum[:]
		}
	}

	if dict.KeyLength > len(key) {
		return nil
	}

	return append([]byte(nil), key[:dict.KeyLength]...)
}

func isValidUserPassword(key []byte, dict encryptionDict) bool {
	if len(key) == 0 {
		return false
	}

	data := append([]byte(nil), dict.U...)
	if dict.R >= 3 {
		for i := 19; i >= 0; i-- {
			k := make([]byte, len(key))
			for j := range key {
				k[j] = key[j] ^ byte(i)
			}
			c, err := rc4.NewCipher(k)
			if err != nil {
				return false
			}
			c.XORKeyStream(data, data)
		}
	} else {
		c, err := rc4.NewCipher(key)
		if err != nil {
			return false
		}
		c.XORKeyStream(data, data)
	}

	if dict.R >= 3 {
		if len(data) < 16 || len(dict.ID) == 0 {
			return false
		}
		sum := md5.New()
		sum.Write(passwordPadding)
		sum.Write(dict.ID)
		expected := sum.Sum(nil)
		return bytes.Equal(data[:16], expected)
	}

	if len(data) < len(passwordPadding) {
		return false
	}

	return bytes.Equal(data[:len(passwordPadding)], passwordPadding)
}

func padPassword(password []byte) []byte {
	padded := make([]byte, 32)
	copy(padded, password)
	if len(password) < len(passwordPadding) {
		copy(padded[len(password):], passwordPadding[:32-len(password)])
	}
	return padded
}

func readEncryptionDict(pdfPath string) (encryptionDict, error) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return encryptionDict{}, err
	}

	encRef, err := findEncryptReference(data)
	if err != nil {
		return encryptionDict{}, err
	}

	obj, err := findObject(data, encRef.objNum, encRef.genNum)
	if err != nil {
		return encryptionDict{}, err
	}

	dict, err := parseEncryptionObject(obj)
	if err != nil {
		return encryptionDict{}, err
	}

	id, err := parseID(data)
	if err != nil {
		return encryptionDict{}, err
	}

	dict.ID = id

	if dict.Length == 0 {
		dict.Length = 40
	}

	dict.KeyLength = dict.Length / 8
	if dict.KeyLength < 5 {
		dict.KeyLength = 5
	}
	if dict.KeyLength > 16 {
		dict.KeyLength = 16
	}

	return dict, nil
}

func parseID(data []byte) ([]byte, error) {
	idx := bytes.LastIndex(data, []byte("/ID ["))
	if idx == -1 {
		return nil, errors.New("ID not found in PDF")
	}

	start := idx + len("/ID [")
	for start < len(data) && data[start] != '(' && data[start] != '<' {
		start++
	}

	if start >= len(data) {
		return nil, errors.New("ID entry malformed")
	}

	if data[start] == '(' {
		end := start + 1
		depth := 0
		for end < len(data) {
			if data[end] == '(' {
				depth++
			} else if data[end] == ')' {
				if depth == 0 {
					break
				}
				depth--
			} else if data[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(data) {
			return nil, errors.New("unterminated ID literal")
		}
		literal := data[start+1 : end]
		return parseLiteralString(literal), nil
	}

	if data[start] == '<' {
		end := start + 1
		for end < len(data) && data[end] != '>' {
			end++
		}
		if end >= len(data) {
			return nil, errors.New("unterminated ID hex string")
		}
		decoded, err := hex.DecodeString(string(data[start+1 : end]))
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}

	return nil, errors.New("unknown ID format")
}

func parseLiteralString(literal []byte) []byte {
	buf := make([]byte, 0, len(literal))
	for i := 0; i < len(literal); i++ {
		c := literal[i]
		if c == '\\' && i+1 < len(literal) {
			i++
			esc := literal[i]
			switch esc {
			case 'n':
				buf = append(buf, '\n')
			case 'r':
				buf = append(buf, '\r')
			case 't':
				buf = append(buf, '\t')
			case 'b':
				buf = append(buf, '\b')
			case 'f':
				buf = append(buf, '\f')
			case '\\', '(', ')':
				buf = append(buf, esc)
			default:
				if esc >= '0' && esc <= '7' {
					octal := esc
					count := 1
					for count < 3 && i+1 < len(literal) {
						if literal[i+1] >= '0' && literal[i+1] <= '7' {
							i++
							octal = octal*8 + (literal[i] - '0')
							count++
						} else {
							break
						}
					}
					buf = append(buf, octal)
				} else {
					buf = append(buf, esc)
				}
			}
		} else {
			buf = append(buf, c)
		}
	}
	return buf
}

type objRef struct {
	objNum int
	genNum int
}

func findEncryptReference(data []byte) (objRef, error) {
	idx := bytes.Index(data, []byte("/Encrypt"))
	if idx == -1 {
		return objRef{}, errors.New("/Encrypt entry not found")
	}

	snippet := data[idx:]
	var objNum, genNum int
	n, err := fmt.Sscanf(string(snippet), "/Encrypt %d %d R", &objNum, &genNum)
	if err != nil || n != 2 {
		return objRef{}, errors.New("failed to parse Encrypt reference")
	}

	return objRef{objNum: objNum, genNum: genNum}, nil
}

func findObject(data []byte, objNum, genNum int) ([]byte, error) {
	marker := fmt.Sprintf("%d %d obj", objNum, genNum)
	idx := bytes.Index(data, []byte(marker))
	if idx == -1 {
		return nil, fmt.Errorf("object %d %d not found", objNum, genNum)
	}
	start := idx + len(marker)
	end := bytes.Index(data[start:], []byte("endobj"))
	if end == -1 {
		return nil, fmt.Errorf("end of object %d %d not found", objNum, genNum)
	}
	return data[start : start+end], nil
}

func parseEncryptionObject(obj []byte) (encryptionDict, error) {
	dict := encryptionDict{}
	if d, ok := findIntEntry(obj, "/V"); ok {
		dict.V = d
	}
	if d, ok := findIntEntry(obj, "/R"); ok {
		dict.R = d
	}
	if d, ok := findIntEntry(obj, "/Length"); ok {
		dict.Length = d
	}
	if p, ok := findIntEntry(obj, "/P"); ok {
		dict.P = int32(p)
	}
	if v, ok := findByteEntry(obj, "/O"); ok {
		dict.O = v
	}
	if u, ok := findByteEntry(obj, "/U"); ok {
		dict.U = u
	}

	if dict.V == 0 || dict.R == 0 || len(dict.O) == 0 || len(dict.U) == 0 {
		return dict, fmt.Errorf("incomplete encryption dictionary: V=%d R=%d len(O)=%d len(U)=%d", dict.V, dict.R, len(dict.O), len(dict.U))
	}

	return dict, nil
}

func findIntEntry(data []byte, key string) (int, bool) {
	idx := bytes.Index(data, []byte(key))
	if idx == -1 {
		return 0, false
	}
	idx += len(key)
	for idx < len(data) && (data[idx] == ' ' || data[idx] == '\n' || data[idx] == '\r' || data[idx] == '\t') {
		idx++
	}
	start := idx
	if idx < len(data) && (data[idx] == '+' || data[idx] == '-') {
		idx++
	}
	for idx < len(data) && (data[idx] >= '0' && data[idx] <= '9') {
		idx++
	}
	if start == idx {
		return 0, false
	}
	val, err := strconv.Atoi(string(data[start:idx]))
	if err != nil {
		return 0, false
	}
	return val, true
}

func findHexEntry(data []byte, key string) ([]byte, bool) {
	idx := bytes.Index(data, []byte(key))
	if idx == -1 {
		return nil, false
	}
	idx += len(key)
	for idx < len(data) && (data[idx] == ' ' || data[idx] == '\n' || data[idx] == '\r' || data[idx] == '\t') {
		idx++
	}
	if idx >= len(data) || data[idx] != '<' {
		return nil, false
	}
	idx++
	start := idx
	for idx < len(data) && data[idx] != '>' {
		idx++
	}
	if idx >= len(data) {
		return nil, false
	}
	decoded, err := hex.DecodeString(string(data[start:idx]))
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func findByteEntry(data []byte, key string) ([]byte, bool) {
	if v, ok := findHexEntry(data, key); ok {
		return v, true
	}

	idx := bytes.Index(data, []byte(key))
	if idx == -1 {
		return nil, false
	}
	idx += len(key)
	for idx < len(data) && isSpace(data[idx]) {
		idx++
	}
	value, _, ok := readLiteralAt(data, idx)
	return value, ok
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func readLiteralAt(data []byte, start int) ([]byte, int, bool) {
	if start >= len(data) || data[start] != '(' {
		return nil, 0, false
	}

	buf := make([]byte, 0, 32)
	depth := 0
	for i := start + 1; i < len(data); i++ {
		c := data[i]
		if c == '\\' {
			if i+1 >= len(data) {
				return nil, 0, false
			}
			i++
			switch data[i] {
			case 'n':
				buf = append(buf, '\n')
			case 'r':
				buf = append(buf, '\r')
			case 't':
				buf = append(buf, '\t')
			case 'b':
				buf = append(buf, '\b')
			case 'f':
				buf = append(buf, '\f')
			case '\\', '(', ')':
				buf = append(buf, data[i])
			default:
				if data[i] >= '0' && data[i] <= '7' {
					octal := int(data[i] - '0')
					count := 1
					for count < 3 && i+1 < len(data) && data[i+1] >= '0' && data[i+1] <= '7' {
						i++
						octal = octal*8 + int(data[i]-'0')
						count++
					}
					buf = append(buf, byte(octal))
				} else {
					buf = append(buf, data[i])
				}
			}
		} else if c == '(' {
			depth++
			buf = append(buf, '(')
		} else if c == ')' {
			if depth == 0 {
				return buf, i, true
			}
			depth--
			buf = append(buf, ')')
		} else {
			buf = append(buf, c)
		}
	}

	return nil, 0, false
}

func expectFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("PDF path invalid: %w", err)
	}
	return nil
}
