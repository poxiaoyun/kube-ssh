package helper

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type scpOptions struct {
	source    bool
	sink      bool
	recursive bool
	preserve  bool
	target    string
}

func RunSCP(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	opts, err := parseSCPOptions(args)
	if err != nil {
		return err
	}
	in = contextReader{ctx: ctx, reader: in}
	out = contextWriter{ctx: ctx, writer: out}
	if opts.sink {
		return runSCPSink(opts, in, out)
	}
	return runSCPSource(opts, in, out)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w contextWriter) Write(p []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	default:
		return w.writer.Write(p)
	}
}

func parseSCPOptions(args []string) (scpOptions, error) {
	opts := scpOptions{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			for _, flag := range arg[1:] {
				switch flag {
				case 't':
					opts.sink = true
				case 'f':
					opts.source = true
				case 'r':
					opts.recursive = true
				case 'p':
					opts.preserve = true
				case 'd', 'v':
				default:
					return scpOptions{}, fmt.Errorf("unsupported scp flag -%c", flag)
				}
			}
			continue
		}
		opts.target = arg
	}
	if opts.target == "" {
		return scpOptions{}, fmt.Errorf("scp target is required")
	}
	if opts.sink == opts.source {
		return scpOptions{}, fmt.Errorf("scp requires exactly one of -t or -f")
	}
	return opts, nil
}

func runSCPSink(opts scpOptions, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	if err := writeSCPAck(out, nil); err != nil {
		return err
	}

	root := opts.target
	targetIsDir := isDir(root)
	dirs := []string{root}
	var pendingTimes *scpTimes
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'T':
			times, err := parseSCPTimes(line)
			if err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			pendingTimes = &times
			if err := writeSCPAck(out, nil); err != nil {
				return err
			}
		case 'D':
			mode, name, err := parseSCPEntry(line)
			if err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			name, err = cleanSCPName(name)
			if err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			parent := dirs[len(dirs)-1]
			dir := parent
			if targetIsDir || len(dirs) > 1 {
				dir = filepath.Join(parent, name)
			}
			if err := os.MkdirAll(dir, mode); err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			if pendingTimes != nil {
				_ = os.Chtimes(dir, pendingTimes.atime, pendingTimes.mtime)
				pendingTimes = nil
			}
			dirs = append(dirs, dir)
			if err := writeSCPAck(out, nil); err != nil {
				return err
			}
		case 'E':
			if len(dirs) > 1 {
				dirs = dirs[:len(dirs)-1]
			}
			if err := writeSCPAck(out, nil); err != nil {
				return err
			}
		case 'C':
			mode, size, name, err := parseSCPFile(line)
			if err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			name, err = cleanSCPName(name)
			if err != nil {
				_ = writeSCPAck(out, err)
				return err
			}
			dest := dirs[len(dirs)-1]
			if targetIsDir || len(dirs) > 1 {
				dest = filepath.Join(dest, name)
			}
			if err := receiveSCPFile(reader, out, dest, mode, size, pendingTimes); err != nil {
				return err
			}
			pendingTimes = nil
		default:
			err := fmt.Errorf("unsupported scp command %q", line)
			_ = writeSCPAck(out, err)
			return err
		}
	}
}

func runSCPSource(opts scpOptions, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	if err := readSCPResponse(reader); err != nil {
		return err
	}
	info, err := os.Stat(opts.target)
	if err != nil {
		_ = writeSCPAck(out, err)
		return err
	}
	if info.IsDir() {
		if !opts.recursive {
			err := fmt.Errorf("%s: not a regular file", opts.target)
			_ = writeSCPAck(out, err)
			return err
		}
		return sendSCPDir(reader, out, opts.target, info, opts.preserve)
	}
	return sendSCPFile(reader, out, opts.target, info, opts.preserve)
}

func receiveSCPFile(reader *bufio.Reader, out io.Writer, dest string, mode os.FileMode, size int64, times *scpTimes) error {
	if err := writeSCPAck(out, nil); err != nil {
		return err
	}
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		_ = writeSCPAck(out, err)
		return err
	}
	_, copyErr := io.CopyN(file, reader, size)
	closeErr := file.Close()
	if copyErr != nil {
		_ = writeSCPAck(out, copyErr)
		return copyErr
	}
	if closeErr != nil {
		_ = writeSCPAck(out, closeErr)
		return closeErr
	}
	status, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("invalid scp file terminator %d", status)
	}
	if times != nil {
		_ = os.Chtimes(dest, times.atime, times.mtime)
	}
	return writeSCPAck(out, nil)
}

func sendSCPFile(reader *bufio.Reader, out io.Writer, path string, info os.FileInfo, preserve bool) error {
	if preserve {
		if err := sendSCPTimes(reader, out, info); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(out, "C%04o %d %s\n", uint32(info.Mode().Perm()), info.Size(), filepath.Base(path)); err != nil {
		return err
	}
	if err := readSCPResponse(reader); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		_ = writeSCPAck(out, err)
		return err
	}
	if _, err := io.Copy(out, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := out.Write([]byte{0}); err != nil {
		return err
	}
	return readSCPResponse(reader)
}

func sendSCPDir(reader *bufio.Reader, out io.Writer, path string, info os.FileInfo, preserve bool) error {
	if preserve {
		if err := sendSCPTimes(reader, out, info); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(out, "D%04o 0 %s\n", uint32(info.Mode().Perm()), filepath.Base(path)); err != nil {
		return err
	}
	if err := readSCPResponse(reader); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		_ = writeSCPAck(out, err)
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		childInfo, err := entry.Info()
		if err != nil {
			_ = writeSCPAck(out, err)
			return err
		}
		if childInfo.IsDir() {
			if err := sendSCPDir(reader, out, child, childInfo, preserve); err != nil {
				return err
			}
			continue
		}
		if childInfo.Mode().IsRegular() {
			if err := sendSCPFile(reader, out, child, childInfo, preserve); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprint(out, "E\n"); err != nil {
		return err
	}
	return readSCPResponse(reader)
}

func sendSCPTimes(reader *bufio.Reader, out io.Writer, info os.FileInfo) error {
	mtime := info.ModTime().Unix()
	if _, err := fmt.Fprintf(out, "T%d 0 %d 0\n", mtime, mtime); err != nil {
		return err
	}
	return readSCPResponse(reader)
}

func writeSCPAck(out io.Writer, err error) error {
	if err == nil {
		_, writeErr := out.Write([]byte{0})
		return writeErr
	}
	_, writeErr := fmt.Fprintf(out, "\x01%s\n", err.Error())
	return writeErr
}

func readSCPResponse(reader *bufio.Reader) error {
	status, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch status {
	case 0:
		return nil
	case 1, 2:
		message, _ := reader.ReadString('\n')
		return fmt.Errorf("scp remote error: %s", strings.TrimSpace(message))
	default:
		return fmt.Errorf("unexpected scp response %d", status)
	}
}

func parseSCPFile(line string) (os.FileMode, int64, string, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || len(parts[0]) < 5 {
		return 0, 0, "", fmt.Errorf("invalid scp file header %q", line)
	}
	mode, err := strconv.ParseUint(parts[0][1:], 8, 32)
	if err != nil {
		return 0, 0, "", err
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, "", err
	}
	// Reject invalid protocol input before it reaches io.CopyN.
	if size < 0 {
		return 0, 0, "", fmt.Errorf("invalid scp file size %d", size)
	}
	return os.FileMode(mode), size, parts[2], nil
}

func parseSCPEntry(line string) (os.FileMode, string, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || len(parts[0]) < 5 {
		return 0, "", fmt.Errorf("invalid scp directory header %q", line)
	}
	mode, err := strconv.ParseUint(parts[0][1:], 8, 32)
	if err != nil {
		return 0, "", err
	}
	return os.FileMode(mode), parts[2], nil
}

type scpTimes struct {
	mtime time.Time
	atime time.Time
}

func parseSCPTimes(line string) (scpTimes, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return scpTimes{}, fmt.Errorf("invalid scp time header %q", line)
	}
	mtime, err := strconv.ParseInt(fields[0][1:], 10, 64)
	if err != nil {
		return scpTimes{}, err
	}
	atime, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return scpTimes{}, err
	}
	return scpTimes{
		mtime: time.Unix(mtime, 0),
		atime: time.Unix(atime, 0),
	}, nil
}

func cleanSCPName(name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, os.PathSeparator) {
		return "", fmt.Errorf("invalid scp filename %q", name)
	}
	return name, nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
