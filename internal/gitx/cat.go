package gitx

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Blob is one resolved file version.
type Blob struct {
	OID  string
	Size int64
	Data []byte
}

// CatBlobs streams the contents of blob object IDs to fn.
//
// This is the preferred reader. It differs from CatFiles in the two ways that
// matter against a hostile repository:
//
//   - It is addressed by object ID, not by "<rev>:<path>". A path is attacker
//     chosen and git permits a newline in one; an object ID is hex and can
//     never alter the line protocol.
//   - Blobs are handed to fn one at a time and not retained, and a blob larger
//     than maxBytes (when maxBytes > 0) is skipped without ever being allocated.
//     Reading every file of a revision into one map, or allocating a
//     multi-gigabyte blob before checking its size, is how a crafted repository
//     exhausts memory.
//
// fn receives the index into oids. IDs that do not resolve, are not blobs or
// are oversized are not reported. A non-nil error from fn stops the read and is
// returned.
func CatBlobs(ctx context.Context, dir string, oids []string, maxBytes int64, fn func(i int, b Blob) error) error {
	keys := make([]string, len(oids))
	for i, o := range oids {
		if isObjectID(o) {
			keys[i] = o
		}
	}
	return catBatch(ctx, dir, keys, maxBytes, fn)
}

// CatFiles resolves "<sha>:<path>" specs to their contents.
//
// One `git cat-file --batch` process handles the whole batch, which matters on
// a blobless clone: the repository is a promisor, so this is the point where
// git lazily fetches the missing blobs, and batching keeps that to a single
// negotiation rather than one per file.
//
// Specs that do not resolve -- a path deleted by the commit, or absent from
// that tree -- are simply omitted from the result rather than treated as
// errors, since a hunt routinely asks about both. A spec containing a line
// break is omitted too: git would read it as several requests. Prefer CatBlobs
// for scanning, which also bounds memory.
func CatFiles(ctx context.Context, dir string, specs []string) (map[string]Blob, error) {
	out := make(map[string]Blob, len(specs))
	err := catBatch(ctx, dir, specs, 0, func(i int, b Blob) error {
		out[specs[i]] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// isObjectID reports whether s looks like a full SHA-1 or SHA-256 object name.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// catBatch runs one `git cat-file --batch`, writing keys[i] as a request and
// calling fn for each blob that comes back. Empty keys, and keys that contain a
// line break, are never sent: git answers one response per line it reads, and
// responses are matched to requests by position, so a key that spans lines would
// shift every later response onto the wrong key.
func catBatch(ctx context.Context, dir string, keys []string, maxBytes int64, fn func(i int, b Blob) error) error {
	sent := make([]int, 0, len(keys))
	for i, k := range keys {
		if k == "" || strings.ContainsAny(k, "\r\n\x00") {
			continue
		}
		sent = append(sent, i)
	}
	if len(sent) == 0 {
		return nil
	}

	full := append(append([]string{}, safeConfig...), "cat-file", "--batch")
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=true",
		"GIT_CONFIG_NOSYSTEM=1",
		"LC_ALL=C",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	writeErr := make(chan error, 1)
	go func() {
		defer stdin.Close()
		w := bufio.NewWriter(stdin)
		for _, i := range sent {
			if _, err := fmt.Fprintln(w, keys[i]); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- w.Flush()
	}()

	abort := func(err error) error {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}

	// Responses arrive in request order, so the key is recovered positionally.
	r := bufio.NewReaderSize(stdout, 64<<10)
	for n := 0; n < len(sent); n++ {
		if err := ctx.Err(); err != nil {
			return abort(err)
		}
		header, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return abort(fmt.Errorf("cat-file: reading header: %w", err))
		}
		header = strings.TrimRight(header, "\n")

		// "<key> missing" or "<key> ambiguous": nothing follows. Checked on the
		// suffix because a key (a "rev:path" spec) may itself contain spaces.
		if strings.HasSuffix(header, " missing") || strings.HasSuffix(header, " ambiguous") {
			continue
		}
		fields := strings.Fields(header)
		if len(fields) < 3 {
			continue
		}
		oid, objType, sizeStr := fields[0], fields[1], fields[2]
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || size < 0 {
			continue
		}

		// Not a blob (a directory or submodule pointer), or too big to be worth
		// holding: consume the payload and its trailing newline without keeping it.
		if objType != "blob" || (maxBytes > 0 && size > maxBytes) {
			if _, err := io.CopyN(io.Discard, r, size+1); err != nil && err != io.EOF {
				return abort(fmt.Errorf("cat-file: skipping %s: %w", oid, err))
			}
			continue
		}

		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return abort(fmt.Errorf("cat-file: reading %s: %w", oid, err))
		}
		// Each payload is followed by a trailing newline git adds itself.
		if _, err := r.Discard(1); err != nil && err != io.EOF {
			return abort(err)
		}
		if err := fn(sent[n], Blob{OID: oid, Size: size, Data: data}); err != nil {
			return abort(err)
		}
	}

	// Drain anything unread so the child never blocks on a full pipe.
	io.Copy(io.Discard, r)

	if err := <-writeErr; err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("cat-file: writing requests: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("cat-file: %s", truncate(strings.TrimSpace(stderr.String()), 300))
	}
	return nil
}

// IsBinary reports whether content looks binary, using the same NUL-byte
// heuristic git itself applies, so the caller can avoid dumping it to a
// terminal.
func IsBinary(data []byte) bool {
	if len(data) > 8000 {
		data = data[:8000]
	}
	return bytes.IndexByte(data, 0) >= 0
}
