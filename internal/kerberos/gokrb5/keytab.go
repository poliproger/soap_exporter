package gokrb5

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// maxKVNO is the highest kvno the workaround covers (the 8-bit kvno field of a keytab entry).
const maxKVNO = 255

// readKeytab reads and parses the keytab at path. The FileInfo describes the file that was
// read, for change detection.
func readKeytab(path string) (*keytab.Keytab, os.FileInfo, error) {
	b, fi, err := readFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read keytab: %w", err)
	}
	kt, err := parseKeytab(b)
	if err != nil {
		return nil, nil, fmt.Errorf("keytab %s: %w", path, err)
	}
	return kt, fi, nil
}

// parseKeytab parses keytab file contents.
func parseKeytab(b []byte) (kt *keytab.Keytab, err error) {
	// Byte 0 is always 5, byte 1 is the format version (1 or 2).
	if len(b) < 2 || b[0] != 5 || (b[1] != 1 && b[1] != 2) {
		return nil, errors.New("not a keytab file")
	}
	kt = keytab.New()
	if len(b) == 2 {
		return kt, nil // a valid keytab without entries, which gokrb5 does not parse
	}
	// gokrb5's parse errors quote the raw keytab bytes, i.e. key material, so they are not
	// passed on. The parser is not hardened against hostile input either.
	defer func() {
		if recover() != nil {
			kt, err = nil, errors.New("malformed keytab")
		}
	}()
	if kt.Unmarshal(b) != nil {
		return nil, errors.New("malformed keytab")
	}
	return kt, nil
}

// entriesOf returns the indexes of the keytab entries of the principal name@realm, where comps
// are the components of name.
func entriesOf(kt *keytab.Keytab, comps []string, realm string) []int {
	var idx []int
	for i := range kt.Entries {
		p := &kt.Entries[i].Principal
		if p.Realm == realm && slices.Equal(p.Components, comps) {
			idx = append(idx, i)
		}
	}
	return idx
}

// principals lists the distinct principals in kt, for error messages.
func principals(kt *keytab.Keytab) []string {
	var names []string
	for i := range kt.Entries {
		p := &kt.Entries[i].Principal
		if n := strings.Join(p.Components, "/") + "@" + p.Realm; !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// applyKVNOWorkaround works around gokrb5 looking up the key for an AS-REP by its exact kvno
// (plan finding 8): if every entry at idx has kvno 0, it appends copies of them for kvno
// 1..255 to the in-memory keytab and reports true. The original entries keep kvno 0.
func applyKVNOWorkaround(kt *keytab.Keytab, idx []int) bool {
	if len(idx) == 0 {
		return false
	}
	for _, i := range idx {
		if kt.Entries[i].KVNO != 0 {
			return false
		}
	}
	kt.Entries = slices.Grow(kt.Entries, len(idx)*maxKVNO)
	for _, i := range idx {
		for kvno := 1; kvno <= maxKVNO; kvno++ {
			e := kt.Entries[i]
			e.KVNO, e.KVNO8 = uint32(kvno), uint8(kvno)
			kt.Entries = append(kt.Entries, e)
		}
	}
	return true
}

// readFile reads the regular file at path; the FileInfo describes the file read. The type is
// checked before the file is opened, because opening a FIFO blocks until a writer appears.
func readFile(path string) ([]byte, os.FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if err := checkRegular(path, fi); err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	// The path may have been replaced in between.
	if fi, err = f.Stat(); err != nil {
		return nil, nil, err
	}
	if err := checkRegular(path, fi); err != nil {
		return nil, nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return b, fi, nil
}

func checkRegular(path string, fi os.FileInfo) error {
	switch {
	case fi.Mode().IsRegular():
		return nil
	case fi.IsDir():
		// E.g. a bind mount whose source did not exist, which Docker creates as a directory.
		return fmt.Errorf("%s is a directory, not a regular file", path)
	default:
		return fmt.Errorf("%s is not a regular file", path)
	}
}

// changed reports whether the keytab file described by cur differs from the one read as old:
// replaced (e.g. an atomic rename or a Kubernetes secret update), resized or modified.
func changed(old, cur os.FileInfo) bool {
	return !os.SameFile(old, cur) || cur.Size() != old.Size() || !cur.ModTime().Equal(old.ModTime())
}
