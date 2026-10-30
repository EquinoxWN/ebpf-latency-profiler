// Package tpformat parses tracefs tracepoint format files and checks expected field layouts.
package tpformat

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxFormatBytes bounds a format file; real ones are a few kilobytes.
const maxFormatBytes = 1 << 20

// ErrFormat reports a format file that cannot be parsed.
var ErrFormat = errors.New("tpformat: malformed format file")

// Field is one record field as the kernel describes it.
type Field struct {
	Name   string
	Decl   string
	Offset int
	Size   int
	Signed bool
}

// Format is a parsed tracepoint format file.
type Format struct {
	Name   string
	ID     int
	Fields []Field
}

// Expect is a field layout the BPF program relies on.
type Expect struct {
	Name   string
	Offset int
	Size   int
}

// Parse reads a format file such as /sys/kernel/tracing/events/sched/sched_switch/format.
func Parse(r io.Reader) (*Format, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxFormatBytes))
	sc.Buffer(make([]byte, 0, 4096), maxFormatBytes)
	f := &Format{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "name:"):
			f.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		case strings.HasPrefix(line, "ID:"):
			id, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "ID:")))
			if err != nil {
				return nil, fmt.Errorf("%w: ID line %q", ErrFormat, line)
			}
			f.ID = id
		case strings.HasPrefix(line, "field:"):
			fld, err := parseField(line)
			if err != nil {
				return nil, err
			}
			f.Fields = append(f.Fields, fld)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if f.Name == "" || len(f.Fields) == 0 {
		return nil, fmt.Errorf("%w: no name or no fields", ErrFormat)
	}
	return f, nil
}

// parseField parses "field:<decl>;\toffset:N;\tsize:N;\tsigned:N;".
func parseField(line string) (Field, error) {
	parts := strings.Split(line, ";")
	var fld Field
	var haveOff, haveSize bool
	for _, p := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(p), ":")
		if !ok {
			continue
		}
		switch k {
		case "field":
			fld.Decl = strings.TrimSpace(v)
			fld.Name = fieldName(fld.Decl)
		case "offset", "size", "signed":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 {
				return Field{}, fmt.Errorf("%w: %s in %q", ErrFormat, k, line)
			}
			switch k {
			case "offset":
				fld.Offset, haveOff = n, true
			case "size":
				fld.Size, haveSize = n, true
			default:
				fld.Signed = n == 1
			}
		}
	}
	if fld.Name == "" || !haveOff || !haveSize {
		return Field{}, fmt.Errorf("%w: field line %q", ErrFormat, line)
	}
	return fld, nil
}

// fieldName extracts the identifier from a C declaration like "char prev_comm[16]".
func fieldName(decl string) string {
	if i := strings.IndexByte(decl, '['); i >= 0 && strings.HasSuffix(decl, "]") && !strings.HasSuffix(decl, "[]") {
		decl = decl[:i]
	}
	fields := strings.Fields(decl)
	if len(fields) == 0 {
		return ""
	}
	name := fields[len(fields)-1]
	name = strings.TrimLeft(name, "*")
	for _, r := range name {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return name
}

// Field returns the named field.
func (f *Format) Field(name string) (Field, bool) {
	for _, fld := range f.Fields {
		if fld.Name == name {
			return fld, true
		}
	}
	return Field{}, false
}

// Check returns one message per expected field that is missing or laid out differently.
func (f *Format) Check(want []Expect) []string {
	var problems []string
	for _, w := range want {
		got, ok := f.Field(w.Name)
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: field %s missing", f.Name, w.Name))
		case got.Offset != w.Offset || got.Size != w.Size:
			problems = append(problems, fmt.Sprintf("%s: field %s at offset %d size %d, program expects offset %d size %d",
				f.Name, w.Name, got.Offset, got.Size, w.Offset, w.Size))
		}
	}
	return problems
}
