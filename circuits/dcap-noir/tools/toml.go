package main

import (
	"fmt"
	"strings"
)

// tomlWriter emits a Noir Prover.toml. Top-level keys are buffered and flushed
// before any [section], because TOML requires bare keys to precede table
// headers. Within a section, keys are written in call order.
type tomlWriter struct {
	top  strings.Builder // top-level (non-section) lines
	rest strings.Builder // section lines (sections + their keys)
	cur  *strings.Builder // current target
}

func (w *tomlWriter) target() *strings.Builder {
	if w.cur == nil {
		w.cur = &w.top
	}
	return w.cur
}

// section starts a new [name] table; subsequent keys belong to it.
func (w *tomlWriter) section(name string) {
	w.rest.WriteString("\n[" + name + "]\n")
	w.cur = &w.rest
}

// num writes key = "v".
func (w *tomlWriter) num(key string, v int) {
	fmt.Fprintf(w.target(), "%s = \"%d\"\n", key, v)
}

// numArr writes key = ["a", "b", ...].
func (w *tomlWriter) numArr(key string, v []int) {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("\"%d\"", x)
	}
	fmt.Fprintf(w.target(), "%s = [%s]\n", key, strings.Join(parts, ", "))
}

// numGrid writes key = [[".."], ["..."], ...].
func (w *tomlWriter) numGrid(key string, v [][]int) {
	rows := make([]string, len(v))
	for i, row := range v {
		parts := make([]string, len(row))
		for j, x := range row {
			parts[j] = fmt.Sprintf("\"%d\"", x)
		}
		rows[i] = "[" + strings.Join(parts, ", ") + "]"
	}
	fmt.Fprintf(w.target(), "%s = [%s]\n", key, strings.Join(rows, ", "))
}

// bytes writes key = ["b0", "b1", ...] for a byte slice (top-level field).
func (w *tomlWriter) bytes(key string, b []byte) {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("\"%d\"", x)
	}
	fmt.Fprintf(w.target(), "%s = [%s]\n", key, strings.Join(parts, ", "))
}

// bytesField is bytes() for a key inside the current section.
func (w *tomlWriter) bytesField(key string, b []byte) {
	w.bytes(key, b)
}

func (w *tomlWriter) String() string {
	return w.top.String() + w.rest.String()
}
