// gore — reverse-engineer STRIPPED Go binaries via the pclntab (debug/gosym).
// BN/Ghidra-INDEPENDENT: parses .gopclntab directly, so it is instant on huge (40MB+) Go
// binaries where symdiff/ghidriff/BinDiff fail (Go strips the ELF symtab; names live in pclntab).
package main

import (
	"crypto/md5"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
)

func openTab(path string) (*gosym.Table, []byte, uint64) {
	f, err := elf.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	pcln := f.Section(".gopclntab")
	txt := f.Section(".text")
	if pcln == nil || txt == nil {
		fmt.Fprintln(os.Stderr, "not a Go binary (.gopclntab/.text missing)")
		os.Exit(1)
	}
	pd, _ := pcln.Data()
	td, _ := txt.Data()
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(pd, txt.Addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gosym:", err)
		os.Exit(1)
	}
	return tab, td, txt.Addr
}

func funcsMap(path string) (map[string]string, int) {
	tab, td, base := openTab(path)
	out := map[string]string{}
	for _, fn := range tab.Funcs {
		s, e := fn.Entry-base, fn.End-base
		if e <= s || e > uint64(len(td)) {
			continue
		}
		h := md5.Sum(td[s:e])
		out[fn.Name] = fmt.Sprintf("%x", h)
	}
	return out, len(tab.Funcs)
}

func cmdDiff(a, b string) {
	fa, _ := funcsMap(a)
	fb, _ := funcsMap(b)
	var ch, ad, rm []string
	for n, ha := range fa {
		if hb, ok := fb[n]; !ok {
			rm = append(rm, n)
		} else if ha != hb {
			ch = append(ch, n)
		}
	}
	for n := range fb {
		if _, ok := fa[n]; !ok {
			ad = append(ad, n)
		}
	}
	sort.Strings(ch)
	sort.Strings(ad)
	sort.Strings(rm)
	fmt.Printf("# a=%d b=%d CHANGED=%d added=%d removed=%d\n", len(fa), len(fb), len(ch), len(ad), len(rm))
	for _, n := range ch {
		fmt.Println("CHANGED", n)
	}
	for _, n := range ad {
		fmt.Println("ADDED", n)
	}
	for _, n := range rm {
		fmt.Println("REMOVED", n)
	}
}

func cmdList(path, pat string) {
	tab, _, _ := openTab(path)
	re := regexp.MustCompile(pat)
	for _, fn := range tab.Funcs {
		if re.MatchString(fn.Name) {
			fmt.Printf("%#x  %d  %s\n", fn.Entry, fn.End-fn.Entry, fn.Name)
		}
	}
}

func cmdXref(path, addrS string) {
	tab, td, base := openTab(path)
	target, err := strconv.ParseUint(addrS, 0, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad addr:", err)
		os.Exit(2)
	}
	seen := map[string]bool{}
	for _, fn := range tab.Funcs {
		s, e := fn.Entry-base, fn.End-base
		if e <= s || e > uint64(len(td)) {
			continue
		}
		b := td[s:e]
		for i := 0; i+5 <= len(b); i++ {
			if b[i] == 0xe8 || b[i] == 0xe9 { // call/jmp rel32
				rel := int32(binary.LittleEndian.Uint32(b[i+1 : i+5]))
				tgt := uint64(int64(fn.Entry+uint64(i)) + 5 + int64(rel))
				if tgt == target && !seen[fn.Name] {
					seen[fn.Name] = true
					fmt.Printf("%#x  %s\n", fn.Entry, fn.Name)
				}
			}
		}
	}
}

func cmdAddr(path, addrS string) {
	tab, _, _ := openTab(path)
	a, err := strconv.ParseUint(addrS, 0, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad addr:", err)
		os.Exit(2)
	}
	if fn := tab.PCToFunc(a); fn != nil {
		fmt.Printf("%#x  %s\n", a, fn.Name)
	} else {
		fmt.Printf("%#x  ?\n", a)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `gore — RE stripped Go binaries via pclntab (BN/Ghidra-independent)
  gore diff <old> <new>         changed/added/removed funcs by name+bytes (Go patch-diff)
  gore list <bin> <name-regex>  functions matching regex -> "addr size name"
  gore xref <bin> <hexaddr>     functions that CALL the target address
  gore addr <bin> <hexaddr>     resolve address -> function name`)
	os.Exit(2)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}
	switch os.Args[1] {
	case "diff":
		cmdDiff(os.Args[2], os.Args[3])
	case "list":
		cmdList(os.Args[2], os.Args[3])
	case "xref":
		cmdXref(os.Args[2], os.Args[3])
	case "addr":
		cmdAddr(os.Args[2], os.Args[3])
	default:
		usage()
	}
}
