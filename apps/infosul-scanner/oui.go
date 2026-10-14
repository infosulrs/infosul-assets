package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// Base pública IEEE (MA-L), gerada a partir de standards-oui.ieee.org/oui/oui.csv.
//
//go:embed data/oui.txt.gz
var ouiGz []byte

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func loadOUI() {
	ouiMap = make(map[string]string, 40000)
	zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "\t"); ok {
			ouiMap[k] = v
		}
	}
}

// Vendor devolve o fabricante para um MAC no formato AA:BB:CC:DD:EE:FF.
func Vendor(mac string) string {
	ouiOnce.Do(loadOUI)
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(h) < 6 {
		return ""
	}
	return ouiMap[h[:6]]
}
