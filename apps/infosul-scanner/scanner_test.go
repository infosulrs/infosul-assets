package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestParseRanges(t *testing.T) {
	cases := []struct {
		in    string
		n     int
		first string
		last  string
	}{
		{"192.168.0.1-100", 100, "192.168.0.1", "192.168.0.100"},
		{"192.168.0.1-100, 192.168.0.200", 101, "192.168.0.1", "192.168.0.200"},
		{"10.0.0.0/24", 254, "10.0.0.1", "10.0.0.254"},
		{"10.0.0.250-10.0.1.5", 12, "10.0.0.250", "10.0.1.5"},
		{"10.0.0.5", 1, "10.0.0.5", "10.0.0.5"},
		{"10.0.0.1-5\n10.0.0.3;10.0.0.9", 6, "10.0.0.1", "10.0.0.9"},
	}
	for _, c := range cases {
		got, err := ParseRanges(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if len(got) != c.n || got[0].IP.String() != c.first || got[len(got)-1].IP.String() != c.last {
			t.Errorf("%q: n=%d first=%s last=%s", c.in, len(got), got[0].IP, got[len(got)-1].IP)
		}
	}
	for _, bad := range []string{"", "192.168.0.1-300", "10.0.0.0/8", "999.1.1.1"} {
		if _, err := ParseRanges(bad); err == nil {
			t.Errorf("%q deveria falhar", bad)
		}
	}
}

func TestVendor(t *testing.T) {
	if v := Vendor("00:00:0C:12:34:56"); !strings.Contains(strings.ToLower(v), "cisco") {
		t.Fatalf("OUI Cisco não encontrado: %q", v)
	}
	if v := Vendor("zz"); v != "" {
		t.Fatalf("esperado vazio, veio %q", v)
	}
}

// Monta uma resposta NBSTAT sintética, como a de um Windows em grupo de trabalho.
func fakeNBStat(id uint16) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, id)
	b.Write([]byte{0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0})
	b.Write(nbstatRequest(id)[12:46]) // nome codificado
	b.Write([]byte{0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0})
	entry := func(name string, suffix byte, group bool) []byte {
		e := []byte(name + strings.Repeat(" ", 15-len(name)))
		e = append(e, suffix)
		if group {
			return append(e, 0x84, 0x00)
		}
		return append(e, 0x04, 0x00)
	}
	var rd bytes.Buffer
	rd.WriteByte(4)
	rd.Write(entry("RECEPCAO-01", 0x00, false))
	rd.Write(entry("WORKGROUP", 0x00, true))
	rd.Write(entry("RECEPCAO-01", 0x20, false))
	rd.Write(entry("CARLOS", 0x03, false))
	rd.Write([]byte{0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC})
	binary.Write(&b, binary.BigEndian, uint16(rd.Len()))
	b.Write(rd.Bytes())
	return b.Bytes()
}

func TestParseNBStat(t *testing.T) {
	info, err := parseNBStat(fakeNBStat(0x1234), 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "RECEPCAO-01" || info.Group != "WORKGROUP" || info.User != "CARLOS" || info.MAC != "00:1B:21:AA:BB:CC" {
		t.Fatalf("%+v", info)
	}
	if _, err := parseNBStat(fakeNBStat(1), 2); err == nil {
		t.Fatal("ID divergente deveria falhar")
	}
}

func TestNBStatRequest(t *testing.T) {
	r := nbstatRequest(7)
	if len(r) != 50 || r[12] != 0x20 || string(r[13:15]) != "CK" || r[47] != 0x21 {
		t.Fatalf("pacote inválido: % x", r)
	}
}

func TestQueryNetBIOSLoopback(t *testing.T) {
	// Servidor NBSTAT falso em loopback, numa porta qualquer, para exercitar parse em UDP real.
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 100)
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil || n < 2 {
			return
		}
		pc.WriteToUDP(fakeNBStat(binary.BigEndian.Uint16(buf)), from)
	}()
	conn, _ := net.ListenUDP("udp4", nil)
	defer conn.Close()
	conn.WriteToUDP(nbstatRequest(99), pc.LocalAddr().(*net.UDPAddr))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := parseNBStat(buf[:n], 99); err != nil || info.Name != "RECEPCAO-01" {
		t.Fatalf("%v %+v", err, info)
	}
}
