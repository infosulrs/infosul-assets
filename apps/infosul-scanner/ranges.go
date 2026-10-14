package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Limite de alvos por verificação (equivale a uma /16).
const maxTargets = 65536

// Target é um endereço a verificar. Host guarda o nome digitado quando o
// alvo veio de um hostname.
type Target struct {
	IP   net.IP
	Host string
}

// ParseRanges interpreta a sintaxe aceita na caixa de faixa:
//
//	192.168.0.1-100, 192.168.0.200, 10.0.0.0/24, 10.0.0.1-10.0.1.5, servidor01
//
// Separadores aceitos: vírgula, ponto e vírgula, espaço e quebra de linha.
func ParseRanges(s string) ([]Target, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("nenhum endereço IP informado")
	}
	seen := map[uint32]bool{}
	var out []Target
	add := func(u uint32, host string) error {
		if seen[u] {
			return nil
		}
		if len(out) >= maxTargets {
			return fmt.Errorf("faixa grande demais (limite de %d endereços)", maxTargets)
		}
		seen[u] = true
		out = append(out, Target{IP: u32ToIP(u), Host: host})
		return nil
	}
	for _, f := range fields {
		start, end, host, err := parseOne(f)
		if err != nil {
			return nil, err
		}
		if end < start {
			start, end = end, start
		}
		if uint64(end-start) >= maxTargets {
			return nil, fmt.Errorf("faixa grande demais: %s", f)
		}
		for u := uint64(start); u <= uint64(end); u++ {
			if err := add(uint32(u), host); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func parseOne(f string) (start, end uint32, host string, err error) {
	if strings.Contains(f, "/") {
		_, n, e := net.ParseCIDR(f)
		if e != nil || n.IP.To4() == nil {
			return 0, 0, "", fmt.Errorf("faixa inválida: %s", f)
		}
		ones, _ := n.Mask.Size()
		base := ipToU32(n.IP)
		size := uint32(1) << (32 - ones)
		if ones <= 30 {
			// Ignora endereço de rede e de broadcast.
			return base + 1, base + size - 2, "", nil
		}
		return base, base + size - 1, "", nil
	}
	if i := strings.Index(f, "-"); i > 0 {
		left, right := f[:i], f[i+1:]
		a := net.ParseIP(left).To4()
		if a == nil {
			return 0, 0, "", fmt.Errorf("faixa inválida: %s", f)
		}
		if b := net.ParseIP(right).To4(); b != nil {
			return ipToU32(a), ipToU32(b), "", nil
		}
		// Forma curta: 192.168.0.1-100 (último octeto).
		n, e := strconv.Atoi(right)
		if e != nil || n < 0 || n > 255 {
			return 0, 0, "", fmt.Errorf("faixa inválida: %s", f)
		}
		b := make(net.IP, 4)
		copy(b, a)
		b[3] = byte(n)
		return ipToU32(a), ipToU32(b), "", nil
	}
	if ip := net.ParseIP(f).To4(); ip != nil {
		u := ipToU32(ip)
		return u, u, "", nil
	}
	addrs, e := net.LookupIP(f)
	if e == nil {
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				u := ipToU32(v4)
				return u, u, f, nil
			}
		}
	}
	return 0, 0, "", fmt.Errorf("não foi possível resolver o nome de host: %s", f)
}

func ipToU32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func u32ToIP(u uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, u)
	return ip
}

// LocalNetwork descreve um adaptador IPv4 ativo deste computador.
type LocalNetwork struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	CIDR      string `json:"cidr"`
	Range     string `json:"range"`
	ClassC    string `json:"classC"`
	MAC       string `json:"mac"`
}

// LocalNetworks lista os adaptadores com IPv4, ignorando loopback e APIPA.
func LocalNetworks() []LocalNetwork {
	var out []LocalNetwork
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || n.IP.IsLinkLocalUnicast() {
				continue
			}
			ip := n.IP.To4()
			ones, _ := n.Mask.Size()
			// Sub-redes maiores que /22 viram a /24 do próprio IP, como o original faz
			// com "Sub-rede deste computador" em redes muito grandes.
			eff := ones
			if eff < 22 {
				eff = 24
			}
			mask := net.CIDRMask(eff, 32)
			netIP := ip.Mask(mask)
			base := ipToU32(netIP)
			size := uint32(1) << (32 - eff)
			first, last := base+1, base+size-2
			if eff > 30 {
				first, last = base, base+size-1
			}
			c := make(net.IP, 4)
			copy(c, ip)
			out = append(out, LocalNetwork{
				Interface: ifc.Name,
				IP:        ip.String(),
				CIDR:      fmt.Sprintf("%s/%d", ip.Mask(n.Mask), ones),
				Range:     u32ToIP(first).String() + "-" + u32ToIP(last).String(),
				ClassC:    fmt.Sprintf("%d.%d.%d.1-254", c[0], c[1], c[2]),
				MAC:       strings.ToUpper(ifc.HardwareAddr.String()),
			})
		}
	}
	return out
}
