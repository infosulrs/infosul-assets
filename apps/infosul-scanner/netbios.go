package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// NetBIOSInfo é o resultado de uma consulta NBSTAT (RFC 1002, 4.2.17).
type NetBIOSInfo struct {
	Name  string
	Group string
	User  string
	MAC   string
}

// nbstatRequest monta a consulta de status para o nome curinga "*".
func nbstatRequest(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	b = append(b, 0x20)
	name := append([]byte{'*'}, make([]byte, 15)...)
	for _, c := range name {
		b = append(b, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	b = append(b, 0x00, 0x00, 0x21, 0x00, 0x01)
	return b
}

func parseNBStat(p []byte, id uint16) (*NetBIOSInfo, error) {
	if len(p) < 12 || binary.BigEndian.Uint16(p) != id {
		return nil, errors.New("resposta NetBIOS inválida")
	}
	if binary.BigEndian.Uint16(p[6:]) == 0 {
		return nil, errors.New("resposta NetBIOS sem registros")
	}
	i := 12
	for i < len(p) {
		l := int(p[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 == 0xC0 {
			i += 2
			break
		}
		i += 1 + l
	}
	// tipo(2) classe(2) ttl(4) rdlength(2)
	if i+10 > len(p) || binary.BigEndian.Uint16(p[i:]) != 0x21 {
		return nil, errors.New("resposta NetBIOS sem NBSTAT")
	}
	i += 10
	if i >= len(p) {
		return nil, errors.New("resposta NetBIOS truncada")
	}
	n := int(p[i])
	i++
	info := &NetBIOSInfo{}
	for k := 0; k < n && i+18 <= len(p); k++ {
		raw := strings.TrimRight(string(p[i:i+15]), " \x00")
		suffix := p[i+15]
		group := binary.BigEndian.Uint16(p[i+16:])&0x8000 != 0
		i += 18
		switch {
		case suffix == 0x00 && !group && info.Name == "":
			info.Name = raw
		case suffix == 0x00 && group && info.Group == "":
			info.Group = raw
		case suffix == 0x03 && !group && info.User == "" && !strings.EqualFold(raw, info.Name):
			info.User = raw
		}
	}
	if i+6 <= len(p) {
		m := net.HardwareAddr(p[i : i+6])
		if m.String() != "00:00:00:00:00:00" {
			info.MAC = strings.ToUpper(m.String())
		}
	}
	if info.Name == "" {
		return nil, errors.New("NetBIOS sem nome de computador")
	}
	return info, nil
}

// QueryNetBIOS envia a consulta NBSTAT para ip:137 e aguarda a resposta.
func QueryNetBIOS(ip net.IP, timeout time.Duration, attempts int) (*NetBIOSInfo, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: ip, Port: 137}
	id := uint16(rand.Intn(0xffff))
	req := nbstatRequest(id)
	buf := make([]byte, 1500)
	if attempts < 1 {
		attempts = 1
	}
	for a := 0; a < attempts; a++ {
		if _, err := conn.WriteToUDP(req, dst); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if !from.IP.Equal(ip) {
				continue
			}
			return parseNBStat(buf[:n], id)
		}
	}
	return nil, fmt.Errorf("sem resposta NetBIOS de %s", ip)
}
