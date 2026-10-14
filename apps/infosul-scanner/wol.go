package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"syscall"
)

// WakeOnLAN envia o pacote mágico (6x 0xFF + 16x MAC) para o broadcast geral
// e para o broadcast da /24 do host, nas portas 7 e 9.
func WakeOnLAN(mac, ip string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("endereço MAC incorreto")
	}
	pkt := append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(hw, 16)...)
	dsts := []string{"255.255.255.255"}
	if v4 := net.ParseIP(ip).To4(); v4 != nil {
		dsts = append(dsts, fmt.Sprintf("%d.%d.%d.255", v4[0], v4[1], v4[2]))
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(setBroadcast)
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return err
	}
	defer pc.Close()
	sent := 0
	for _, d := range dsts {
		for _, port := range []int{9, 7} {
			if _, err := pc.WriteTo(pkt, &net.UDPAddr{IP: net.ParseIP(d), Port: port}); err == nil {
				sent++
			}
		}
	}
	if sent == 0 {
		return fmt.Errorf("não foi possível enviar o pacote mágico")
	}
	return nil
}
