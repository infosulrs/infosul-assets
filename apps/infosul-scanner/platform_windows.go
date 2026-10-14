//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Mesmas APIs Win32 que o REA encontrou na tabela de importação do original:
// IPHLPAPI (IcmpSendEcho, SendARP) e NETAPI32 (NetShareEnum).
var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose   = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend    = iphlpapi.NewProc("IcmpSendEcho")
	procSendARP     = iphlpapi.NewProc("SendARP")
	netapi32        = syscall.NewLazyDLL("netapi32.dll")
	procNetShareEnm = netapi32.NewProc("NetShareEnum")
	procNetApiFree  = netapi32.NewProc("NetApiBufferFree")
)

func inAddr(ip net.IP) uintptr {
	// IPAddr é um in_addr: os bytes ficam na ordem de rede na memória.
	return uintptr(binary.LittleEndian.Uint32(ip.To4()))
}

func Ping(ip net.IP, timeout time.Duration) (time.Duration, bool) {
	h, _, _ := procIcmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, false
	}
	defer procIcmpClose.Call(h)
	data := []byte("INFOSUL-SCANNER-PING-32-BYTES!!!")
	reply := make([]byte, 256)
	start := time.Now()
	n, _, _ := procIcmpSend.Call(h, inAddr(ip),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(timeout/time.Millisecond))
	if n == 0 {
		return 0, false
	}
	// ICMP_ECHO_REPLY: Address(4) Status(4) RoundTripTime(4)...
	addr := net.IP(reply[0:4])
	status := binary.LittleEndian.Uint32(reply[4:8])
	rtt := binary.LittleEndian.Uint32(reply[8:12])
	if status != 0 || !addr.Equal(ip.To4()) {
		return 0, false
	}
	if rtt == 0 {
		return time.Since(start), true
	}
	return time.Duration(rtt) * time.Millisecond, true
}

func ARPLookup(ip net.IP) string {
	var mac [8]byte
	l := uint32(len(mac))
	r, _, _ := procSendARP.Call(inAddr(ip), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&l)))
	if r != 0 || l < 6 {
		return ""
	}
	return strings.ToUpper(net.HardwareAddr(mac[:6]).String())
}

type shareInfo1 struct {
	Netname *uint16
	Type    uint32
	Remark  *uint16
}

func utf16Ptr(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for ptr := unsafe.Pointer(p); ; ptr = unsafe.Add(ptr, 2) {
		c := *(*uint16)(ptr)
		if c == 0 {
			break
		}
		s = append(s, c)
	}
	return syscall.UTF16ToString(s)
}

func ListShares(ip string, timeout time.Duration) []Share {
	ch := make(chan []Share, 1)
	go func() {
		server, _ := syscall.UTF16PtrFromString(`\\` + ip)
		var buf unsafe.Pointer
		var read, total, resume uint32
		r, _, _ := procNetShareEnm.Call(uintptr(unsafe.Pointer(server)), 1,
			uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != 0 || buf == nil {
			ch <- nil
			return
		}
		defer procNetApiFree.Call(uintptr(buf))
		items := unsafe.Slice((*shareInfo1)(buf), read)
		var out []Share
		for _, it := range items {
			t := "pasta"
			switch {
			case it.Type&0x80000000 != 0:
				t = "admin"
			case it.Type&0xff == 1:
				t = "impressora"
			case it.Type&0xff != 0:
				continue
			}
			out = append(out, Share{Name: utf16Ptr(it.Netname), Type: t, Comment: utf16Ptr(it.Remark)})
		}
		ch <- out
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(timeout):
		return nil
	}
}

func dataDir() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base, _ = os.UserConfigDir()
	}
	return filepath.Join(base, "INFOSUL Scanner")
}

// startDetached abre um programa sem prender o servidor.
func startDetached(name string, args ...string) error {
	return exec.Command(name, args...).Start()
}

// openTerminal abre uma janela do prompt com o comando informado.
func openTerminal(title string, cmd ...string) error {
	args := append([]string{"/c", "start", title, "cmd", "/k"}, cmd...)
	return exec.Command("cmd", args...).Start()
}

func openURL(u string) error { return startDetached("rundll32", "url.dll,FileProtocolHandler", u) }

// RunAction executa uma ação da interface contra o host (menu "Ferramentas").
func RunAction(a ActionRequest) (string, error) {
	ip := a.IP
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("IP inválido")
	}
	port := a.Port
	switch a.Action {
	case "http":
		if port == 0 {
			port = 80
		}
		return "", openURL(fmt.Sprintf("http://%s:%d/", ip, port))
	case "https":
		if port == 0 {
			port = 443
		}
		return "", openURL(fmt.Sprintf("https://%s:%d/", ip, port))
	case "ftp":
		return "", openURL("ftp://" + ip + "/")
	case "explore":
		return "", startDetached("explorer.exe", `\\`+ip)
	case "share":
		return "", startDetached("explorer.exe", `\\`+ip+`\`+a.Share)
	case "rdp":
		return "", startDetached("mstsc.exe", "/v:"+ip)
	case "ssh":
		return "", openTerminal("SSH "+ip, "ssh", ip)
	case "telnet":
		return "", openTerminal("Telnet "+ip, "telnet", ip)
	case "ping":
		return "", openTerminal("Ping "+ip, "ping", "-t", ip)
	case "tracert":
		return "", openTerminal("Tracert "+ip, "tracert", ip)
	case "winbox":
		if p, err := exec.LookPath("winbox64.exe"); err == nil {
			return "", startDetached(p, ip)
		}
		if p, err := exec.LookPath("winbox.exe"); err == nil {
			return "", startDetached(p, ip)
		}
		return "", fmt.Errorf("Winbox não encontrado no PATH. Coloque winbox64.exe em uma pasta do PATH.")
	case "wol":
		return "Pacote mágico enviado", WakeOnLAN(a.MAC, ip)
	case "shutdown", "reboot":
		args := []string{"/s"}
		if a.Action == "reboot" {
			args = []string{"/r"}
		}
		args = append(args, "/m", `\\`+ip, "/t", fmt.Sprint(a.Timeout))
		if a.Force {
			args = append(args, "/f")
		}
		if strings.TrimSpace(a.Message) != "" {
			args = append(args, "/c", a.Message)
		}
		out, err := exec.Command("shutdown", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("falha: %s", strings.TrimSpace(string(out)))
		}
		return "Comando enviado com êxito", nil
	case "abort":
		out, err := exec.Command("shutdown", "/a", "/m", `\\`+ip).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("falha: %s", strings.TrimSpace(string(out)))
		}
		return "Desligamento anulado", nil
	}
	return "", fmt.Errorf("ação desconhecida: %s", a.Action)
}

// openUI abre a interface em janela própria do Edge (modo aplicativo),
// com fallback para o navegador padrão.
func openUI(url string) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
	}
	profile := filepath.Join(dataDir(), "janela")
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			if exec.Command(c, "--app="+url, "--user-data-dir="+profile, "--window-size=1280,800", "--no-first-run").Start() == nil {
				return
			}
		}
	}
	openURL(url)
}

func setBroadcast(fd uintptr) {
	syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
