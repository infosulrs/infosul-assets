//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Implementação para Linux/macOS, usada no desenvolvimento e nos testes.
// O alvo principal é o Windows (platform_windows.go).

var rttRe = regexp.MustCompile(`time[=<]([\d.]+)`)

func Ping(ip net.IP, timeout time.Duration) (time.Duration, bool) {
	sec := int((timeout + time.Second - 1) / time.Second)
	out, err := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(sec), ip.String()).Output()
	if err != nil {
		return 0, false
	}
	if m := rttRe.FindSubmatch(out); m != nil {
		f, _ := strconv.ParseFloat(string(m[1]), 64)
		return time.Duration(f * float64(time.Millisecond)), true
	}
	return 0, true
}

func ARPLookup(ip net.IP) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 4 && fs[0] == ip.String() && fs[3] != "00:00:00:00:00:00" && strings.Count(fs[3], ":") == 5 {
			return strings.ToUpper(fs[3])
		}
	}
	return ""
}

func ListShares(ip string, timeout time.Duration) []Share { return nil }

func dataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "infosul-scanner")
}

func openURL(u string) error { return exec.Command("xdg-open", u).Start() }

func RunAction(a ActionRequest) (string, error) {
	switch a.Action {
	case "wol":
		return "Pacote mágico enviado", WakeOnLAN(a.MAC, a.IP)
	case "http":
		return "", openURL(fmt.Sprintf("http://%s:%d/", a.IP, max(a.Port, 80)))
	case "https":
		return "", openURL(fmt.Sprintf("https://%s:%d/", a.IP, max(a.Port, 443)))
	}
	return "", fmt.Errorf("ação disponível apenas no Windows")
}

func openUI(url string) { openURL(url) }

func setBroadcast(fd uintptr) {
	syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
