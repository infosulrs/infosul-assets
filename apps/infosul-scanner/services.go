package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Probe descreve uma porta TCP verificada e como interpretar o serviço.
type Probe struct {
	Key   string // chave usada nas opções e nas ações da interface
	Name  string
	Port  int
	Kind  string // http, https, banner, connect
	Group string // grupo de opção que habilita a porta
}

// Portas do original (FTP, HTTP, HTTPS, RDP, SSH, Telnet, Radmin, SMB) mais
// as que a INFOSUL usa no dia a dia: CFTV, MikroTik, impressoras e Zabbix.
var probes = []Probe{
	{"ftp", "FTP", 21, "banner", "ftp"},
	{"ssh", "SSH", 22, "banner", "ssh"},
	{"telnet", "Telnet", 23, "connect", "telnet"},
	{"http", "HTTP", 80, "http", "http"},
	{"https", "HTTPS", 443, "https", "https"},
	{"smb", "SMB", 445, "connect", "shares"},
	{"rdp", "RDP", 3389, "connect", "rdp"},
	{"radmin", "Radmin", 4899, "connect", "radmin"},
	{"http8080", "HTTP 8080", 8080, "http", "http"},
	{"rtsp", "RTSP (câmera)", 554, "connect", "cftv"},
	{"dvr", "DVR Intelbras/Dahua", 37777, "connect", "cftv"},
	{"hik", "Hikvision SDK", 8000, "connect", "cftv"},
	{"winbox", "MikroTik Winbox", 8291, "connect", "mikrotik"},
	{"mtapi", "MikroTik API", 8728, "connect", "mikrotik"},
	{"jetdirect", "Impressora (9100)", 9100, "connect", "printer"},
	{"vnc", "VNC", 5900, "connect", "misc"},
	{"zabbix", "Zabbix Agent", 10050, "connect", "misc"},
}

// Service é um serviço encontrado em um host.
type Service struct {
	Key    string `json:"key" xml:"key,attr"`
	Name   string `json:"name" xml:"name,attr"`
	Port   int    `json:"port" xml:"port,attr"`
	Detail string `json:"detail" xml:",chardata"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func probeService(ip net.IP, p Probe, timeout time.Duration) (*Service, bool) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(p.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	s := &Service{Key: p.Key, Name: p.Name, Port: p.Port}
	ioTimeout := timeout * 3
	if ioTimeout < 1500*time.Millisecond {
		ioTimeout = 1500 * time.Millisecond
	}
	conn.SetDeadline(time.Now().Add(ioTimeout))
	switch p.Kind {
	case "banner":
		line, _ := bufio.NewReader(conn).ReadString('\n')
		s.Detail = clean(line)
	case "http":
		s.Detail = httpInfo(conn, ip.String())
	case "https":
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip.String()})
		if err := tc.Handshake(); err == nil {
			d := httpInfo(tc, ip.String())
			if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
				if cn := cs.PeerCertificates[0].Subject.CommonName; cn != "" {
					d = strings.TrimSpace(d + " (certificado: " + cn + ")")
				}
			}
			s.Detail = d
		}
	}
	return s, true
}

func httpInfo(c io.ReadWriter, host string) string {
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: INFOSUL-Scanner\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
	body, _ := io.ReadAll(io.LimitReader(c, 64*1024))
	text := string(body)
	var server, title string
	head, rest, _ := strings.Cut(text, "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "server") {
			server = strings.TrimSpace(v)
		}
	}
	if m := titleRe.FindStringSubmatch(rest); m != nil {
		title = clean(html.UnescapeString(m[1]))
	}
	switch {
	case title != "" && server != "":
		return title + " [" + server + "]"
	case title != "":
		return title
	default:
		return server
	}
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// guessType sugere o tipo de dispositivo pelos serviços e pelo fabricante.
func guessType(r *Result) string {
	has := map[string]bool{}
	for _, s := range r.Services {
		has[s.Key] = true
	}
	v := strings.ToLower(r.Vendor)
	switch {
	case has["winbox"] || has["mtapi"] || strings.Contains(v, "routerboard") || strings.Contains(v, "mikrotik"):
		return "Roteador MikroTik"
	case has["dvr"] || has["hik"] || has["rtsp"] ||
		strings.Contains(v, "hikvision") || strings.Contains(v, "dahua") || strings.Contains(v, "intelbras"):
		return "CFTV / Câmera / DVR"
	case has["jetdirect"]:
		return "Impressora"
	case strings.Contains(v, "ubiquiti"):
		return "UniFi / Ubiquiti"
	case has["rdp"] || (has["smb"] && r.NetBIOSName != ""):
		return "Computador Windows"
	case has["ssh"] && !has["smb"]:
		return "Linux / Equipamento de rede"
	case strings.Contains(v, "apple"):
		return "Apple"
	case has["http"] || has["https"] || has["http8080"]:
		return "Dispositivo com interface web"
	}
	return ""
}
