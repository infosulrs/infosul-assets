package main

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options espelha a tela "Opções" do original (velocidade, precisão e recursos).
type Options struct {
	Threads      int             `json:"threads"`
	HighAccuracy bool            `json:"highAccuracy"`
	TimeoutMs    int             `json:"timeoutMs"`
	Groups       map[string]bool `json:"groups"` // http, https, ftp, ssh, telnet, rdp, radmin, shares, netbios, cftv, mikrotik, printer, misc
	ExtraPorts   []int           `json:"extraPorts"`
}

func DefaultOptions() Options {
	return Options{
		Threads:   64,
		TimeoutMs: 700,
		Groups: map[string]bool{
			"http": true, "https": true, "ftp": true, "ssh": true, "telnet": false,
			"rdp": true, "radmin": true, "shares": true, "netbios": true,
			"cftv": true, "mikrotik": true, "printer": true, "misc": false,
		},
	}
}

func (o *Options) normalize() {
	if o.Threads < 1 {
		o.Threads = 1
	}
	if o.Threads > 512 {
		o.Threads = 512
	}
	if o.TimeoutMs < 100 {
		o.TimeoutMs = 100
	}
	if o.TimeoutMs > 10000 {
		o.TimeoutMs = 10000
	}
	if o.Groups == nil {
		o.Groups = DefaultOptions().Groups
	}
}

// Result é uma linha da tabela de resultados.
type Result struct {
	IP           string    `json:"ip"`
	Status       string    `json:"status"` // ativo, inativo, desconhecido
	Name         string    `json:"name"`
	NetBIOSName  string    `json:"netbiosName"`
	NetBIOSGroup string    `json:"netbiosGroup"`
	User         string    `json:"user"`
	MAC          string    `json:"mac"`
	Vendor       string    `json:"vendor"`
	Type         string    `json:"type"`
	RTTms        int       `json:"rttMs"`
	Services     []Service `json:"services"`
	Shares       []Share   `json:"shares"`
	Date         string    `json:"date"`
	Comment      string    `json:"comment"`
	Favorite     bool      `json:"favorite"`
}

// Share é uma pasta ou impressora compartilhada (NetShareEnum no Windows).
type Share struct {
	Name    string `json:"name" xml:"name,attr"`
	Type    string `json:"type" xml:"type,attr"` // pasta, impressora, admin
	Comment string `json:"comment" xml:",chardata"`
}

// Progress é o estado da verificação em andamento.
type Progress struct {
	Total    int  `json:"total"`
	Done     int  `json:"done"`
	Alive    int  `json:"alive"`
	Dead     int  `json:"dead"`
	Unknown  int  `json:"unknown"`
	Running  bool `json:"running"`
	Elapsed  int  `json:"elapsedMs"`
	Canceled bool `json:"canceled"`
}

// Scan verifica todos os alvos em paralelo e chama onResult para cada host concluído.
func Scan(ctx context.Context, targets []Target, opt Options, onResult func(Result), onProgress func(done int)) {
	opt.normalize()
	timeout := time.Duration(opt.TimeoutMs) * time.Millisecond
	jobs := make(chan Target)
	var wg sync.WaitGroup
	var done int64
	for w := 0; w < opt.Threads && w < len(targets); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				r := scanHost(ctx, t, opt, timeout)
				if ctx.Err() == nil {
					onResult(r)
				}
				onProgress(int(atomic.AddInt64(&done, 1)))
			}
		}()
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
}

func scanHost(ctx context.Context, t Target, opt Options, timeout time.Duration) Result {
	r := Result{IP: t.IP.String(), Status: "inativo", Date: time.Now().Format("02/01/2006 15:04:05")}
	attempts := 1
	if opt.HighAccuracy {
		attempts = 2
	}

	// 1) Presença: ICMP e ARP em paralelo (como IcmpSendEcho + SendARP no original).
	var rtt time.Duration
	var pingOK bool
	var mac string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for a := 0; a < attempts && !pingOK; a++ {
			rtt, pingOK = Ping(t.IP, timeout)
		}
	}()
	go func() {
		defer wg.Done()
		mac = ARPLookup(t.IP)
	}()
	wg.Wait()
	if ctx.Err() != nil {
		return r
	}

	// 2) Portas: também servem para detectar hosts que bloqueiam ICMP.
	var list []Probe
	for _, p := range probes {
		if opt.Groups[p.Group] {
			list = append(list, p)
		}
	}
	for _, port := range opt.ExtraPorts {
		if port > 0 && port < 65536 {
			list = append(list, Probe{Key: "tcp", Name: "TCP", Port: port, Kind: "connect", Group: "extra"})
		}
	}
	var mu sync.Mutex
	run := func(ps []Probe) {
		var swg sync.WaitGroup
		for _, p := range ps {
			swg.Add(1)
			go func(p Probe) {
				defer swg.Done()
				if s, ok := probeService(t.IP, p, timeout); ok {
					mu.Lock()
					r.Services = append(r.Services, *s)
					mu.Unlock()
				}
			}(p)
		}
		swg.Wait()
	}
	if pingOK || mac != "" {
		run(list)
	} else {
		// Host sem ping nem ARP (firewall bloqueando ICMP, ou outra sub-rede):
		// primeiro poucas portas comuns; só continua se alguma responder.
		var quick, rest []Probe
		for _, p := range list {
			switch p.Port {
			case 80, 443, 445, 3389, 22, 8080, 554:
				quick = append(quick, p)
			default:
				rest = append(rest, p)
			}
		}
		run(quick)
		if len(r.Services) > 0 {
			run(rest)
		}
	}

	alive := pingOK || mac != "" || len(r.Services) > 0
	if !alive {
		if t.Host != "" {
			r.Name = t.Host
		}
		return r
	}
	r.Status = "ativo"
	r.RTTms = int(rtt / time.Millisecond)
	sort.Slice(r.Services, func(i, j int) bool { return r.Services[i].Port < r.Services[j].Port })

	// 3) Identificação: DNS reverso, NetBIOS e compartilhamentos.
	var iwg sync.WaitGroup
	iwg.Add(1)
	go func() {
		defer iwg.Done()
		if names, err := net.LookupAddr(r.IP); err == nil && len(names) > 0 {
			r.Name = strings.TrimSuffix(names[0], ".")
		}
	}()
	if opt.Groups["netbios"] {
		iwg.Add(1)
		go func() {
			defer iwg.Done()
			if nb, err := QueryNetBIOS(t.IP, timeout, attempts); err == nil {
				r.NetBIOSName, r.NetBIOSGroup, r.User = nb.Name, nb.Group, nb.User
				if mac == "" {
					mac = nb.MAC
				}
			}
		}()
	}
	iwg.Wait()
	if opt.Groups["shares"] && hasService(r.Services, "smb") {
		r.Shares = ListShares(r.IP, 3*time.Second)
	}
	if r.Name == "" {
		r.Name = r.NetBIOSName
	}
	if r.Name == "" && t.Host != "" {
		r.Name = t.Host
	}
	r.MAC = mac
	if mac != "" {
		r.Vendor = Vendor(mac)
	}
	r.Type = guessType(&r)
	return r
}

func hasService(s []Service, key string) bool {
	for _, x := range s {
		if x.Key == key {
			return true
		}
	}
	return false
}
