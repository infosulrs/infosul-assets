package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

// ActionRequest é uma ação disparada pelo menu do host.
type ActionRequest struct {
	Action  string `json:"action"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Port    int    `json:"port"`
	Share   string `json:"share"`
	Timeout int    `json:"timeout"`
	Force   bool   `json:"force"`
	Message string `json:"message"`
}

type App struct {
	store    *Store
	token    string
	mu       sync.Mutex
	results  []Result
	progress Progress
	cancel   context.CancelFunc
	started  time.Time
	lastPing time.Time
}

func NewApp() *App {
	b := make([]byte, 16)
	rand.Read(b)
	return &App{store: OpenStore(), token: hex.EncodeToString(b), lastPing: time.Now()}
}

// decorate aplica nome/comentário editados e marca favoritos.
func (a *App) decorate(rows []Result) []Result {
	d := a.store.Snapshot()
	out := make([]Result, len(rows))
	for i, r := range rows {
		if m, ok := d.Meta[metaKey(r.IP, r.MAC)]; ok {
			if m.Name != "" {
				r.Name = m.Name
			}
			r.Comment = m.Comment
		}
		for _, f := range d.Favorites {
			if f.IP == r.IP && strings.EqualFold(f.MAC, r.MAC) {
				r.Favorite = true
			}
		}
		out[i] = r
	}
	return out
}

func (a *App) startScan(rangeText string, opt Options) error {
	targets, err := ParseRanges(rangeText)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.progress.Running {
		a.mu.Unlock()
		return fmt.Errorf("já existe uma verificação em andamento")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.results = nil
	a.started = time.Now()
	a.progress = Progress{Total: len(targets), Running: true}
	a.mu.Unlock()
	a.store.AddMRU(strings.TrimSpace(rangeText))
	go func() {
		Scan(ctx, targets, opt, func(r Result) {
			a.mu.Lock()
			a.results = append(a.results, r)
			switch r.Status {
			case "ativo":
				a.progress.Alive++
			case "inativo":
				a.progress.Dead++
			default:
				a.progress.Unknown++
			}
			a.mu.Unlock()
		}, func(done int) {
			a.mu.Lock()
			a.progress.Done = done
			a.mu.Unlock()
		})
		a.mu.Lock()
		a.progress.Running = false
		a.progress.Canceled = ctx.Err() != nil
		a.progress.Elapsed = int(time.Since(a.started) / time.Millisecond)
		a.mu.Unlock()
		cancel()
	}()
	return nil
}

func (a *App) stopScan() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	api := http.NewServeMux()
	api.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		d := a.store.Snapshot()
		writeJSON(w, map[string]any{
			"networks": LocalNetworks(), "options": d.Options, "mru": d.MRU,
			"favorites": d.Favorites, "version": version, "platform": runtime.GOOS,
		})
	})
	api.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		var since int
		fmt.Sscan(r.URL.Query().Get("since"), &since)
		a.mu.Lock()
		p := a.progress
		if p.Running {
			p.Elapsed = int(time.Since(a.started) / time.Millisecond)
		}
		if since < 0 || since > len(a.results) {
			since = 0
		}
		rows := append([]Result(nil), a.results[since:]...)
		total := len(a.results)
		a.mu.Unlock()
		writeJSON(w, map[string]any{"progress": p, "results": a.decorate(rows), "count": total})
	})
	api.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Range   string   `json:"range"`
			Options *Options `json:"options"`
		}
		if err := readJSON(r, &req); err != nil {
			httpErr(w, err)
			return
		}
		opt := a.store.Snapshot().Options
		if req.Options != nil {
			opt = *req.Options
		}
		if err := a.startScan(req.Range, opt); err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api.HandleFunc("POST /api/stop", func(w http.ResponseWriter, r *http.Request) {
		a.stopScan()
		writeJSON(w, map[string]bool{"ok": true})
	})
	api.HandleFunc("POST /api/options", func(w http.ResponseWriter, r *http.Request) {
		var o Options
		if err := readJSON(r, &o); err != nil {
			httpErr(w, err)
			return
		}
		if err := a.store.SetOptions(o); err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, a.store.Snapshot().Options)
	})
	api.HandleFunc("POST /api/meta", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP, MAC, Name, Comment string
		}
		if err := readJSON(r, &req); err != nil {
			httpErr(w, err)
			return
		}
		if err := a.store.SetMeta(req.IP, req.MAC, Meta{Name: req.Name, Comment: req.Comment}); err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api.HandleFunc("POST /api/favorite", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Op  string   `json:"op"`
			Fav Favorite `json:"fav"`
		}
		if err := readJSON(r, &req); err != nil {
			httpErr(w, err)
			return
		}
		var err error
		if req.Op == "remove" {
			err = a.store.RemoveFavorite(req.Fav.IP, req.Fav.MAC)
		} else {
			if net.ParseIP(req.Fav.IP).To4() == nil {
				httpErr(w, fmt.Errorf("endereço IP incorreto"))
				return
			}
			err = a.store.AddFavorite(req.Fav)
		}
		if err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, a.store.Snapshot().Favorites)
	})
	api.HandleFunc("POST /api/clear", func(w http.ResponseWriter, r *http.Request) {
		if err := a.store.ClearData(); err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api.HandleFunc("POST /api/action", func(w http.ResponseWriter, r *http.Request) {
		var req ActionRequest
		if err := readJSON(r, &req); err != nil {
			httpErr(w, err)
			return
		}
		msg, err := RunAction(req)
		if err != nil {
			httpErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"message": msg})
	})
	api.HandleFunc("GET /api/export", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		rows := append([]Result(nil), a.results...)
		a.mu.Unlock()
		rows = a.decorate(rows)
		if r.URL.Query().Get("scope") == "alive" {
			alive := rows[:0]
			for _, x := range rows {
				if x.Status == "ativo" {
					alive = append(alive, x)
				}
			}
			rows = alive
		}
		sortByIP(rows)
		stamp := time.Now().Format("2006-01-02_1504")
		switch r.URL.Query().Get("fmt") {
		case "xml":
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="infosul-scanner_`+stamp+`.xml"`)
			ExportXML(w, rows)
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.URL.Query().Get("inline") == "" {
				w.Header().Set("Content-Disposition", `attachment; filename="infosul-scanner_`+stamp+`.html"`)
			}
			ExportHTML(w, rows)
		default:
			comma := ';'
			if r.URL.Query().Get("comma") == "1" {
				comma = ','
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="infosul-scanner_`+stamp+`.csv"`)
			ExportCSV(w, rows, comma)
		}
	})
	api.HandleFunc("POST /api/ping", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.lastPing = time.Now()
		a.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})

	// Proteção da API local: token por sessão (cabeçalho ou ?t= nos downloads)
	// e Host restrito ao loopback, contra DNS rebinding.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "host não permitido", http.StatusForbidden)
			return
		}
		t := r.Header.Get("X-Token")
		if t == "" {
			t = r.URL.Query().Get("t")
		}
		if t != a.token {
			http.Error(w, "token inválido", http.StatusForbidden)
			return
		}
		api.ServeHTTP(w, r)
	})
	return mux
}

func sortByIP(rows []Result) {
	key := func(s string) uint32 {
		if ip := net.ParseIP(s).To4(); ip != nil {
			return ipToU32(ip)
		}
		return 0
	}
	sort.Slice(rows, func(i, j int) bool { return key(rows[i].IP) < key(rows[j].IP) })
}

// Serve sobe a interface em 127.0.0.1 e encerra quando a janela fecha
// (sem heartbeat por 3 minutos).
func (a *App) Serve(addr string, open bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), a.token)
	fmt.Println("INFOSUL Scanner em", url)
	if open {
		go openUI(url)
		go func() {
			for range time.Tick(15 * time.Second) {
				a.mu.Lock()
				idle := time.Since(a.lastPing)
				a.mu.Unlock()
				if idle > 3*time.Minute {
					ln.Close()
					return
				}
			}
		}()
	}
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	err = srv.Serve(ln)
	if err == http.ErrServerClosed || strings.Contains(fmt.Sprint(err), "use of closed") {
		return nil
	}
	return err
}
