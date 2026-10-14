// INFOSUL Scanner: scanner de rede local para Windows.
//
// Reimplementação própria (clean-room) das funções do Advanced IP Scanner,
// a partir do mapeamento feito com o REA. Nenhum código, base de dados ou
// marca do original é usado. Ver docs/analise-rea.md.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
)

var version = "1.0.1"

func main() {
	// Aceita também a sintaxe do console original: /r:<faixa> /s:<arquivo> /f:<arquivo> /v
	args := os.Args[1:]
	for i, a := range args {
		if len(a) > 2 && a[0] == '/' && strings.Contains("rsfv", string(a[1])) {
			if a[2] == ':' {
				args[i] = "-" + string(a[1]) + "=" + a[3:]
			} else if a == "/v" || a == "/v2" {
				args[i] = "-v"
			}
		} else if a == "/v" {
			args[i] = "-v"
		}
	}

	fl := flag.NewFlagSet("infosul-scanner", flag.ExitOnError)
	rng := fl.String("r", "", "endereço ou faixa a verificar, ex. 192.168.0.1-254")
	src := fl.String("s", "", "arquivo com uma faixa ou IP por linha")
	out := fl.String("f", "", "arquivo de saída (.csv, .xml, .html ou .txt)")
	verbose := fl.Bool("v", false, "mostrar serviços encontrados")
	threads := fl.Int("t", 0, "número de threads (padrão: opções salvas)")
	addr := fl.String("listen", "127.0.0.1:0", "endereço da interface local")
	noOpen := fl.Bool("no-open", false, "não abrir a janela automaticamente")
	fl.Usage = func() {
		fmt.Fprintf(fl.Output(), "INFOSUL Scanner %s\n\nInterface: execute sem parâmetros.\n\nConsole:\n  infosul-scanner-console -r 192.168.0.1-254 [-f resultado.csv] [-v]\n  infosul-scanner-console /r:192.168.0.1-254 /f:resultado.txt /v\n\n", version)
		fl.PrintDefaults()
	}
	fl.Parse(args)

	if *rng == "" && *src == "" {
		app := NewApp()
		if err := app.Serve(*addr, !*noOpen); err != nil {
			fmt.Fprintln(os.Stderr, "erro:", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(runConsole(*rng, *src, *out, *verbose, *threads))
}

func runConsole(rng, src, outPath string, verbose bool, threads int) int {
	text := rng
	if src != "" {
		b, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Não foi possível ler os dados do arquivo:", err)
			return 2
		}
		text = strings.TrimSpace(text + "\n" + string(b))
	}
	targets, err := ParseRanges(text)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	opt := OpenStore().Snapshot().Options
	if threads > 0 {
		opt.Threads = threads
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var mu sync.Mutex
	var rows []Result
	fmt.Fprintf(os.Stderr, "Verificando %d endereços...\n", len(targets))
	Scan(ctx, targets, opt, func(r Result) {
		mu.Lock()
		rows = append(rows, r)
		mu.Unlock()
	}, func(done int) {
		if done%32 == 0 || done == len(targets) {
			fmt.Fprintf(os.Stderr, "\r%d/%d", done, len(targets))
		}
	})
	fmt.Fprintln(os.Stderr)
	sortByIP(rows)

	var w io.Writer = os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Não foi possível abrir o arquivo para gravação:", err)
			return 2
		}
		defer f.Close()
		w = f
		switch strings.ToLower(outPath[strings.LastIndex(outPath, ".")+1:]) {
		case "csv":
			ExportCSV(f, rows, ';')
			return 0
		case "xml":
			ExportXML(f, rows)
			return 0
		case "html", "htm":
			ExportHTML(f, rows)
			return 0
		}
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	alive := 0
	for _, r := range rows {
		if r.Status != "ativo" {
			continue
		}
		alive++
		fmt.Fprintf(bw, "%-15s  %-28s  %-17s  %s\n", r.IP, r.Name, r.MAC, r.Vendor)
		if verbose {
			for _, s := range r.Services {
				fmt.Fprintf(bw, "    %-22s %5d  %s\n", s.Name, s.Port, s.Detail)
			}
			for _, sh := range r.Shares {
				fmt.Fprintf(bw, "    Compartilhamento       \\\\%s\\%s (%s)\n", r.IP, sh.Name, sh.Type)
			}
			if r.NetBIOSName != "" {
				fmt.Fprintf(bw, "    NetBIOS: %s  Grupo: %s  Usuário: %s\n", r.NetBIOSName, r.NetBIOSGroup, r.User)
			}
		}
	}
	fmt.Fprintf(bw, "\n%d ativos, %d inativos\n", alive, len(rows)-alive)
	return 0
}
