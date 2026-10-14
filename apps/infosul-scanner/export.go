package main

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

func servicesText(r Result) string {
	var parts []string
	for _, s := range r.Services {
		t := fmt.Sprintf("%s:%d", s.Name, s.Port)
		if s.Detail != "" {
			t += " (" + s.Detail + ")"
		}
		parts = append(parts, t)
	}
	for _, sh := range r.Shares {
		parts = append(parts, "\\\\"+r.IP+"\\"+sh.Name)
	}
	return strings.Join(parts, "; ")
}

// ExportCSV usa ponto e vírgula e BOM UTF-8 para abrir direto no Excel em pt-BR.
func ExportCSV(w io.Writer, rows []Result, comma rune) error {
	io.WriteString(w, "\xEF\xBB\xBF")
	cw := csv.NewWriter(w)
	cw.Comma = comma
	cw.Write([]string{"Status", "Nome", "IP", "Fabricante", "MAC", "Tipo", "NetBIOS", "Grupo", "Usuário", "Comentários", "Serviços", "Data"})
	for _, r := range rows {
		cw.Write([]string{r.Status, r.Name, r.IP, r.Vendor, r.MAC, r.Type, r.NetBIOSName, r.NetBIOSGroup, r.User, r.Comment, servicesText(r), r.Date})
	}
	cw.Flush()
	return cw.Error()
}

type xmlRow struct {
	XMLName  xml.Name  `xml:"host"`
	Status   string    `xml:"status,attr"`
	IP       string    `xml:"ip,attr"`
	Name     string    `xml:"name,attr"`
	MAC      string    `xml:"mac,attr,omitempty"`
	Vendor   string    `xml:"vendor,attr,omitempty"`
	Type     string    `xml:"type,attr,omitempty"`
	NetBIOS  string    `xml:"netbios,attr,omitempty"`
	Group    string    `xml:"group,attr,omitempty"`
	User     string    `xml:"user,attr,omitempty"`
	Comment  string    `xml:"comment,attr,omitempty"`
	Services []Service `xml:"service"`
	Shares   []Share   `xml:"share"`
}

func ExportXML(w io.Writer, rows []Result) error {
	io.WriteString(w, xml.Header)
	io.WriteString(w, "<infosul_scanner>\n")
	enc := xml.NewEncoder(w)
	enc.Indent("  ", "  ")
	for _, r := range rows {
		enc.Encode(xmlRow{Status: r.Status, IP: r.IP, Name: r.Name, MAC: r.MAC, Vendor: r.Vendor, Type: r.Type,
			NetBIOS: r.NetBIOSName, Group: r.NetBIOSGroup, User: r.User, Comment: r.Comment, Services: r.Services, Shares: r.Shares})
	}
	enc.Flush()
	_, err := io.WriteString(w, "\n</infosul_scanner>\n")
	return err
}

var reportTpl = template.Must(template.New("r").Funcs(template.FuncMap{"svc": servicesText}).Parse(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>INFOSUL - Inventário de rede</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;color:#111;margin:32px;background:#fff}
header{border-bottom:3px solid #1B3358;padding-bottom:10px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:flex-end}
.brand{font-size:26px;font-weight:800;color:#1B3358;letter-spacing:1px}
.sub{color:#444;font-size:13px}
.gold{height:2px;background:#B8963E;width:80px;margin-bottom:18px}
h1{font-size:18px;color:#1B3358;margin:0 0 4px}
table{border-collapse:collapse;width:100%;font-size:12px}
th{background:#1B3358;color:#fff;text-align:left;padding:6px}
td{border-bottom:1px solid #ddd;padding:5px 6px;vertical-align:top}
tr:nth-child(even) td{background:#f4f6f9}
.ok{color:#1d7a35;font-weight:600}.off{color:#888}
footer{margin-top:24px;font-size:11px;color:#666}
</style></head><body>
<header><div><div class="brand">INFOSUL</div><div class="sub">Redes de Computadores · Porto Alegre, RS</div></div>
<div class="sub">Gerado em {{.When}}</div></header><div class="gold"></div>
<h1>Inventário de rede</h1><p class="sub">{{.Summary}}</p>
<table><tr><th>Status</th><th>Nome</th><th>IP</th><th>Fabricante</th><th>MAC</th><th>Tipo</th><th>Serviços</th><th>Comentários</th></tr>
{{range .Rows}}<tr><td class="{{if eq .Status "ativo"}}ok{{else}}off{{end}}">{{.Status}}</td><td>{{.Name}}</td><td>{{.IP}}</td><td>{{.Vendor}}</td><td>{{.MAC}}</td><td>{{.Type}}</td><td>{{svc .}}</td><td>{{.Comment}}</td></tr>
{{end}}</table>
<footer>INFOSUL Scanner · relatório gerado automaticamente</footer>
</body></html>`))

func ExportHTML(w io.Writer, rows []Result) error {
	a, d := 0, 0
	for _, r := range rows {
		if r.Status == "ativo" {
			a++
		} else {
			d++
		}
	}
	return reportTpl.Execute(w, map[string]any{
		"When":    time.Now().Format("02/01/2006 15:04"),
		"Summary": fmt.Sprintf("%d hosts: %d ativos, %d inativos", len(rows), a, d),
		"Rows":    rows,
	})
}
