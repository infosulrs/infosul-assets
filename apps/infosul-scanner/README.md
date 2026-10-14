# INFOSUL Scanner

Scanner de rede local para Windows, inspirado nas funções do Advanced IP Scanner e reimplementado do zero.
A análise do original feita com o REA está em [docs/analise-rea.md](docs/analise-rea.md).

Um único `.exe`, sem instalação. A interface abre em janela própria do Edge (modo aplicativo) e conversa
com um serviço local em `127.0.0.1`, protegido por token de sessão.

## Funções

- Faixas: `192.168.0.1-100, 192.168.0.200`, `10.0.0.0/24`, `10.0.0.1-10.0.1.50`, nomes de host, importação de lista `.txt`.
- Presença por ICMP (`IcmpSendEcho`) e ARP (`SendARP`), com fallback por portas TCP para hosts que bloqueiam ping.
- Nome DNS, nome NetBIOS, grupo de trabalho, usuário logado e MAC (NBSTAT, UDP 137).
- Fabricante pelo MAC (base IEEE OUI embutida).
- Serviços: FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP, Radmin, RTSP, DVR Intelbras/Dahua, Hikvision, Winbox, API MikroTik, impressora 9100, VNC, Zabbix e portas extras. Mostra banner e título da página web.
- Pastas e impressoras compartilhadas (`NetShareEnum`).
- Ações: abrir HTTP/HTTPS/FTP, Explorar `\\host`, RDP, SSH, Telnet, Ping, Tracert, Winbox, Wake-On-LAN, desligar / reinicializar / anular desligamento remoto.
- Favoritos, renomear e comentários (salvos por MAC), pesquisa, filtros, ordenação.
- Exportar CSV (`;` para Excel pt-BR, ou `,`), relatório HTML INFOSUL, XML e impressão.

## Uso

Interface: dê dois cliques em `INFOSUL-Scanner.exe`.

Console (mesma sintaxe do original):

```bat
INFOSUL-Scanner-Console.exe /r:192.168.0.1-254 /v
INFOSUL-Scanner-Console.exe /s:faixas.txt /f:resultado.csv
INFOSUL-Scanner-Console.exe -r 10.0.0.0/24 -f inventario.html -t 128
```

Dados e opções ficam em `%APPDATA%\INFOSUL Scanner\dados.json`.

## Compilar

Requer Go 1.22 ou superior. Compila a partir do Linux ou do Windows, sem CGO.

```bash
go test ./...
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o dist/INFOSUL-Scanner.exe .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/INFOSUL-Scanner-Console.exe .
```

## Estrutura

| Arquivo | Conteúdo |
|---|---|
| `ranges.go` | interpretação das faixas e adaptadores locais |
| `scanner.go` | motor de verificação paralela |
| `services.go` | portas, banners, título HTTP e tipo de dispositivo |
| `netbios.go` | consulta NBSTAT |
| `oui.go`, `data/oui.txt.gz` | fabricante pelo MAC |
| `platform_windows.go` | ICMP, ARP, compartilhamentos e ações no Windows |
| `platform_other.go` | equivalentes para Linux (desenvolvimento e testes) |
| `server.go`, `web/` | API local e interface |
| `export.go`, `store.go`, `wol.go` | exportação, persistência e Wake-On-LAN |
