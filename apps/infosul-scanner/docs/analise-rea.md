# Análise do Advanced IP Scanner 2.5.4594.1 com o REA

Objetivo: mapear as funções do programa para reimplementá-las do zero no INFOSUL Scanner.
Nenhum código, base de dados, texto ou marca do original foi copiado.

## Artefato analisado

| Item | Valor |
|---|---|
| Instalador | `Advanced_IP_Scanner_2.5.4594.1.exe`, SHA-256 `26d5748f...c193b` |
| Empacotamento | Inno Setup 5.5 contendo MSI (WiX) com `ip_scan_en_us_Release_2.5.4594.1.msi` |
| Executável principal | `advanced_ip_scanner.exe`, PE32 x86, SHA-256 `4b036cc9...bd3e5` |
| Console | `advanced_ip_scanner_console.exe` |
| Framework | C++ com Qt 5 (Core, Gui, Widgets, Network, Xml, PrintSupport), OpenSSL 1.0, PCRE |
| Fabricante | Famatech Corp., freeware, compilado em 29/04/2022 |

Ferramentas: `rea inspect-artifact` e `rea inspect-pe-resources` (REA 6.4.0), `innoextract`, `7z`,
`objdump -p` (tabela de importação) e extração dos textos das traduções Qt (`.qm`).

## Como o original funciona (pela tabela de importação)

| Função | API Win32 usada pelo original | INFOSUL Scanner |
|---|---|---|
| Ping | `IPHLPAPI!IcmpCreateFile / IcmpSendEcho` | mesma API, via `syscall` |
| MAC na rede local | `IPHLPAPI!SendARP` | mesma API |
| Adaptadores locais | `IPHLPAPI!GetAdaptersInfo` | `net.Interfaces` |
| Nome DNS | `WS2_32!GetNameInfoW`, `DNSAPI!DnsQuery_W` | `net.LookupAddr` |
| Nome NetBIOS, grupo, usuário | NBSTAT UDP 137 | NBSTAT UDP 137 (RFC 1002) implementado do zero |
| Pastas e impressoras compartilhadas | `NETAPI32!NetShareEnum` | mesma API |
| Info do servidor e usuários | `NetServerGetInfo`, `NetWkstaUserEnum`, `NetRemoteTOD` | não implementado (NBSTAT já traz usuário) |
| Desligar / anular remoto | `ADVAPI32!InitiateSystemShutdownW / AbortSystemShutdownW` | `shutdown.exe /s /r /a /m` |
| Mapear unidade | `MPR!WNetAddConnection2W` | Explorer `\\host` |
| Instalar impressora | `WINSPOOL!AddPrinterConnectionW` | não implementado |
| SNMP | `mgmtapi!SnmpMgrRequest` | não implementado (próxima versão) |
| Serviços (HTTP, HTTPS, FTP...) | Qt Network + `service_probes` (assinaturas compactadas) | conexão TCP + banner + título HTTP |
| Fabricante pelo MAC | `mac_interval_tree.txt` (IEEE) | base pública IEEE OUI embutida |
| Painel de detalhes | `details_panel_*.tpl` (HTML) | painel lateral |
| Configurações | Registro `HKCU\Software\famatech\advanced_ip_scanner` | `%APPDATA%\INFOSUL Scanner\dados.json` |

Opções encontradas no MSI: `HIGH_ACCURACY`, `THREAD_COUNT`, `SCAN_RADMIN`, `RADMIN_PORTS`,
`SCAN_FTP`, `SCAN_HTTP`, `SCAN_HTTPS`, `SCAN_NETBIOS`, `SCAN_SHARES`, `SCAN_USERNAME`,
`SCAN_ADMIN_SHARES`, `CHECK_SMB`, `SHOW_ALIVE`, `SHOW_DEAD`, `SHOW_UNKNOWN`, `IPRANGESMRULIST`.

Console original: `/r:<faixa>`, `/s:<arquivo>`, `/f:<saída>`, `/v` e `/v2`. O INFOSUL Scanner aceita a mesma sintaxe.

## Funções da interface (pelas traduções)

Verificar / Pausar / Parar, sub-rede deste computador, classe C, verificar em arquivo, MRU de faixas,
abas Resultados e Favoritos, mostrar ativos / inativos / desconhecidos, pesquisa, painel de detalhes,
renomear, editar comentário e MAC, adicionar a favoritos, adicionar computador, explorar, HTTP, HTTPS,
FTP, RDP, SSH (plink), Telnet, Radmin (controle total, transferência, chat, mensagem), Wake-On-LAN,
desligar / reinicializar / anular, salvar como CSV, HTML e XML, imprimir, excluir dados armazenados.

## O que ficou de fora (de propósito)

- **Integração Radmin** (produto pago da Famatech). O INFOSUL Scanner só detecta a porta 4899.
- **Pausar** (só Parar), **mapear unidade** e **instalar impressora remota**.

## O que o INFOSUL Scanner tem a mais

- Detecção de CFTV: RTSP 554, DVR Intelbras/Dahua 37777, Hikvision 8000, com título da página web do DVR.
- MikroTik: Winbox 8291 e API 8728, com atalho para o Winbox.
- Impressoras (9100), VNC, Zabbix Agent e portas TCP extras configuráveis.
- Tipo de dispositivo sugerido (CFTV, MikroTik, Windows, impressora, UniFi).
- Relatório HTML com identidade INFOSUL e CSV com ponto e vírgula (Excel pt-BR).
