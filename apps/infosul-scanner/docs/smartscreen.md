# SmartScreen e assinatura de código

## Por que o aviso aparece

O SmartScreen ("O Windows protegeu o computador") avalia a **reputação** do arquivo baixado.
Ele só entra em ação quando o arquivo tem a marca de origem da internet (Mark of the Web),
colocada pelo navegador, pelo Outlook ou pelo WhatsApp Desktop no download.

Um executável sem assinatura digital não tem reputação. Ícone e informações de versão
deixam o arquivo com aparência profissional, mas **não removem o aviso**. Só a assinatura resolve.

## Solução definitiva: certificado de assinatura de código

| Opção | Custo aproximado | Observação |
|---|---|---|
| Certum Standard Code Signing (nuvem, SimplySign) | a partir de 99 € por ano | não precisa de token físico; aceita pessoa jurídica no Brasil |
| Sectigo OV (revendas brasileiras) | R$ 1.158 a R$ 3.026 por ano | token USB obrigatório, entregue pelo correio |
| RapidSSL / DigiCert OV | R$ 1.419 a R$ 1.999 por ano | token USB ou HSM |
| Azure Artifact Signing | US$ 9,99 por mês | **indisponível no Brasil** (só EUA, Canadá, UE e Reino Unido) |

Desde junho de 2023 a chave privada fica obrigatoriamente em token, HSM ou nuvem.
A validação OV exige CNPJ ativo e verificação da empresa (alguns dias).

Mesmo assinado, o SmartScreen pode avisar nas primeiras semanas, até o certificado acumular
reputação (downloads sem denúncia). Depois disso, todo executável novo assinado com o mesmo
certificado abre direto. Certificados EV deixaram de dar reputação imediata em 2024.

Com o certificado em mãos: `powershell -ExecutionPolicy Bypass -File .\assinar.ps1`

## Enquanto não houver certificado

- **Pendrive ou pasta de rede**: copiar o `.exe` por pendrive ou compartilhamento SMB não coloca a
  marca de internet, e o SmartScreen não aparece.
- **Desbloquear uma vez**: botão direito no `.exe` > Propriedades > marcar **Desbloquear** > OK.
  Ou no PowerShell: `Unblock-File .\INFOSUL-Scanner.exe`
- **Falso positivo do Defender**: enviar o arquivo em https://www.microsoft.com/wdsi/filesubmission
  como "software legítimo" de desenvolvedor.
