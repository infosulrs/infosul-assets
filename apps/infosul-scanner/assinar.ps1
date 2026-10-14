# Assina os executáveis do INFOSUL Scanner com o certificado de assinatura de código.
#
# Pré-requisitos (no Windows):
#   - Windows SDK (signtool.exe) instalado
#   - Certificado de assinatura de código no token USB ou na nuvem (ex.: Certum SimplySign)
#     já conectado e visível em certmgr.msc > Pessoal > Certificados
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File .\assinar.ps1
#   powershell -ExecutionPolicy Bypass -File .\assinar.ps1 -Thumbprint "AB12...EF"

param(
    [string]$Thumbprint = "",
    [string]$Pasta = "$PSScriptRoot\dist",
    [string]$Timestamp = "http://time.certum.pl"
)

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe não encontrado. Instale o Windows SDK." }

$exes = Get-ChildItem $Pasta -Filter *.exe
if (-not $exes) { throw "Nenhum .exe em $Pasta" }

foreach ($exe in $exes) {
    $sigArgs = @("sign", "/fd", "SHA256", "/tr", $Timestamp, "/td", "SHA256", "/d", "INFOSUL Scanner")
    if ($Thumbprint) { $sigArgs += @("/sha1", $Thumbprint) } else { $sigArgs += "/a" }
    & $signtool.FullName @args $exe.FullName
    if ($LASTEXITCODE -ne 0) { throw "Falha ao assinar $($exe.Name)" }
    & $signtool.FullName verify /pa /v $exe.FullName | Select-String "Issued to|Successfully verified"
}
Write-Host "Assinatura concluída." -ForegroundColor Green
