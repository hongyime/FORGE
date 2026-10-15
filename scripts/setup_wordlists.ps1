# Windows counterpart to scripts/setup_wordlists.sh.
[CmdletBinding()]
param([string]$DataDir = "data/wordlists")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
Write-Host "[*] Setting up essential wordlists in $DataDir..."
$rockyou = Join-Path $DataDir 'rockyou.txt'
if (-not (Test-Path $rockyou)) {
    $archive = Join-Path $DataDir 'rockyou.download'
    Write-Host '[*] Downloading rockyou.txt...'
    try { Invoke-WebRequest 'https://github.com/brannondorsey/PassDicts/raw/master/rockyou.txt.tar.bz2' -OutFile $archive }
    catch { Invoke-WebRequest 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz' -OutFile $archive }
    $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tar) { throw 'Windows tar.exe is required to extract the wordlist archive.' }
    & $tar.Source -xf $archive -C $DataDir
    if ($LASTEXITCODE -ne 0) { throw "Wordlist archive extraction failed with exit code $LASTEXITCODE" }
    Remove-Item $archive -Force
    Write-Host '[+] rockyou.txt ready.'
} else { Write-Host '[+] rockyou.txt already exists.' }
$secLists = Join-Path $DataDir 'seclists'; New-Item -ItemType Directory -Path $secLists -Force | Out-Null
$lists = @(
    @{ Name='usernames.txt'; Url='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt'; Label='common usernames' },
    @{ Name='common_web_dirs.txt'; Url='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt'; Label='common web directories' }
)
foreach ($list in $lists) { $path=Join-Path $secLists $list.Name; if (-not (Test-Path $path)) { Write-Host "[*] Downloading $($list.Label)..."; Invoke-WebRequest $list.Url -OutFile $path; Write-Host "[+] $($list.Label) list ready." } }
Write-Host '[*] Wordlist setup complete.'
