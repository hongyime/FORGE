# Windows counterpart to scripts/self_host_operator.sh.
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$InstallRoot = 'C:\forge',
    [string]$EnvFile = 'C:\ProgramData\Forge\forge.env',
    [string]$HelmValues = '', [string]$Release = 'forge', [string]$Namespace = 'forge',
    [switch]$DryRun,
    [Parameter(Position=0)][ValidateSet('preflight','install-systemd','upgrade-compose','helm-lint','helm-template','status')][string]$Command = 'preflight'
)
$ErrorActionPreference='Stop'
if (-not $HelmValues) { $HelmValues=Join-Path $RepoRoot 'docker/helm/forge/values.production-example.yaml' }
function Invoke-Tool([string]$Name,[string[]]$Arguments) {
    if ($DryRun) { Write-Host ('+ ' + $Name + ' ' + ($Arguments -join ' ')); return }
    & $Name @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}
function Require-File([string]$Path) { if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "required file not found: $Path" } }
$requiredEnvKeys = @('FORGE_WEB_SECRET_KEY','FORGE_WEB_BOOTSTRAP_TOKEN','FORGE_ENGAGEMENT_KEY','FORGE_POSTGRES_PASSWORD','FORGE_PUBLIC_BASE_URL','FORGE_AUDIT_BUNDLE_REMOTE_SCOPE')
function Test-EnvContract {
 $values = @{}
 foreach ($line in Get-Content -LiteralPath $EnvFile) {
  if ($line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') {
   $value=$matches[2].Trim()
   if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) { $value=$value.Substring(1,$value.Length-2) }
   $values[$matches[1]]=$value
  }
 }
 $missing=@($requiredEnvKeys | Where-Object { -not $values.ContainsKey($_) })
 if ($missing.Count) { Write-Host 'Missing required production env keys:'; $missing | ForEach-Object { Write-Host "  - $_" }; throw 'env file is missing required production keys' }
 $invalid=@()
 foreach ($key in @('FORGE_WEB_SECRET_KEY','FORGE_WEB_BOOTSTRAP_TOKEN','FORGE_ENGAGEMENT_KEY')) { if ($values[$key].Length -lt 32) { $invalid += "$key must be at least 32 characters" } }
 if (-not $values['FORGE_PUBLIC_BASE_URL'].StartsWith('https://')) { $invalid += 'FORGE_PUBLIC_BASE_URL must start with https://' }
 if ($values['FORGE_AUDIT_BUNDLE_REMOTE_SCOPE'] -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { $invalid += 'FORGE_AUDIT_BUNDLE_REMOTE_SCOPE must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}' }
 if ($invalid.Count) { Write-Host 'Invalid production env values:'; $invalid | ForEach-Object { Write-Host "  - $_" }; throw 'env file does not satisfy the production security contract' }
 foreach ($key in $requiredEnvKeys) { Write-Host "Env key present: $key" }
}
$compose=Join-Path $RepoRoot 'docker/docker-compose.prod.yml'; $chart=Join-Path $RepoRoot 'docker/helm/forge'
switch ($Command) {
 preflight {
  foreach ($p in @((Join-Path $RepoRoot 'docker/Dockerfile'),$compose,(Join-Path $RepoRoot 'docker/reverse-proxy/Caddyfile'),(Join-Path $RepoRoot 'docker/reverse-proxy/nginx.conf'),(Join-Path $chart 'Chart.yaml'),(Join-Path $chart 'values.yaml'),$HelmValues)) { Require-File $p }
  Write-Host 'FORGE self-host artifacts present.'; Write-Host "Docker CLI: $([bool](Get-Command docker -ErrorAction SilentlyContinue))"; Write-Host "Helm CLI: $([bool](Get-Command helm -ErrorAction SilentlyContinue))"
  if (Test-Path -LiteralPath $EnvFile -PathType Leaf) { Write-Host "Env file present: $EnvFile"; Test-EnvContract } else { Write-Host "Env file missing: $EnvFile" }
 }
 install-systemd {
  Require-File $compose
  $docker=(Get-Command docker -ErrorAction Stop).Source
  $action='"{0}" compose -f "{1}" up -d --remove-orphans' -f $docker,$compose
  Invoke-Tool (Get-Command schtasks.exe -ErrorAction Stop).Source @('/Create','/F','/TN','FORGE Compose Startup','/SC','ONSTART','/RL','HIGHEST','/TR',$action)
 }
 upgrade-compose {
  Require-File $compose; if (Test-Path $EnvFile) { Get-Content $EnvFile | ForEach-Object { if ($_ -match '^\s*([^#=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1].Trim(),$matches[2].Trim().Trim('"').Trim("'"),'Process') } } }
  Invoke-Tool (Get-Command docker -ErrorAction Stop).Source @('compose','-f',$compose,'config','--quiet'); Invoke-Tool (Get-Command docker -ErrorAction Stop).Source @('compose','-f',$compose,'build'); Invoke-Tool (Get-Command docker -ErrorAction Stop).Source @('compose','-f',$compose,'up','-d','--remove-orphans')
 }
 helm-template { Require-File $HelmValues; Invoke-Tool (Get-Command helm -ErrorAction Stop).Source @('template',$Release,$chart,'--namespace',$Namespace,'--create-namespace','-f',$HelmValues) }
 helm-lint { Require-File $HelmValues; Invoke-Tool (Get-Command helm -ErrorAction Stop).Source @('lint',$chart,'-f',$HelmValues) }
 status { if (Get-Command docker -ErrorAction SilentlyContinue) { Invoke-Tool (Get-Command docker).Source @('compose','-f',$compose,'ps') } else { Write-Host 'Docker CLI missing.' } }
}
