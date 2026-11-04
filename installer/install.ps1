# PARANOID one-command installer for Windows 10/11 (per user, no administrator rights).
#
#   irm https://www.paranoid.family/install.ps1 | iex
#
# What it does, in order (every download is verified before use):
#   1. Node.js 24 (official portable build, SHA-256 checked against nodejs.org's SHASUMS256.txt),
#      unless Node 24+ is already installed.
#   2. The PARANOID runtime (zip from www.paranoid.family, SHA-256 checked against the published .sha256).
#   3. Tor Expert Bundle (scripts/install-tor.mjs: SHA-256 against torproject.org's signed sums file,
#      plus the OpenPGP signature when gpg is available).
#   4. Ollama (winget, or the official installer after an Authenticode signature check) and a local
#      sanitizer model (qwen3:8b, or qwen3:4b on machines with less than 16 GB of memory).
#   5. Start Menu shortcuts, start at sign-in, an entry in Settings > Apps, then opens the chat.
#
# Nothing is sent anywhere except these downloads. Your keys, prompts and settings stay in
# %APPDATA%\paranoid, which an upgrade or uninstall leaves in place unless you ask otherwise.
#
# Options: & ([scriptblock]::Create((irm https://www.paranoid.family/install.ps1))) -Model qwen3:4b -NoAutostart
#   -Model <ollama model>  -SkipOllama  -SkipModel  -NoAutostart  -NoLaunch  -PortableNode (ignore an installed Node)
param(
  [string]$Model = '',
  [switch]$SkipOllama,
  [switch]$SkipModel,
  [switch]$NoAutostart,
  [switch]$NoLaunch,
  [switch]$PortableNode,
  [string]$Source = 'https://www.paranoid.family'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is much faster without the progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Dir     = Join-Path $env:LOCALAPPDATA 'Programs\PARANOID'
$AppDir  = Join-Path $Dir 'app'
$NodeDir = Join-Path $Dir 'node'
$DataDir = Join-Path $env:APPDATA 'paranoid'
$Tmp     = Join-Path $env:TEMP ('paranoid-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Dir, $Tmp, $DataDir | Out-Null

function Step($n, $text) { Write-Host ''; Write-Host ("[{0}/5] {1}" -f $n, $text) -ForegroundColor White }
function Info($text) { Write-Host ('      ' + $text) -ForegroundColor DarkGray }
function Fail($text) { Write-Host ''; Write-Host ('PARANOID install stopped: ' + $text) -ForegroundColor Red; throw $text }
function Download($url, $out) { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -Headers @{ 'User-Agent' = 'paranoid-installer' } }
function GetText($url) { $f = Join-Path $Tmp ([guid]::NewGuid().ToString('N')); Download $url $f; [IO.File]::ReadAllText($f) }
# Runs a native program; its progress on stderr must not count as a PowerShell error. Returns the exit code.
function Native([string]$exe, [string[]]$argv) { $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & $exe @argv 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { Write-Host $_.Exception.Message } else { Write-Host $_ } } } finally { $ErrorActionPreference = $old }; return $LASTEXITCODE }
function Sha256($path) { (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant() }

Write-Host ''
Write-Host 'PARANOID - privacy layer for AI agents' -ForegroundColor White
Write-Host ('Installing into ' + $Dir) -ForegroundColor DarkGray

if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitOperatingSystem) { Fail 'this installer needs 64-bit Windows' }

# ---------------------------------------------------------------- 1. Node.js
Step 1 'Node.js 24'
$node = $null
$sys = Get-Command node -ErrorAction SilentlyContinue
if ($sys -and -not $PortableNode) {
  $v = (& $sys.Source --version) 2>$null
  if ($v -match '^v(\d+)\.' -and [int]$Matches[1] -ge 24) { $node = $sys.Source; Info ("using installed Node " + $v) }
}
if (-not $node) {
  $base = 'https://nodejs.org/dist/latest-v24.x/'
  $sums = GetText ($base + 'SHASUMS256.txt')
  $line = ($sums -split "`n") | Where-Object { $_ -match '\s(node-v24\.\d+\.\d+-win-x64\.zip)\s*$' } | Select-Object -First 1
  if (-not $line) { Fail 'could not find the Node.js 24 Windows build' }
  $want = ($line.Trim() -split '\s+')[0].ToLowerInvariant()
  $file = ($line.Trim() -split '\s+')[1]
  Info ('downloading ' + $file)
  $zip = Join-Path $Tmp $file
  Download ($base + $file) $zip
  if ((Sha256 $zip) -ne $want) { Fail 'Node.js download does not match SHASUMS256.txt' }
  Info 'SHA-256 verified'
  Expand-Archive -Path $zip -DestinationPath $Tmp -Force
  if (Test-Path $NodeDir) { Remove-Item -Recurse -Force $NodeDir }
  Move-Item (Join-Path $Tmp ($file -replace '\.zip$', '')) $NodeDir
  $node = Join-Path $NodeDir 'node.exe'
  Info ('installed ' + (& $node --version))
}

# ---------------------------------------------------------------- 2. runtime
Step 2 'PARANOID runtime'
$zip = Join-Path $Tmp 'paranoid-local.zip'
Download ($Source + '/download/paranoid-local.zip') $zip
$want = ((GetText ($Source + '/download/paranoid-local.zip.sha256')).Trim() -split '\s+')[0].ToLowerInvariant()
if ((Sha256 $zip) -ne $want) { Fail 'runtime download does not match its published SHA-256' }
Info 'SHA-256 verified'
# stop a running copy before replacing its files
Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" | Where-Object { $_.CommandLine -like ('*' + (Join-Path $AppDir 'src\main.ts') + '*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$x = Join-Path $Tmp 'runtime'
Expand-Archive -Path $zip -DestinationPath $x -Force
if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir }
Move-Item (Join-Path $x 'local') $AppDir
Info ('installed in ' + $AppDir)

# ---------------------------------------------------------------- 3. Tor
Step 3 'Tor'
$torExe = Join-Path $DataDir 'tor\tor\tor.exe'
if (Test-Path $torExe) { Info 'already installed' }
else {
  Push-Location $AppDir
  try { if ((Native $node @('scripts/install-tor.mjs')) -ne 0) { Fail 'Tor installation failed (see above)' } }
  finally { Pop-Location }
}

# ---------------------------------------------------------------- 4. Ollama + model
Step 4 'Local sanitizer (Ollama)'
$ollama = $null
$cmd = Get-Command ollama -ErrorAction SilentlyContinue
if ($cmd) { $ollama = $cmd.Source }
elseif (Test-Path (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe')) { $ollama = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe' }
if (-not $ollama -and -not $SkipOllama) {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if ($winget) {
    Info 'installing Ollama with winget'
    Native $winget.Source @('install', '--id', 'Ollama.Ollama', '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements') | Out-Null
  } else {
    Info 'downloading the Ollama installer'
    $setup = Join-Path $Tmp 'OllamaSetup.exe'
    Download 'https://ollama.com/download/OllamaSetup.exe' $setup
    $sig = Get-AuthenticodeSignature $setup
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Ollama') { Fail 'the Ollama installer is not validly signed by Ollama' }
    Info ('signature valid: ' + $sig.SignerCertificate.Subject)
    Start-Process -FilePath $setup -ArgumentList '/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES' -Wait
  }
  $p = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
  if (Test-Path $p) { $ollama = $p }
}
if (-not $ollama) {
  Info 'Ollama not installed: the chat will ask for a local model before Private and Paranoid can send.'
} elseif (-not $SkipModel) {
  # the model server must answer before a pull
  $up = $false
  for ($i = 0; $i -lt 30 -and -not $up; $i++) {
    try { Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/version' -UseBasicParsing -TimeoutSec 2 | Out-Null; $up = $true }
    catch { if ($i -eq 0) { Start-Process -FilePath $ollama -ArgumentList 'serve' -WindowStyle Hidden }; Start-Sleep -Seconds 1 }
  }
  if (-not $Model) {
    $gb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    if ($gb -lt 16) { $Model = 'qwen3:4b' } else { $Model = 'qwen3:8b' }
    Info ("{0} GB of memory: using {1}" -f $gb, $Model)
  }
  Info ('downloading ' + $Model + ' (several GB, once)')
  # progress bars are redrawn on one line; run it in this console so they render normally
  $p = Start-Process -FilePath $ollama -ArgumentList 'pull', $Model -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -ne 0) { Fail ('could not download the model ' + $Model) }
  # preselect it as the sanitizer model, keeping any existing settings
  $cfg = Join-Path $DataDir 'config.json'
  & $node -e "const fs=require('fs');const f=process.argv[1];let c={};try{c=JSON.parse(fs.readFileSync(f,'utf8'))}catch{};c.sanitizer=Object.assign({},c.sanitizer,{model:process.argv[2]});fs.writeFileSync(f,JSON.stringify(c,null,2))" $cfg $Model
}

# ---------------------------------------------------------------- 5. shortcuts, autostart, uninstall entry
Step 5 'Shortcuts'
# values embedded in the generated scripts below, quoted for single-quoted strings
function Q($v) { $v -replace "'", "''" }
$nodeQ = Q $node
$mainQ = Q (Join-Path $AppDir 'src\main.ts')
$dirQ = Q $Dir
$launcher = @"
# Starts the PARANOID daemon in the background (if it is not already running) and opens the chat.
`$ErrorActionPreference = 'SilentlyContinue'
function Up { try { Invoke-WebRequest -Uri 'http://127.0.0.1:7700/healthz' -UseBasicParsing -TimeoutSec 2 | Out-Null; `$true } catch { `$false } }
if (-not (Up)) {
  `$log = Join-Path `$env:APPDATA 'paranoid\daemon.log'
  Start-Process -FilePath '$nodeQ' -ArgumentList ('"' + '$mainQ' + '"') -WorkingDirectory (Split-Path '$mainQ' | Split-Path) -WindowStyle Hidden -RedirectStandardError `$log -RedirectStandardOutput (`$log + '.out')
  for (`$i = 0; `$i -lt 60 -and -not (Up); `$i++) { Start-Sleep -Milliseconds 500 }
}
if (`$args -notcontains '-NoBrowser') { Start-Process 'http://127.0.0.1:7700/' }
"@
$stopper = @"
# Stops the PARANOID daemon and the Tor process it supervises.
Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" | Where-Object { `$_.CommandLine -like ('*' + '$mainQ' + '*') } | ForEach-Object { Stop-Process -Id `$_.ProcessId -Force }
Get-Process tor -ErrorAction SilentlyContinue | Where-Object { `$_.Path -like (Join-Path `$env:APPDATA 'paranoid\tor\*') } | Stop-Process -Force
"@
$uninstaller = @"
# Removes PARANOID. Your settings, keys and Tor data in %APPDATA%\paranoid are kept unless you pass -RemoveData.
param([switch]`$RemoveData)
& (Join-Path '$dirQ' 'Stop-PARANOID.ps1')
`$sm = Join-Path ([Environment]::GetFolderPath('Programs')) 'PARANOID'
Remove-Item -Recurse -Force `$sm -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Startup')) 'PARANOID.lnk') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PARANOID' -ErrorAction SilentlyContinue
if (`$RemoveData) { Remove-Item -Recurse -Force (Join-Path `$env:APPDATA 'paranoid') -ErrorAction SilentlyContinue }
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',"Start-Sleep 2; Remove-Item -Recurse -Force '$dirQ'"
Write-Host 'PARANOID removed.'
"@
Set-Content -Path (Join-Path $Dir 'PARANOID.ps1') -Value $launcher -Encoding UTF8
Set-Content -Path (Join-Path $Dir 'Stop-PARANOID.ps1') -Value $stopper -Encoding UTF8
Set-Content -Path (Join-Path $Dir 'uninstall.ps1') -Value $uninstaller -Encoding UTF8
$ico = Join-Path $Dir 'paranoid.ico'
try { Download ($Source + '/brand/paranoid.ico') $ico } catch { $ico = $null }

$shell = New-Object -ComObject WScript.Shell
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Shortcut($path, $script, $extra, $desc) {
  $s = $shell.CreateShortcut($path)
  $s.TargetPath = $ps
  $s.Arguments = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" {1}' -f $script, $extra).Trim()
  $s.WorkingDirectory = $Dir
  $s.Description = $desc
  if ($ico) { $s.IconLocation = $ico }
  $s.WindowStyle = 7
  $s.Save()
}
$sm = Join-Path ([Environment]::GetFolderPath('Programs')) 'PARANOID'
New-Item -ItemType Directory -Force -Path $sm | Out-Null
Shortcut (Join-Path $sm 'PARANOID.lnk') (Join-Path $Dir 'PARANOID.ps1') '' 'Open the PARANOID private AI chat'
Shortcut (Join-Path $sm 'Stop PARANOID.lnk') (Join-Path $Dir 'Stop-PARANOID.ps1') '' 'Stop the PARANOID daemon and Tor'
$startup = Join-Path ([Environment]::GetFolderPath('Startup')) 'PARANOID.lnk'
if ($NoAutostart) { Remove-Item -Force $startup -ErrorAction SilentlyContinue; Info 'start at sign-in: off' }
else { Shortcut $startup (Join-Path $Dir 'PARANOID.ps1') '-NoBrowser' 'Start PARANOID at sign-in'; Info 'start at sign-in: on' }

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PARANOID'
New-Item -Force -Path $key | Out-Null
$version = (Get-Content (Join-Path $AppDir 'package.json') -Raw | ConvertFrom-Json).version
Set-ItemProperty -Path $key -Name DisplayName -Value 'PARANOID'
Set-ItemProperty -Path $key -Name DisplayVersion -Value $version
Set-ItemProperty -Path $key -Name Publisher -Value 'PARANOID'
Set-ItemProperty -Path $key -Name URLInfoAbout -Value 'https://www.paranoid.family'
Set-ItemProperty -Path $key -Name InstallLocation -Value $Dir
Set-ItemProperty -Path $key -Name UninstallString -Value ('"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $ps, (Join-Path $Dir 'uninstall.ps1'))
Set-ItemProperty -Path $key -Name NoModify -Value 1 -Type DWord
Set-ItemProperty -Path $key -Name NoRepair -Value 1 -Type DWord
if ($ico) { Set-ItemProperty -Path $key -Name DisplayIcon -Value $ico }
Info 'Start Menu: PARANOID, Stop PARANOID; Settings > Apps: PARANOID'

Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'PARANOID is installed.' -ForegroundColor Green
Write-Host 'Next: in the chat, open Settings and add your OpenRouter key (or connect the zkAPI wallet).' -ForegroundColor DarkGray
if (-not $NoLaunch) { & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Dir 'PARANOID.ps1') }
