<#
  vps2vpn one-click deployer for Windows 10/11. Needs nothing extra: PowerShell, tar.exe and ssh.exe ship with Windows.
  Double-click deploy-windows.bat. Fill in the server IP, drop the SSH key file (or the whole .ssh folder) on the
  window or type the root password, press the button. Everything else is automatic: the server creates the admin
  login and your first account, the firewall is checked from this computer, your VPN app (Clash Verge, FlClash...)
  is opened with the subscription, and a second server can be added to the first one.
  Logins are saved only on this computer, in %USERPROFILE%\vps2vpn\<server>.json.

  Headless (used for testing, prints no secrets and never opens the VPN app):
    powershell -File deploy\deploy.ps1 -Headless -Server 203.0.113.10 [-Key file | -Pass pw] [-User root] [-Port 22] [-Main 198.51.100.7]
#>
param(
  [switch]$Headless,
  [string]$Server = '',
  [string]$Key = '',
  [string]$Pass = '',
  [string]$User = 'root',
  [int]$Port = 22,
  [string]$Main = '',
  [switch]$PackageOnly,
  [switch]$UiSmokeTest
)
$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
function Restrict-Path([string]$p) {
  # only this Windows account may read it (ssh refuses keys others can read; logins stay private)
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $grant = if (Test-Path -LiteralPath $p -PathType Container) { "*${sid}:(OI)(CI)F" } else { "*${sid}:F" }
  & icacls.exe $p /inheritance:r /grant:r $grant | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls.exe failed on $p (exit $LASTEXITCODE)" }
}

function Test-SafeUrl([string]$url, [string[]]$schemes) {
  if ([string]::IsNullOrWhiteSpace($url)) { return $false }
  if ($url.StartsWith('-') -or $url -match '[\x00-\x20\x7f]') { return $false }
  $uri = $null
  if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri)) { return $false }
  $sc = $uri.Scheme.ToLowerInvariant()
  if ($schemes -notcontains $sc) { return $false }
  if (($sc -eq 'http' -or $sc -eq 'https') -and [string]::IsNullOrEmpty($uri.Host)) { return $false }
  return $true
}

function Assert-Target([string]$h, [string]$u, [int]$p) {
  if ($h -notmatch '^[A-Za-z0-9.:-]{3,255}$' -or $h.StartsWith('-')) { throw '先填服务器 IP（只能是 IP 或域名）。' }
  if ($u -notmatch '^[a-z_][a-z0-9_.-]{0,31}$') { throw '用户名不对。' }
  if ($p -lt 1 -or $p -gt 65535) { throw 'SSH 端口必须在 1 到 65535 之间。' }
}

$Work = Join-Path ([IO.Path]::GetTempPath()) ('v2v-deploy-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $Work | Out-Null
Restrict-Path $Work
$Records = if ($env:V2V_RECORDS) { $env:V2V_RECORDS } else { Join-Path $env:USERPROFILE 'vps2vpn' }
$ClientDownload = 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest'
# Windows' own tools (Git and other toolkits put different tar/ssh builds on PATH)
function Find-Tool([string]$name, [string[]]$candidates) {
  foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
  $g = Get-Command $name -ErrorAction SilentlyContinue
  if ($g) { return $g.Source }
  return $null
}
$Sys = Join-Path $env:SystemRoot 'System32'
$TarExe = Find-Tool 'tar.exe' @((Join-Path $Sys 'tar.exe'))
$SshExe = Find-Tool 'ssh.exe' @((Join-Path $Sys 'OpenSSH\ssh.exe'), (Join-Path $env:ProgramFiles 'OpenSSH\ssh.exe'))

# ---------------------------------------------------------------- core steps
function New-Payload {
  # tar the installer + panel code, then base64 on ONE line (GNU base64 -d rejects CR characters)
  $tgz = Join-Path $Work 'v.tgz'
  & $TarExe -czf $tgz -C $Repo --exclude=__pycache__ --exclude=*.pyc install.sh vps2vpn
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tgz)) { throw 'tar.exe failed to pack the files' }
  $b64 = Join-Path $Work 'v.b64'
  [IO.File]::WriteAllText($b64, [Convert]::ToBase64String([IO.File]::ReadAllBytes($tgz)) + "`n", [Text.Encoding]::ASCII)
  return $b64
}

function Find-KeyFile([string]$p) {
  # Accept a key file, or a folder such as .ssh: take the usual private key inside it.
  if (Test-Path -LiteralPath $p -PathType Container) {
    foreach ($n in 'id_ed25519', 'id_ecdsa', 'id_rsa') {
      $c = Join-Path $p $n
      if (Test-Path -LiteralPath $c) { return $c }
    }
    $pem = Get-ChildItem -LiteralPath $p -File | Where-Object { $_.Extension -in '.pem', '.key' } | Select-Object -First 1
    if ($pem) { return $pem.FullName }
    return $null
  }
  if ((Get-Item -LiteralPath $p).Length -gt 32768) { return $null }
  return $p
}

function Copy-Key([string]$src) {
  # Windows ssh refuses keys that other accounts can read, so use a private copy (deleted afterwards).
  $dst = Join-Path $Work 'key'
  $text = [IO.File]::ReadAllText($src) -replace "`r`n", "`n"
  if ($text -notmatch 'PRIVATE KEY') { throw '这不是私钥文件（里面没有 PRIVATE KEY）。请拖入 .pem / .key / id_ed25519 这类文件。' }
  if (-not $text.EndsWith("`n")) { $text += "`n" }
  [IO.File]::WriteAllText($dst, $text, (New-Object Text.UTF8Encoding($false)))
  Restrict-Path $dst
  return $dst
}

function Get-KnownHostsFile {
  # Server keys are remembered next to the saved logins (the same file deploy.py uses), so a server whose
  # key changed since the last deploy is refused instead of trusted again.
  if (-not (Test-Path -LiteralPath $Records)) { New-Item -ItemType Directory -Force $Records | Out-Null; Restrict-Path $Records }
  return (Join-Path $Records 'known_hosts')
}

function Get-KnownHostName { if ($Port -eq 22) { $Server } else { "[$Server]:$Port" } }

function Get-SshArgs([string]$keyPath, [bool]$usePassword) {
  # ssh splits this value on spaces (a list of files) and expands %-tokens in it: keep the quotes all the way
  # to ssh (\" survives the Windows command line) and double every %.
  $kh = (Get-KnownHostsFile) -replace '%', '%%'
  $a = @('-F', 'none', '-p', "$Port", '-o', 'StrictHostKeyChecking=accept-new', '-o', (Quote-Arg "UserKnownHostsFile=`"$kh`""),
    '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8')
  if ($keyPath) { $a += @('-i', "`"$keyPath`"", '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes') }
  elseif ($usePassword) {
    $a += @('-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no',
      '-o', 'NumberOfPasswordPrompts=1')
  }
  return $a + @('--', "$User@$Server")
}

function Set-AskPass([string]$pw) {
  # ssh asks this helper for the password; the password itself only lives in an environment variable.
  $helper = Join-Path $Work 'askpass.cmd'
  $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  [IO.File]::WriteAllText($helper, "@`"$psExe`" -NoProfile -NonInteractive -Command `"[Console]::Out.WriteLine(`$env:V2V_PW)`"`r`n")
  $env:V2V_PW = $pw
  $env:SSH_ASKPASS = $helper
  $env:SSH_ASKPASS_REQUIRE = 'force'
  if (-not $env:DISPLAY) { $env:DISPLAY = ':0' }
}

function Test-SshVersionForPassword {
  $v = (& $SshExe -V 2>&1 | Out-String)
  if ($v -match 'OpenSSH_for_Windows_(\d+)\.(\d+)') {
    return ([int]$Matches[1] -gt 8) -or ([int]$Matches[1] -eq 8 -and [int]$Matches[2] -ge 4)
  }
  return $true
}

function Quote-Arg([string]$s) { '"' + (($s -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }

function Start-Ssh([string[]]$sshArgs, [string]$remote, [string]$stdinFile) {
  $out = Join-Path $Work ('out-' + [Guid]::NewGuid().ToString('N').Substring(0, 6) + '.txt')
  $err = $out + '.err'
  if (-not $stdinFile) { $stdinFile = Join-Path $Work 'empty.txt'; [IO.File]::WriteAllText($stdinFile, '') }
  $argLine = ($sshArgs -join ' ') + ' ' + (Quote-Arg $remote)
  $p = Start-Process -FilePath $SshExe -ArgumentList $argLine -RedirectStandardInput $stdinFile `
    -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden -PassThru
  $null = $p.Handle      # keep the handle, or ExitCode reads as empty once the process has finished
  return @{ Proc = $p; Out = $out; Err = $err; Pos = 0; ErrPos = 0; Text = ''; Pending = '' }
}

function Read-New($job) {
  # new text the process wrote since last time (stdout and stderr)
  $txt = ''
  foreach ($k in @(@('Out', 'Pos'), @('Err', 'ErrPos'))) {
    $f = $job[$k[0]]
    if (-not (Test-Path $f)) { continue }
    $fs = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite')
    try {
      if ($fs.Length -gt $job[$k[1]]) {
        $fs.Position = $job[$k[1]]
        $buf = New-Object byte[] ($fs.Length - $job[$k[1]])
        $n = $fs.Read($buf, 0, $buf.Length)
        $job[$k[1]] += $n
        $txt += [Text.Encoding]::UTF8.GetString($buf, 0, $n)
      }
    } finally { $fs.Close() }
  }
  return ($txt -replace "\x1b\[[0-9;]*m", '')
}

function Get-ShowLines($job, [string]$t, [bool]$final) {
  # Complete lines to show in the log. The result line holds the new admin password, so it is never shown.
  $job.Pending += $t
  $parts = $job.Pending -split "`n"
  if ($final) { $job.Pending = '' }
  elseif ($parts.Count -le 1) { return '' }
  else { $job.Pending = $parts[-1]; $parts = $parts[0..($parts.Count - 2)] }
  $keep = @($parts | Where-Object { $_ -notmatch '^V2V_RESULT:' })
  if ($keep.Count -eq 0) { return '' }
  return (($keep -join "`n") + $(if ($final) { '' } else { "`n" }))
}

function Get-Result([string]$text) {
  $m = [regex]::Match($text, '(?m)^V2V_RESULT:([A-Za-z0-9+/=]+)')
  if (-not $m.Success) { return $null }
  try {
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.Groups[1].Value))
    return ($json | ConvertFrom-Json)
  } catch { return $null }
}

function Explain([string]$msg) {
  if ($msg -match 'Permission denied') { $msg += "`r`n→ 密钥或密码不对，或者用户名不对（亚马逊一般是 ubuntu / ec2-user / admin）。" }
  if ($msg -match 'timed out|Connection refused|No route') { $msg += "`r`n→ 连不上服务器的 $Port 端口：检查 IP 是否写对、服务器是否开机、云厂商防火墙是否放行 SSH。" }
  if ($msg -match 'Could not resolve') { $msg += "`r`n→ 服务器地址写错了。" }
  if ($msg -match 'sudo') { $msg += "`r`n→ 这个用户不能免密码使用 sudo，请改用 root 登录。" }
  if ($msg -match 'bad permissions|UNPROTECTED') { $msg += "`r`n→ 密钥文件权限问题，请把密钥文件复制到桌面再拖进来。" }
  if ($msg -match 'IDENTIFICATION HAS CHANGED|Host key verification failed') {
    $msg += "`r`n→ 这台服务器的身份和上次连接时不一样。如果你刚重装过系统或换了同一个 IP 的新服务器，这是正常的：运行  ssh-keygen -R $(Get-KnownHostName) -f `"$(Join-Path $Records 'known_hosts')`"  后再部署一次。没有重装过就先别继续，可能有人在冒充你的服务器。"
  }
  return $msg
}

function Remove-Secrets {
  Remove-Item Env:V2V_PW, Env:SSH_ASKPASS, Env:SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $Work 'key'), (Join-Path $Work 'askpass.cmd') -Force -ErrorAction SilentlyContinue
  # the installer's output (it contains the result line) is not needed once read
  Get-ChildItem -LiteralPath $Work -Filter 'out-*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

$Sudo = { if ($User -eq 'root') { '' } else { 'sudo -n ' } }
$ProbeCmd = { 'echo connected; uname -sm; ' + (& $Sudo) + 'id -u' }
$InstallCmd = {
  $runAs = if ($User -eq 'root') { '' } else { 'sudo -n env ' }
  'set -e; T=$(mktemp -d); trap ''rm -rf "$T"'' EXIT; base64 -d > "$T/v.tgz"; tar -xzf "$T/v.tgz" -C "$T"; ' + $runAs +
  'V2V_AUTO=1 V2V_SRC="$T/v.tgz" bash "$T/install.sh" install'
}

function Check-Prereqs {
  if (-not $SshExe) {
    throw '这台电脑没有 ssh 程序。Windows 10/11：设置 > 应用 > 可选功能 > 添加「OpenSSH 客户端」，然后再试。'
  }
  if (-not $TarExe) { throw '没有 tar.exe（需要 Windows 10 1803 或更新）。' }
}

# ---------------------------------------------------------------- saved servers (only on this computer)
function Get-RecordPath([string]$h) { Join-Path $Records (($h -replace '[^A-Za-z0-9._-]', '_') + '.json') }

function Get-Record([string]$h) {
  $p = Get-RecordPath $h
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return ([IO.File]::ReadAllText($p, [Text.Encoding]::UTF8) | ConvertFrom-Json) } catch { return $null }
}

function Get-Records {
  if (-not (Test-Path -LiteralPath $Records)) { return @() }
  $out = @()
  foreach ($f in Get-ChildItem -LiteralPath $Records -Filter '*.json' -File) {
    try { $r = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8) | ConvertFrom-Json; if ($r.host) { $out += $r } } catch {}
  }
  return $out
}

function Merge-Record($res, [string]$mainHost) {
  # an upgrade brings no new password, so the one saved earlier is kept
  $a = $res.auto
  $rec = [ordered]@{}
  $old = Get-Record $Server
  if ($old) { foreach ($p in $old.PSObject.Properties) { $rec[$p.Name] = $p.Value } }
  foreach ($k in 'panel', 'pin', 'join_code', 'name', 'user', 'sub_url', 'qr_url', 'links', 'checks', 'ai') {
    if ($null -ne $a.$k) { $rec[$k] = $a.$k }
  }
  if ($a.admin_password) { $rec['admin_user'] = $a.admin_user; $rec['admin_password'] = $a.admin_password }
  $rec['host'] = $Server; $rec['ssh_user'] = $User; $rec['ssh_port'] = $Port
  $rec['cloud'] = "$($res.cloud)"; $rec['cloud_firewall'] = "$($res.cloud_firewall)"
  $rec['updated'] = (Get-Date -Format 'yyyy-MM-dd HH:mm')
  $rec['说明'] = 'vps2vpn 一键部署工具保存的登录信息。只在你自己的电脑上，不要发给别人。'
  if ($mainHost -and $mainHost -ne $Server) { $rec['main'] = $mainHost }
  return $rec
}

function Save-Record($rec) {
  if (-not (Test-Path -LiteralPath $Records)) { New-Item -ItemType Directory -Force $Records | Out-Null; Restrict-Path $Records }
  $p = Get-RecordPath $Server
  $tmp = $p + '.' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp'
  try {
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $rec -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Restrict-Path $tmp
    Move-Item -LiteralPath $tmp -Destination $p -Force
    Restrict-Path $p
  } catch {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    throw
  }
  return $p
}

# ---------------------------------------------------------------- firewall check from the outside
function Test-Tcp([string]$h, [int]$p) {
  $fam = if ($h -match ':') { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
  $c = New-Object Net.Sockets.TcpClient($fam)
  try { $t = $c.ConnectAsync($h, $p); return ($t.Wait(5000) -and $c.Connected) } catch { return $false } finally { $c.Close() }
}

function Test-Quic([string]$h, [int]$p) {
  # A QUIC packet with an unknown version: Hysteria 2 and TUIC answer "version negotiation",
  # which proves the UDP port is open all the way through the cloud firewall.
  $pkt = New-Object byte[] 1200
  $rnd = New-Object byte[] 16
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
  $pkt[0] = 0xC3; $pkt[1] = 0x1a; $pkt[2] = 0x2a; $pkt[3] = 0x3a; $pkt[4] = 0x4a; $pkt[5] = 8; $pkt[14] = 8
  [Array]::Copy($rnd, 0, $pkt, 6, 8); [Array]::Copy($rnd, 8, $pkt, 15, 8)
  $fam = if ($h -match ':') { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }
  $u = New-Object Net.Sockets.UdpClient($fam)
  $u.Client.ReceiveTimeout = 3000
  try {
    for ($i = 0; $i -lt 2; $i++) {
      try {
        [void]$u.Send($pkt, $pkt.Length, $h, $p)
        $ep = New-Object Net.IPEndPoint($(if ($h -match ':') { [Net.IPAddress]::IPv6Any } else { [Net.IPAddress]::Any }), 0)
        $d = $u.Receive([ref]$ep)
        if ($d.Length -ge 7 -and ($d[0] -band 0x80) -and $d[1] -eq 0 -and $d[2] -eq 0 -and $d[3] -eq 0 -and $d[4] -eq 0) { return $true }
      } catch {}
    }
  } finally { $u.Close() }
  return $false
}

function Check-Ports($checks) {
  $out = @()
  foreach ($c in @($checks)) {
    if ($null -eq $c -or $c.Count -lt 3) { continue }
    $proto = "$($c[0])".ToLowerInvariant()
    if ($proto -notin 'tcp', 'udp') { continue }
    $port = 0
    if (-not [int]::TryParse("$($c[1])", [ref]$port) -or $port -lt 1 -or $port -gt 65535) { continue }
    $out += [pscustomobject]@{ proto = $proto; port = $port; name = "$($c[2])"; ok = $false }
  }
  if ($out.Count -eq 0) { return $out }
  for ($round = 0; $round -lt 3; $round++) {     # the services were only just started
    foreach ($c in $out | Where-Object { -not $_.ok }) {
      $c.ok = if ($c.proto -eq 'tcp') { Test-Tcp $Server $c.port } else { Test-Quic $Server $c.port }
      if (-not $Headless) { [Windows.Forms.Application]::DoEvents() }
    }
    if (-not ($out | Where-Object { -not $_.ok })) { break }
    if ($round -lt 2) { Start-Sleep -Seconds 3 }
  }
  return $out
}

# ---------------------------------------------------------------- the VPN app on this computer
function Find-Client {
  # Which installed app opens vps2vpn:// or clash:// (or hiddify:// / sing-box://) links. Only reads the registry.
  $names = @(@('vps2vpn', 'vps2vpn'), @('clash-verge', 'Clash Verge'), @('clash verge', 'Clash Verge'), @('flclash', 'FlClash'),
    @('mihomo', 'Mihomo Party'), @('nyanpasu', 'Clash Nyanpasu'), @('clash for windows', 'Clash for Windows'),
    @('hiddify', 'Hiddify'), @('sing-box', 'sing-box'))
  foreach ($s in @(@('vps2vpn', 'vps2vpn'), @('clash', 'clash'), @('hiddify', 'hiddify'), @('sing-box', 'singbox'))) {
    foreach ($root in 'HKCU:', 'HKLM:') {
      $k = "$root\Software\Classes\$($s[0])\shell\open\command"
      if (-not (Test-Path $k)) { continue }
      $cmd = (Get-ItemProperty $k).'(default)'
      if ($cmd -match '^\s*"?([^"]+?\.exe)' -and (Test-Path -LiteralPath $Matches[1])) {
        $exe = [IO.Path]::GetFileNameWithoutExtension($Matches[1])
        $name = $exe
        foreach ($n in $names) { if ($exe.ToLower().Contains($n[0])) { $name = $n[1]; break } }
        return [pscustomobject]@{ name = $name; link = $s[1] }
      }
    }
  }
  return $null
}

# ---------------------------------------------------------------- adding a server to one deployed before
if (-not ('V2VHttp' -as [type])) {
  Add-Type -TypeDefinition @'
using System; using System.IO; using System.Net; using System.Net.Security; using System.Text;
using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates;
public static class V2VHttp {
  // POST to a panel. The certificate must be one any browser trusts, or the one saved at deploy time.
  public static string[] Post(string url, string body, string cookie, string pin) {
    Uri u = new Uri(url);
    if (!String.Equals(u.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
      throw new ArgumentException("Only https:// panel URLs are allowed.");
    }
    ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(u);
    req.AllowAutoRedirect = false;
    req.ServerCertificateValidationCallback = delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) {
      if (e == SslPolicyErrors.None) return true;
      if (String.IsNullOrEmpty(pin) || c == null) return false;
      using (SHA256 sha = SHA256.Create()) {
        byte[] h = sha.ComputeHash(c.GetRawCertData());
        return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant() == pin;
      }
    };
    req.Method = "POST"; req.ContentType = "application/json"; req.Timeout = 30000;
    req.Headers["X-V2V"] = "1";
    if (!String.IsNullOrEmpty(cookie)) req.Headers["Cookie"] = cookie;
    byte[] b = Encoding.UTF8.GetBytes(body);
    using (Stream w = req.GetRequestStream()) { w.Write(b, 0, b.Length); }
    HttpWebResponse r;
    try { r = (HttpWebResponse)req.GetResponse(); }
    catch (WebException we) { if (we.Response == null) throw; r = (HttpWebResponse)we.Response; }
    using (r) {
      string text; using (StreamReader sr = new StreamReader(r.GetResponseStream(), Encoding.UTF8)) { text = sr.ReadToEnd(); }
      string sc = r.Headers["Set-Cookie"] ?? "";
      return new string[] { ((int)r.StatusCode).ToString(), text, sc.Split(';')[0] };
    }
  }
}
'@
}

function Invoke-Panel($rec, [string]$path, $body, [string]$cookie = '') {
  $base = [string]$rec.panel
  if (-not (Test-SafeUrl $base @('https'))) { throw '主服务器的面板地址无效。' }
  $url = $base.TrimEnd('/') + '/api/' + $path
  try { $r = [V2VHttp]::Post($url, (ConvertTo-Json -InputObject $body -Compress), $cookie, "$($rec.pin)") }
  catch {
    $detail = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
    throw ('连不上主服务器的面板，或者它的证书和部署时记下的不一样（' + $detail + '）')
  }
  $j = $null; try { $j = $r[1] | ConvertFrom-Json } catch {}
  return @{ Status = [int]$r[0]; Json = $j; Cookie = $r[2] }
}

function Join-Main($mainRec, $rec) {
  # log in to the main server's panel and paste this server's join code there
  if (-not $mainRec.admin_password) { throw '没有保存主服务器的面板密码。' }
  $r = Invoke-Panel $mainRec 'login' @{ username = "$($mainRec.admin_user)"; password = "$($mainRec.admin_password)" }
  if ($r.Status -eq 403 -and $r.Json.error -eq 'totp_required') { return 'totp' }
  if ($r.Status -ne 200 -or -not $r.Cookie) { throw ('登录主服务器失败：' + $r.Json.error + '（如果你改过面板密码，请到主面板手动粘贴加入码）') }
  $r2 = Invoke-Panel $mainRec 'servers' @{ code = "$($rec['join_code'])"; name = $(if ($rec['name']) { "$($rec['name'])" } else { $Server }) } $r.Cookie
  if ($r2.Status -eq 200 -or "$($r2.Json.error)" -match 'already added') { return 'ok' }
  throw ('主服务器没能加上这台：' + $r2.Json.error)
}

# ---------------------------------------------------------------- after the install
function Complete-Deploy($res, [string]$mainHost, [bool]$noImport) {
  $rec = Merge-Record $res $mainHost
  $st = @{ Rec = $rec; File = (Save-Record $rec); Client = $null; Imported = $false; Join = ''; JoinMsg = ''; Ports = @(); NoImport = $noImport }
  try { $st.Client = Find-Client } catch {}
  Update-Checks $st
  return $st
}

function Update-Checks($st) {
  # firewall check, then the VPN app import and the join to the main server (both need the panel port)
  $rec = $st.Rec
  $st.Ports = @(Check-Ports $rec['checks'])
  $panelChecks = @($st.Ports | Where-Object { $_.name -eq '管理面板' })
  $panelOk = ($panelChecks.Count -gt 0) -and -not ($panelChecks | Where-Object { -not $_.ok })
  if ($panelOk -and $st.Client -and -not $st.Imported -and -not $rec['main'] -and -not $st.NoImport -and $rec['links']) {
    $link = [string]$rec['links'].($st.Client.link)
    if (-not $link -and $st.Client.link -eq 'vps2vpn') { $link = [string]$rec['links'].clash }
    if (Test-SafeUrl $link @('vps2vpn', 'clash', 'hiddify', 'sing-box')) {
      try { Start-Process $link; $st.Imported = $true } catch {}
    }
  }
  if ($rec['main'] -and $st.Join -ne 'ok') {
    if (-not $panelOk) { $st.Join = 'wait'; $st.JoinMsg = '先放行防火墙，再点「再检查一次」，会自动加入。' }
    else {
      try { $st.Join = Join-Main (Get-Record $rec['main']) $rec; $st.JoinMsg = '' }
      catch { $st.Join = 'fail'; $st.JoinMsg = $_.Exception.Message }
    }
  }
}

# ---------------------------------------------------------------- headless mode (tests)
if ($PackageOnly) {
  $b = New-Payload
  Write-Output ("payload {0} bytes" -f (Get-Item $b).Length)
  Remove-Item -Recurse -Force $Work
  exit 0
}
if ($Headless) {
  try {
    $Server = $Server.Trim().Trim('[', ']')
    $User = $User.Trim()
    Assert-Target $Server $User $Port
    Check-Prereqs
    if ($Main -and -not (Get-Record $Main).admin_password) { throw "no saved login for main server $Main" }
    $kp = $null
    if ($Key) { $kf = Find-KeyFile $Key; if (-not $kf) { throw 'no key file found' }; $kp = Copy-Key $kf }
    elseif ($Pass) { Set-AskPass $Pass }
    $a = Get-SshArgs $kp ([bool]$Pass)
    $j = Start-Ssh $a (& $ProbeCmd) $null
    $j.Proc.WaitForExit()
    $t = Read-New $j
    if ($t -notmatch 'connected') { throw (Explain $t.Trim()) }
    Write-Output $t.Trim()
    $j = Start-Ssh $a (& $InstallCmd) (New-Payload)
    while (-not $j.Proc.HasExited) {
      Start-Sleep -Milliseconds 300; $x = Read-New $j; $j.Text += $x
      $show = Get-ShowLines $j $x $false; if ($show) { Write-Host -NoNewline $show }
    }
    $x = Read-New $j; $j.Text += $x; Write-Host (Get-ShowLines $j $x $true)
    $res = Get-Result $j.Text
    Remove-Secrets
    if ($j.Proc.ExitCode -ne 0 -or -not $res) { throw "installer failed (exit $($j.Proc.ExitCode))" }
    $st = Complete-Deploy $res $Main $true
    $sum = [ordered]@{ ok = $true; record_file = $st.File; saved_password = [bool]$st.Rec['admin_password']
      has_sub_url = [bool]$st.Rec['sub_url']; client = $(if ($st.Client) { $st.Client.name } else { '' })
      join = $st.Join; join_msg = $st.JoinMsg; ports = $st.Ports
      name = "$($st.Rec['name'])"; ai = "$($st.Rec['ai'].summary)" }
    Write-Output (ConvertTo-Json -InputObject $sum -Depth 4 -Compress)
    exit 0
  } catch { Write-Output ('ERROR: ' + $_.Exception.Message); exit 2 }
  finally { Remove-Secrets; Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- window
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$font = New-Object Drawing.Font('Microsoft YaHei UI', 10)
$blue = [Drawing.Color]::FromArgb(37, 99, 235)
$gray = [Drawing.Color]::FromArgb(102, 112, 133)
$green = [Drawing.Color]::FromArgb(7, 148, 85)
$red = [Drawing.Color]::FromArgb(217, 45, 32)
$form = New-Object Windows.Forms.Form -Property @{
  Text = 'vps2vpn 一键部署'; Width = 600; Height = 760; StartPosition = 'CenterScreen'; Font = $font
  FormBorderStyle = 'FixedSingle'; MaximizeBox = $false; AllowDrop = $true; BackColor = [Drawing.Color]::White
}
function Add-Label($text, $y, $h = 22, $color = $null, $parent = $form) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = 20; Top = $y; Width = 545; Height = $h }
  if ($color) { $l.ForeColor = $color }
  $parent.Controls.Add($l); return $l
}
$title = Add-Label 'vps2vpn 一键部署' 14 34
$title.Font = New-Object Drawing.Font('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold)
Add-Label '把你买的服务器变成自己的 VPN：填 IP，拖入密钥文件（或填密码），点按钮，剩下的全自动。' 50 22 $gray | Out-Null

Add-Label '服务器 IP' 84 | Out-Null
$tbHost = New-Object Windows.Forms.TextBox -Property @{ Left = 20; Top = 108; Width = 545; Text = $Server }
$form.Controls.Add($tbHost)

Add-Label 'SSH 密钥文件（.pem / .key / id_ed25519，或整个 .ssh 文件夹）' 144 | Out-Null
$drop = New-Object Windows.Forms.Label -Property @{
  Left = 20; Top = 168; Width = 545; Height = 70; TextAlign = 'MiddleCenter'; BorderStyle = 'FixedSingle'
  Text = '把密钥文件拖到这个窗口里，或点这里选择'; AllowDrop = $true; Cursor = 'Hand'
  BackColor = [Drawing.Color]::FromArgb(245, 247, 250); ForeColor = $blue
}
$form.Controls.Add($drop)
$script:keyFile = $null

Add-Label '没有密钥文件？填服务器的登录密码' 250 | Out-Null
$tbPw = New-Object Windows.Forms.TextBox -Property @{ Left = 20; Top = 274; Width = 545; UseSystemPasswordChar = $true }
$form.Controls.Add($tbPw)

Add-Label '登录用户名' 310 22 $gray | Out-Null
$tbUser = New-Object Windows.Forms.TextBox -Property @{ Left = 20; Top = 334; Width = 260; Text = $User }
$form.Controls.Add($tbUser)
$lp = Add-Label 'SSH 端口' 310 22 $gray; $lp.Left = 305; $lp.Width = 260
$tbPort = New-Object Windows.Forms.TextBox -Property @{ Left = 305; Top = 334; Width = 260; Text = "$Port" }
$form.Controls.Add($tbPort)
Add-Label '（一般不用改。亚马逊 Lightsail/EC2 的用户名通常是 ubuntu、admin 或 ec2-user）' 362 22 $gray | Out-Null

# a second server can share the accounts of one deployed before
Add-Label '这台服务器怎么用' 392 22 $gray | Out-Null
$cbMain = New-Object Windows.Forms.ComboBox -Property @{ Left = 20; Top = 416; Width = 545; DropDownStyle = 'DropDownList' }
$form.Controls.Add($cbMain)
$script:mainHosts = @('')
[void]$cbMain.Items.Add('单独使用（第一台，或不想和别的服务器共用账号）')
foreach ($r in Get-Records) {
  if (-not $r.admin_password) { continue }
  [void]$cbMain.Items.Add("加到 $($r.host) 下面（共用账号，原来的订阅里自动多出这台）")
  $script:mainHosts += "$($r.host)"
}
$cbMain.SelectedIndex = 0

$btn = New-Object Windows.Forms.Button -Property @{
  Left = 20; Top = 456; Width = 545; Height = 44; Text = '一键部署'; FlatStyle = 'Flat'
  BackColor = $blue; ForeColor = [Drawing.Color]::White
  Font = New-Object Drawing.Font('Microsoft YaHei UI', 11, [Drawing.FontStyle]::Bold)
}
$form.Controls.Add($btn)

$status = Add-Label '' 510 22 $gray
$log = New-Object Windows.Forms.TextBox -Property @{
  Left = 20; Top = 536; Width = 545; Height = 140; Multiline = $true; ScrollBars = 'Vertical'; ReadOnly = $true
  Font = New-Object Drawing.Font('Consolas', 9); BackColor = [Drawing.Color]::FromArgb(245, 247, 250)
}
$form.Controls.Add($log)
Add-Label '密钥和密码只用于这一次连接，用完立刻删除。面板登录信息只保存在这台电脑的 vps2vpn 文件夹里。' 684 22 $gray | Out-Null

function Say([string]$t) { $log.AppendText(($t -replace "(?<!`r)`n", "`r`n")) }
function Take-Key([string]$p) {
  $k = Find-KeyFile $p
  if (-not $k) { [Windows.Forms.MessageBox]::Show('这里面没找到私钥文件。请拖入 .pem / .key / id_ed25519 文件。') | Out-Null; return }
  $script:keyFile = $k
  $drop.Text = '已选：' + (Split-Path -Leaf $k) + '    （点这里可以换一个）'
  if ($k -match 'Lightsail|\.pem$' -and $tbUser.Text -eq 'root') { $tbUser.Text = 'ubuntu' }
}
$onEnter = { param($s, $e) if ($e.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' } }
$onDrop = { param($s, $e) $f = $e.Data.GetData([Windows.Forms.DataFormats]::FileDrop); if ($f) { Take-Key $f[0] } }
foreach ($c in @($form, $drop)) { $c.Add_DragEnter($onEnter); $c.Add_DragDrop($onDrop) }
$drop.Add_Click({
  $d = New-Object Windows.Forms.OpenFileDialog -Property @{ Title = '选择 SSH 私钥文件'; Filter = '所有文件|*.*' }
  $sshDir = Join-Path $env:USERPROFILE '.ssh'
  if (Test-Path $sshDir) { $d.InitialDirectory = $sshDir }
  if ($d.ShowDialog() -eq 'OK') { Take-Key $d.FileName }
})

# ---------------------------------------------------------------- result window
function New-Btn([string]$text, $x, $y, $w, [scriptblock]$onClick, [bool]$primary = $false) {
  $b = New-Object Windows.Forms.Button -Property @{ Left = $x; Top = $y; Width = $w; Height = 34; Text = $text; FlatStyle = 'Flat' }
  if ($primary) { $b.BackColor = $blue; $b.ForeColor = [Drawing.Color]::White } else { $b.ForeColor = $blue }
  $b.Add_Click($onClick)
  return $b
}

function Copy-Text([string]$t, $b) { [Windows.Forms.Clipboard]::SetText($t); $b.Text = '已复制' }

function Fill-Result($p, $st) {
  $p.SuspendLayout(); $p.Controls.Clear()
  $rec = $st.Rec; $y = 10
  $h = Add-Label '✅ 部署成功' $y 34 $green $p
  $h.Font = New-Object Drawing.Font('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold); $y += 42
  if ($rec['main']) {
    $msg = switch ($st.Join) {
      'ok' { "已加入主服务器 $($rec['main'])：你在那边的订阅里会自动多出这台服务器（在 VPN 软件里点一下「更新订阅」）。" }
      'totp' { '主服务器开了两步验证，没法自动加入。请打开主服务器面板 → 多服务器 → 粘贴加入码（点下面的按钮复制）。' }
      'wait' { $st.JoinMsg }
      default { '没能自动加入主服务器：' + $st.JoinMsg + ' 可以打开主服务器面板 → 多服务器 → 粘贴加入码。' }
    }
    Add-Label $msg $y 66 $(if ($st.Join -eq 'ok') { $green } else { $red }) $p | Out-Null; $y += 70
    if ($st.Join -in 'totp', 'fail') {
      $p.Controls.Add((New-Btn '复制加入码' 20 $y 160 { Copy-Text "$($script:st.Rec['join_code'])" $this })); $y += 44
    }
  }
  $ai = $rec['ai']
  if ($ai -and $ai.summary) {
    $where = @($ai.place, $ai.org, $ai.kind) | Where-Object { $_ }
    $txt = "AI 可用性（从服务器测试）：$($ai.summary)`n" + ($where -join ' · ')
    if ($ai.advice) { $txt += "`n" + (@($ai.advice) -join "`n") }
    $txt += "`n结果只作参考；以后可以在管理面板 → 系统里重新检测。"
    Add-Label $txt $y 96 $null $p | Out-Null; $y += 100
  }
  if (-not $rec['main'] -and $rec['sub_url']) {
    $t = Add-Label '① 把 VPN 装到你的设备上' $y 24 $null $p; $t.Font = New-Object Drawing.Font('Microsoft YaHei UI', 10, [Drawing.FontStyle]::Bold); $y += 28
    if ($st.Client -and $st.Imported) {
      $m = "检测到你电脑上的 $($st.Client.name)，已经自动打开它导入。在它弹出的窗口点「确定/导入」，然后在软件里选中这个配置、打开「系统代理」开关就能用了。分流规则（国内网站直连、国外走代理）已经写好，不用自己设置。"
      Add-Label $m $y 66 $green $p | Out-Null; $y += 70
    } elseif ($st.Client) {
      Add-Label "检测到你电脑上的 $($st.Client.name)。防火墙放行后会自动导入，也可以直接点下面的按钮。" $y 44 $null $p | Out-Null; $y += 48
    } else {
      Add-Label '没检测到电脑上的 VPN 软件。推荐装免费开源的 Clash Verge Rev（下载名字里带 setup 的 .exe），装好后回来点「导入到 Clash」。' $y 44 $red $p | Out-Null; $y += 48
      $p.Controls.Add((New-Btn '打开 Clash Verge 下载页' 20 $y 220 { if (Test-SafeUrl $ClientDownload @('https')) { Start-Process $ClientDownload } })); $y += 42
    }
    $label = if ($st.Client) { $(if ($st.Imported) { '再导入一次到 ' } else { '导入到 ' }) + $st.Client.name } else { '导入到 Clash' }
    $p.Controls.Add((New-Btn $label 20 $y 175 {
      $l = $script:st.Rec['links']; $k = if ($script:st.Client) { $script:st.Client.link } else { 'clash' }
      $target = [string]($l.$k)
      if (-not $target -and $k -eq 'vps2vpn') { $target = [string]($l.clash) }
      if (-not (Test-SafeUrl $target @('vps2vpn', 'clash', 'hiddify', 'sing-box'))) { [Windows.Forms.MessageBox]::Show('导入链接无效。') | Out-Null; return }
      try { Start-Process $target } catch { [Windows.Forms.MessageBox]::Show('打不开。请先装好 Clash Verge 或 FlClash。') | Out-Null }
    } $true))
    $p.Controls.Add((New-Btn '手机扫码（打开订阅页）' 203 $y 190 {
      $u = "$($script:st.Rec['sub_url'])"
      if (Test-SafeUrl $u @('http', 'https')) { Start-Process $u }
    }))
    $p.Controls.Add((New-Btn '复制订阅链接' 401 $y 145 { Copy-Text "$($script:st.Rec['sub_url'])" $this })); $y += 46
  }
  $t = Add-Label $(if ($rec['main']) { '防火墙检查（从你这台电脑测试）' } else { '② 防火墙检查（从你这台电脑测试）' }) $y 24 $null $p
  $t.Font = New-Object Drawing.Font('Microsoft YaHei UI', 10, [Drawing.FontStyle]::Bold); $y += 28
  foreach ($c in $st.Ports) {
    $l = Add-Label ("{0}   {1} {2}" -f $c.name, $c.proto.ToUpper(), $c.port) $y 22 $null $p; $l.Width = 400
    $r = Add-Label $(if ($c.ok) { '✓ 通了' } else { '✗ 不通' }) $y 22 $(if ($c.ok) { $green } else { $red }) $p; $r.Left = 440; $r.Width = 110
    $y += 24
  }
  $bad = @($st.Ports | Where-Object { -not $_.ok })
  if ($bad.Count) {
    $how = if ($rec['cloud_firewall']) { "这台在 $($rec['cloud']) 上。$($rec['cloud_firewall'])" } else { '请到云服务商的网页控制台，找「防火墙 / 安全组」，添加一条规则：协议选「全部/所有」，来源 0.0.0.0/0。' }
    Add-Label ('有端口被云服务商的防火墙挡住了。' + $how) $y 88 $red $p | Out-Null; $y += 92
    $p.Controls.Add((New-Btn '我已放行，再检查一次' 20 $y 220 {
      $this.Enabled = $false; $this.Text = '正在检查…'; [Windows.Forms.Application]::DoEvents()
      Update-Checks $script:st; Fill-Result $script:resPanel $script:st
    } $true)); $y += 44
  } elseif ($st.Ports.Count) { Add-Label '全部通了，可以用了。' $y 22 $green $p | Out-Null; $y += 26 }
  $t = Add-Label $(if ($rec['main']) { '管理面板（加用户、看流量）' } else { '③ 管理面板（加用户、看流量）' }) $y 24 $null $p
  $t.Font = New-Object Drawing.Font('Microsoft YaHei UI', 10, [Drawing.FontStyle]::Bold); $y += 28
  Add-Label ('地址：' + $rec['panel']) $y 22 $null $p | Out-Null; $y += 24
  $pwText = if ($rec['admin_password']) { '用户名：' + $rec['admin_user'] + '      密码：已保存（点「复制密码」）' } else { '用户名和密码：用你自己设置的那个' }
  Add-Label $pwText $y 22 $null $p | Out-Null; $y += 28
  $p.Controls.Add((New-Btn '打开面板' 20 $y 120 {
    $u = "$($script:st.Rec['panel'])"
    if (Test-SafeUrl $u @('https')) { Start-Process $u }
  } $true))
  if ($rec['admin_password']) { $p.Controls.Add((New-Btn '复制密码' 148 $y 120 { Copy-Text "$($script:st.Rec['admin_password'])" $this })) }
  $p.Controls.Add((New-Btn '打开保存的文件夹' 276 $y 160 { Start-Process explorer.exe -ArgumentList "`"$Records`"" })); $y += 44
  Add-Label ('浏览器若提示「不安全」，点「高级 → 继续访问」即可（照样加密）。登录信息保存在：' + $st.File) $y 44 $gray $p | Out-Null
  $p.ResumeLayout()
}

function Show-Result($st) {
  $script:st = $st
  $rf = New-Object Windows.Forms.Form -Property @{
    Text = 'vps2vpn 部署成功'; Width = 600; Height = 740; StartPosition = 'CenterScreen'; Font = $font
    FormBorderStyle = 'FixedSingle'; MaximizeBox = $false; BackColor = [Drawing.Color]::White
  }
  $script:resPanel = New-Object Windows.Forms.Panel -Property @{ Dock = 'Fill'; AutoScroll = $true }
  $rf.Controls.Add($script:resPanel)
  Fill-Result $script:resPanel $st
  [void]$rf.ShowDialog($form)
}

$timer = New-Object Windows.Forms.Timer -Property @{ Interval = 300 }
$script:job = $null; $script:stage = ''; $script:sshArgs = $null; $script:main = ''

function Finish([bool]$ok, [string]$msg) {
  $timer.Stop()
  $btn.Enabled = $true; $btn.Text = '一键部署'
  if ($ok) {
    $res = Get-Result $script:job.Text
    $script:job.Text = ''
    Remove-Secrets
    $status.Text = '装好了，正在从这台电脑检查防火墙…'; [Windows.Forms.Application]::DoEvents()
    try { $st = Complete-Deploy $res $script:main $false }
    catch { $status.Text = ''; [Windows.Forms.MessageBox]::Show('装好了，但保存或检查时出错：' + $_.Exception.Message, 'vps2vpn') | Out-Null; return }
    $status.Text = '完成。'
    Show-Result $st
  } else {
    Remove-Secrets
    $status.Text = ''
    Say ("`n出错了：" + $msg + "`n")
    [Windows.Forms.MessageBox]::Show($msg, 'vps2vpn') | Out-Null
  }
}

$timer.Add_Tick({
  $j = $script:job
  $t = Read-New $j
  if ($t) {
    $j.Text += $t
    if ($script:stage -eq 'install') { $show = Get-ShowLines $j $t $false; if ($show) { Say $show } }
  }
  if (-not $j.Proc.HasExited) { return }
  $t = Read-New $j; $j.Text += $t
  if ($script:stage -eq 'probe') {
    if ($j.Text -notmatch 'connected') { Finish $false (Explain $j.Text.Trim()); return }
    Say ($j.Text.Trim() + "`n正在上传并安装（1-3 分钟，请别关窗口）…`n")
    $status.Text = '正在安装，大约 1-3 分钟…'
    $script:stage = 'install'
    $script:job = Start-Ssh $script:sshArgs (& $InstallCmd) (New-Payload)
  } else {
    $show = Get-ShowLines $j $t $true; if ($show) { Say $show }
    if ($j.Proc.ExitCode -eq 0 -and (Get-Result $j.Text)) { Finish $true '' } else { Finish $false '安装过程出错了，详情见上面的日志。' }
  }
})

$btn.Add_Click({
  try {
    $script:Server = $tbHost.Text.Trim().Trim('[', ']')
    $script:User = $tbUser.Text.Trim()
    $p = 0
    if (-not [int]::TryParse($tbPort.Text.Trim(), [ref]$p)) { throw 'SSH 端口必须是数字。' }
    $script:Port = $p
    $script:main = $script:mainHosts[[Math]::Max(0, $cbMain.SelectedIndex)]
    Assert-Target $script:Server $script:User $script:Port
    if ($script:main -and $script:main -eq $script:Server) { throw '不能把服务器加到它自己下面。请选「单独使用」。' }
    if (-not $script:keyFile -and -not $tbPw.Text) { throw '拖入密钥文件，或者填密码。' }
    Check-Prereqs
    $kp = $null
    if ($script:keyFile) { $kp = Copy-Key $script:keyFile }
    else {
      if (-not (Test-SshVersionForPassword)) { throw '这台电脑的 ssh 版本太旧，不支持自动填密码。请用密钥文件，或在「可选功能」里更新 OpenSSH 客户端。' }
      Set-AskPass $tbPw.Text
    }
    $Server = $script:Server; $User = $script:User; $Port = $script:Port
    $script:sshArgs = Get-SshArgs $kp (-not $kp)
    $log.Clear()
    $btn.Enabled = $false; $btn.Text = '正在部署…'; $status.Text = '正在连接服务器…'
    Say "正在连接 $Server …`n"
    $script:stage = 'probe'
    $script:job = Start-Ssh $script:sshArgs (& $ProbeCmd) $null
    $timer.Start()
  } catch { Remove-Secrets; [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'vps2vpn') | Out-Null }
})

$form.Add_FormClosing({
  if ($script:job -and -not $script:job.Proc.HasExited) { try { $script:job.Proc.Kill() } catch {} }
  Remove-Secrets
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
})
if ($UiSmokeTest) {
  # build everything, exercise the key picker on a folder and the result page with sample data, then close without showing
  $tmpSsh = Join-Path $Work 'fake-ssh'; New-Item -ItemType Directory $tmpSsh | Out-Null
  [IO.File]::WriteAllText((Join-Path $tmpSsh 'id_ed25519'), "-----BEGIN OPENSSH PRIVATE KEY-----`nx`n-----END OPENSSH PRIVATE KEY-----`n")
  Take-Key $tmpSsh
  $sample = @{ Rec = [ordered]@{ panel = 'https://203.0.113.10:23456/p/'; admin_user = 'admin'; admin_password = 'x'; sub_url = 'http://203.0.113.10:23456/s/t'
      links = [pscustomobject]@{ clash = 'clash://x' }; join_code = 'v2v1.x'; cloud = 'AWS Lightsail'; cloud_firewall = 'open it' }
    File = 'C:\x.json'; Client = [pscustomobject]@{ name = 'FlClash'; link = 'clash' }; Imported = $true; Join = ''; JoinMsg = ''
    Ports = @([pscustomobject]@{ proto = 'tcp'; port = 1; name = '管理面板'; ok = $true }, [pscustomobject]@{ proto = 'udp'; port = 2; name = 'TUIC'; ok = $false }) }
  $pnl = New-Object Windows.Forms.Panel
  Fill-Result $pnl $sample
  $n1 = $pnl.Controls.Count
  $sample.Rec['main'] = '198.51.100.7'; $sample.Join = 'fail'; $sample.JoinMsg = 'x'
  Fill-Result $pnl $sample
  Write-Output ('ui ok: {0} controls; picked {1}; result page {2}/{3} controls; main choices {4}' -f $form.Controls.Count,
    (Split-Path -Leaf $script:keyFile), $n1, $pnl.Controls.Count, $cbMain.Items.Count)
  $form.Dispose(); Remove-Item -Recurse -Force $Work; exit 0
}
[void]$form.ShowDialog()
