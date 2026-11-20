$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../deploy/deploy.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in 'Get-ShowLines', 'Take-ShowLines', 'Read-New', 'Check-Prereqs', 'Get-RecordPath', 'Save-Record', 'Restrict-Path') {
  $node = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
  Invoke-Expression $node.Extent.Text
}
function Assert-Equal($actual, $expected) { if ($actual -cne $expected) { throw "Expected [$expected], got [$actual]" } }
$job = @{ Pending = '' }
Assert-Equal (Get-ShowLines $job 'V2V_RES' $false) ''
Assert-Equal (Get-ShowLines $job "ULT:c2VjcmV0`nvisible`npartial" $false) "visible`n"
Assert-Equal (Get-ShowLines $job '-end' $true) 'partial-end'
$SshExe = 'ssh'; $TarExe = 'tar'; $User = 'root'; $Port = 22
foreach ($Server in '::1', '2001:db8::1', '203.0.113.1', 'example.com') { Check-Prereqs }
foreach ($Server in '-oProxyCommand=bad', 'host..invalid', 'host;bad') {
  $rejected = $false
  try { Check-Prereqs } catch { $rejected = $true }
  if (-not $rejected) { throw "Invalid server accepted: $Server" }
}
$Server = 'example.com'; $Port = 65536
$rejected = $false
try { Check-Prereqs } catch { $rejected = $true }
if (-not $rejected) { throw 'Invalid port accepted' }
# Stderr cannot interrupt a partly read stdout secret marker.
$job = @{ LineBuffers = @{} }
Assert-Equal (Get-ShowLines $job 'V2V_RES' $false 'Out') ''
Assert-Equal (Get-ShowLines $job "progress`n" $false 'Err') "progress`n"
Assert-Equal (Get-ShowLines $job "ULT:c2VjcmV0`n" $false 'Out') ''
Assert-Equal (Get-ShowLines $job "prefix V2V_RESULT:c2VjcmV0`n" $false 'Err') ''
# Failed ACL hardening is an error, not a successfully saved secret.
function icacls.exe { $global:LASTEXITCODE = 5 }
$rejected = $false
try { Restrict-Path $source } catch { $rejected = $true }
if (-not $rejected) { throw 'ACL failure was ignored' }
Remove-Item Function:icacls.exe
$Records = Join-Path ([IO.Path]::GetTempPath()) ('v2v-record-test-' + [Guid]::NewGuid().ToString('N'))
$Server = 'fixture'
$script:rejectAcl = $false
function Restrict-Path([string]$p) {
  if ($script:rejectAcl) { throw 'injected ACL failure' }
  if ([IO.File]::Exists($p) -and [IO.Path]::GetFileName($p).StartsWith('.record-') -and [IO.File]::ReadAllText($p)) {
    throw 'secret written before private ACL'
  }
}
try {
  $p = Save-Record @{ admin_password = 'first-secret' }
  [void](Save-Record @{ admin_password = 'second-secret' })
  Assert-Equal (([IO.File]::ReadAllText($p) | ConvertFrom-Json).admin_password) 'second-secret'
  $script:rejectAcl = $true
  try { [void](Save-Record @{ admin_password = 'must-not-publish' }) } catch {}
  Assert-Equal (([IO.File]::ReadAllText($p) | ConvertFrom-Json).admin_password) 'second-secret'
  Assert-Equal @(Get-ChildItem -LiteralPath $Records -Force).Count 1
  $script:rejectAcl = $false
  # Decode a Chinese UTF-8 character split across disk reads without replacement characters.
  $out = Join-Path $Records 'out'; $err = Join-Path $Records 'err'
  $job = @{ Out = $out; Err = $err; Pos = 0; ErrPos = 0; Decoders = @{}; LineBuffers = @{}; ResultText = ''; Show = '' }
  $bytes = [Text.Encoding]::UTF8.GetBytes("中`nV2V_RESULT:c2VjcmV0`n")
  [IO.File]::WriteAllBytes($out, $bytes[0..0]); [IO.File]::WriteAllText($err, "stderr`n")
  [void](Read-New $job)
  [IO.File]::WriteAllBytes($out, $bytes)
  [void](Read-New $job)
  $shown = Take-ShowLines $job $true
  if ($shown -notmatch '中' -or $shown -match 'c2VjcmV0|V2V_RESULT|�') { throw 'stream decoding or redaction failed' }
} finally { Remove-Item -LiteralPath $Records -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output 'PowerShell parser, stream decoding/redaction, atomic private records, ACL failures and SSH validation passed.'
