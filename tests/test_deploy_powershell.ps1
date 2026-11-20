$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../deploy/deploy.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in 'Get-ShowLines', 'Check-Prereqs') {
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
Write-Output 'PowerShell parser, fragmented secret output and SSH validation passed.'
