param([string]$JdkHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
if (-not $JdkHome) {
    $compiler = Get-Command javac -ErrorAction SilentlyContinue
    if ($compiler) { $JdkHome = Split-Path (Split-Path $compiler.Source) }
}
if (-not $JdkHome) { throw "Specify -JdkHome with a JDK 17+ installation, for example 'C:\Program Files\Java\jdk-21'." }
& (Join-Path $PSScriptRoot 'build.ps1') -JdkHome $JdkHome
$java = Join-Path $JdkHome 'bin/java.exe'
Push-Location $PSScriptRoot
try {
    & $java -jar dist/hostbaseline.jar examples/risky reports/risky workstation examples/hardened
    if ($LASTEXITCODE -ne 1) { throw 'Risky fixture did not produce the expected failure exit code' }
    & $java -jar dist/hostbaseline.jar examples/hardened reports/hardened workstation
    if ($LASTEXITCODE -ne 0) { throw 'Hardened fixture failed' }
    & $java -jar dist/hostbaseline.jar examples/incomplete reports/incomplete workstation
    if ($LASTEXITCODE -ne 3) { throw 'Incomplete fixture did not produce UNKNOWN' }
    Write-Host 'Open reports/risky/report.html to inspect the comparison.'
} finally { Pop-Location }
