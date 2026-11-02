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
    function Expect([int]$Want, [string[]]$Arguments) {
        & $java -jar dist/hostbaseline.jar @Arguments | Out-Null
        if ($LASTEXITCODE -ne $Want) { throw "Expected exit $Want but got ${LASTEXITCODE}: $($Arguments -join ' ')" }
        Write-Host "ok   exit $LASTEXITCODE   $($Arguments -join ' ')"
    }
    Expect 1 @('examples/risky', 'reports/risky', '--baseline', 'examples/hardened')
    Expect 0 @('examples/hardened', 'reports/hardened')
    Expect 3 @('examples/incomplete', 'reports/incomplete')
    Expect 1 @('examples/router', 'reports/router-as-workstation')
    Expect 0 @('examples/router', 'reports/router', '--role', 'router')
    Expect 2 @('examples/does-not-exist', 'reports/none')
    Write-Host 'Open reports/risky/report.html to inspect the comparison.'
} finally { Pop-Location }
