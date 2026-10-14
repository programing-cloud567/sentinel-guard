param(
    [Parameter(Mandatory = $true)]
    [string] $ExePath
)

$ErrorActionPreference = 'Stop'
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path
$DatabasePath = Join-Path (Split-Path -Parent $ExePath) 'signatures.txt'
$TestRoot = Join-Path $env:TEMP ("SentinelGuard JSON test " + [guid]::NewGuid().ToString('N'))

function Invoke-JsonScan {
    param([string] $Path)
    $lines = & $ExePath scan-json $Path $DatabasePath
    $exitCode = $LASTEXITCODE
    $document = ($lines -join [Environment]::NewLine) | ConvertFrom-Json
    return @{ ExitCode = $exitCode; Document = $document }
}

New-Item -ItemType Directory -Path $TestRoot | Out-Null
try {
    $empty = Invoke-JsonScan $TestRoot
    if ($empty.ExitCode -ne 0 -or $empty.Document.summary.scanned -ne 0) {
        throw 'Empty-directory scan should return valid JSON and exit code 0.'
    }

    $cleanPath = Join-Path $TestRoot ("unicode-" + [char]0x03A9 + '.txt')
    Set-Content -LiteralPath $cleanPath -Value 'ordinary notes' -NoNewline
    $clean = Invoke-JsonScan $cleanPath
    if ($clean.ExitCode -ne 0 -or $clean.Document.results[0].detected) {
        throw 'Clean-file scan should be reported as clean with exit code 0.'
    }

    $signalPath = Join-Path $TestRoot 'signal.txt'
    Set-Content -LiteralPath $signalPath -Value ('Invoke' + '-WebRequest') -NoNewline
    $signal = Invoke-JsonScan $signalPath
    if ($signal.ExitCode -ne 1 -or -not $signal.Document.results[0].detected) {
        throw 'Detected-file scan should report a signal and exit code 1.'
    }

    $missingPath = Join-Path $TestRoot 'missing.txt'
    $missing = Invoke-JsonScan $missingPath
    if ($missing.ExitCode -ne 2 -or $missing.Document.summary.unreadable -ne 1 -or
        $missing.Document.results[0].status -ne 'error') {
        throw 'Missing-path scan should report an error and exit code 2.'
    }

    Write-Output 'JSON scan tests passed (empty, clean Unicode path, detected, missing path).'
} finally {
    Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
