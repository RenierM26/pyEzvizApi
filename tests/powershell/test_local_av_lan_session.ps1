#requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$ProbeExecutable)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$entry = Join-Path $PSScriptRoot '../../tools/local_av_lan_session.ps1'
. $entry
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('lan-wsl-test-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$env:LAN_WSL_PROBE_LOG = Join-Path $temporary 'argv.txt'
$env:LAN_WSL_PROBE_EXIT = '0'
$env:LAN_WSL_PROBE_STDERR = ''
$count = 0
function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}
function Read-Probe {
    return @(Get-Content -LiteralPath $env:LAN_WSL_PROBE_LOG | ForEach-Object {
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
    })
}
function Valid-Options {
    return @{
        Distribution = 'Ubuntu'; WslCheckout = '/home/test/checkout with spaces'
        WslPython = '/opt/python with spaces/bin/python3.12'
        WslPrivateConfig = '/private/key ''single'' $(no-eval);literal.json'
        WslResults = ('/private/new results ' + [char]0x00e9); ExpectedPackageSha256 = ('a' * 64)
        Play = $true; StartupPairing = 'strict'; AudioOverlapPolicy = 'reject'
    }
}
try {
    foreach ($code in @(0, 2, 130)) {
        $options = Valid-Options
        $env:LAN_WSL_PROBE_EXIT = $code.ToString()
        $env:LAN_WSL_PROBE_STDERR = 'synthetic native diagnostic'
        # Exercise PS7 callers that opt into native-exit ErrorAction semantics.
        $PSNativeCommandUseErrorActionPreference = $true
        Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable
        Assert-True ($script:LanSessionExitCode -eq $code) 'Native exit code was not preserved.'
        Assert-True $PSNativeCommandUseErrorActionPreference 'Caller native preference was changed.'
        $actual = @(Read-Probe)
        $expected = @('--distribution', 'Ubuntu', '--exec', 'bash',
            '/home/test/checkout with spaces/tools/local_av_lan_session.sh',
            '--python', $options.WslPython, '--results', $options.WslResults,
            '--private-config', $options.WslPrivateConfig, '--expected-package-sha256', ('a' * 64),
            '--startup-pairing', 'strict', '--audio-overlap-policy', 'reject', '--play')
        Assert-True ($actual.Count -eq $expected.Count) 'Native argv count changed.'
        for ($i = 0; $i -lt $expected.Count; $i++) {
            Assert-True ($actual[$i] -ceq $expected[$i]) 'Native argv value changed.'
        }
        $count++
    }
    $options = Valid-Options
    $options.StartupPairing = 'common-keyframe'
    $options.AudioOverlapPolicy = 'bounded-serial-pcm'
    $options.MaxAudioOverlapMs = [int]0
    $options.MaxAudioPhaseMs = [int]1
    $env:LAN_WSL_PROBE_EXIT = '0'
    Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable
    $actual = @(Read-Probe)
    Assert-True (($actual[-4..-1] -join '|') -ceq '--max-audio-overlap-ms|0|--max-audio-phase-ms|1') 'Integer zero/bounds lost.'
    Assert-True ($actual -contains 'common-keyframe') 'Startup opt-in lost.'
    $count++
    foreach ($case in @('play', 'distribution', 'hash', 'relative', 'windows', 'quote',
                         'newline', 'missing', 'startup', 'audio', 'float-bound')) {
        $options = Valid-Options
        switch ($case) {
            'play' { $options.Play = $false }
            'distribution' { $options.Distribution = 'Ubuntu;bad' }
            'hash' { $options.ExpectedPackageSha256 = 'invalid' }
            'relative' { $options.WslCheckout = 'relative' }
            'windows' { $options.WslPrivateConfig = 'C:\private\key.json' }
            'quote' { $options.WslPrivateConfig = '/private/double"quote' }
            'newline' { $options.WslResults = "/private/line`nbreak" }
            'missing' { $options.WslPython = '' }
            'startup' { $options.StartupPairing = 'nearest' }
            'audio' { $options.AudioOverlapPolicy = 'ignore' }
            'float-bound' { $options.MaxAudioOverlapMs = 1.5 }
        }
        $before = [IO.File]::ReadAllText($env:LAN_WSL_PROBE_LOG)
        $failed = $false
        try { Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable }
        catch { $failed = $true }
        Assert-True $failed 'Invalid input reached native invocation.'
        Assert-True ([IO.File]::ReadAllText($env:LAN_WSL_PROBE_LOG) -ceq $before) 'Invalid input launched a native process.'
        $count++
    }
    $options = Valid-Options
    $failed = $false
    try { Invoke-LanWslSession -Options $options -WslExecutable (Join-Path $temporary 'missing.exe') }
    catch { $failed = $true }
    Assert-True $failed 'Missing native executable reported success.'
    $count++
    $PSNativeCommandUseErrorActionPreference = $false
    $hostExecutable = (Get-Process -Id $PID).Path
    & $hostExecutable -NoProfile -File $entry -Help
    Assert-True ($LASTEXITCODE -eq 0) 'Entrypoint help failed.'
    $count++
    Write-Output (ConvertTo-Json -Compress @{status = 'passed'; cases = $count; version = $PSVersionTable.PSVersion.ToString(); wsl_started = $false})
}
finally {
    # Remove only this test's own synthetic argv artifacts.
    [IO.File]::Delete($env:LAN_WSL_PROBE_LOG)
    [IO.Directory]::Delete($temporary)
}
