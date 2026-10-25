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
    $options = Valid-Options
    $options.CaptureProfile = 'TwO-MiNuTe'
    Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable
    $longArguments = @(Read-Probe)
    $profileIndex = [Array]::IndexOf($longArguments, '--capture-profile')
    Assert-True ($profileIndex -ge 0 -and $longArguments[$profileIndex + 1] -ceq 'two-minute') 'Finite profile was not forwarded canonically.'
    $count++
    $options.CaptureProfile = 'TwO-MiNuTe-GaPs'
    Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable
    $gapArguments = @(Read-Probe)
    $gapIndex = [Array]::IndexOf($gapArguments, '--capture-profile')
    Assert-True ($gapIndex -ge 0 -and $gapArguments[$gapIndex + 1] -ceq 'two-minute-gaps') 'Gap profile was not forwarded canonically.'
    $count++
    $options.CaptureProfile = 'automatic'
    $rejected = $false
    try { [void]@(Get-LanWslArguments -Options $options) } catch { $rejected = $true }
    Assert-True $rejected 'Unknown capture profile was accepted.'
    $count++
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
    $options.StartupPairing = 'StRiCt'
    $options.AudioOverlapPolicy = 'ReJeCt'
    $env:LAN_WSL_PROBE_EXIT = '0'
    Invoke-LanWslSession -Options $options -WslExecutable $ProbeExecutable
    $actual = @(Read-Probe)
    Assert-True ($actual -ccontains 'strict') 'Startup spelling was not normalized.'
    Assert-True ($actual -ccontains 'reject') 'Audio policy spelling was not normalized.'
    Assert-True (-not ($actual -ccontains 'StRiCt')) 'Noncanonical startup reached native argv.'
    $count++
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
    # Exercise the real script binder, not a preconstructed helper hashtable.
    # CheckArguments validates before resolving or starting wsl.exe.
    $hostExecutable = (Get-Process -Id $PID).Path
    $env:LAN_WSL_ENTRYPOINT = (Resolve-Path -LiteralPath $entry).Path
    $binderCases = @(
        @{Name = 'CaptureProfile'; Value = "'TwO-MiNuTe'"; Code = 0},
        @{Name = 'CaptureProfile'; Value = "'TwO-MiNuTe-GaPs'"; Code = 0},
        @{ Value = '0.6'; Code = 2 }, @{ Value = '([double]1)'; Code = 2 },
        @{ Value = '([decimal]1)'; Code = 2 }, @{ Value = "'0.6'"; Code = 2 },
        @{ Value = '$true'; Code = 2 }, @{ Value = "'2147483648'"; Code = 2 },
        @{ Value = '0'; Code = 0 }, @{ Value = "'1'"; Code = 0 },
        @{ Value = '([long]1)'; Code = 0 }, @{ Value = '0.6'; Code = 2; Name = 'MaxAudioPhaseMs' }
    )
    foreach ($case in $binderCases) {
        $name = 'MaxAudioOverlapMs'
        if ($case.ContainsKey('Name')) { $name = $case.Name }
        $commandText = '& $env:LAN_WSL_ENTRYPOINT -Distribution NativeProbeOnly -WslCheckout /missing-checkout -WslPython /missing-python -WslPrivateConfig /missing-config -WslResults /missing-results -ExpectedPackageSha256 ("a" * 64) -StartupPairing StRiCt -AudioOverlapPolicy ReJeCt -Play -CheckArguments -' + $name + ' ' + $case.Value + '; exit $LASTEXITCODE'
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commandText))
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $hostExecutable
        $start.Arguments = '-NoProfile -EncodedCommand ' + $encoded
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $start
        try {
            [void]$process.Start()
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Binder control timed out.' }
            $stdout = $stdoutTask.Result
            $stderr = $stderrTask.Result
            Assert-True ($process.ExitCode -eq $case.Code) 'Script binder silently coerced an audio bound.'
            if ($case.Code -eq 0) {
                Assert-True ($stdout.Trim() -ceq 'Arguments valid. WSL has NOT started.') 'Argument-only mode did not stop before WSL.'
            }
            else {
                Assert-True ($stdout -notmatch 'Arguments valid') 'Invalid bound reported validity.'
                Assert-True ($stderr -match 'Windows/WSL session could not start') 'Bound rejection was not sanitized.'
            }
        }
        finally { $process.Dispose() }
        $count++
    }
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
