#requires -Version 5.1
<#
Windows bridge for the existing attended WSL session. No installation, copying,
account login, execution-policy change or additional acquisition is performed.
#>
[CmdletBinding()]
param(
    [string]$Distribution = 'Ubuntu',
    [string]$WslCheckout,
    [string]$WslPython,
    [string]$WslPrivateConfig,
    [string]$WslResults,
    [string]$ExpectedPackageSha256,
    [ValidateSet('strict', 'common-keyframe')][string]$StartupPairing = 'strict',
    [ValidateSet('reject', 'bounded-serial-pcm')][string]$AudioOverlapPolicy = 'reject',
    [object]$MaxAudioOverlapMs,
    [object]$MaxAudioPhaseMs,
    [switch]$Play,
    [switch]$Help,
    [switch]$CheckArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LanWslArguments {
    param([hashtable]$Options)
    if (-not $Options.Play) { throw 'Explicit play authorization is required.' }
    if ($Options.Distribution -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
        throw 'Unsupported distribution name.'
    }
    if ($Options.ExpectedPackageSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'An approved package source fingerprint is required.'
    }
    foreach ($name in @('WslCheckout', 'WslPython', 'WslPrivateConfig', 'WslResults')) {
        $value = $Options[$name]
        # Windows PowerShell 5 native argument marshalling cannot reliably keep
        # embedded double quotes. Backslashes are not supported WSL separators.
        if (($value -isnot [string]) -or (-not $value.StartsWith('/')) -or
            ($value -match '[\x00-\x1f\x7f"\\]')) {
            throw 'Use absolute WSL paths without quotes, controls or backslashes.'
        }
    }
    if (($Options.StartupPairing -isnot [string]) -or ($Options.AudioOverlapPolicy -isnot [string])) {
        throw 'Unsupported startup or audio policy.'
    }
    $startup = $Options.StartupPairing.ToLowerInvariant()
    $audio = $Options.AudioOverlapPolicy.ToLowerInvariant()
    if (($startup -cnotin @('strict', 'common-keyframe')) -or
        ($audio -cnotin @('reject', 'bounded-serial-pcm'))) {
        throw 'Unsupported startup or audio policy.'
    }
    $scriptPath = $Options.WslCheckout.TrimEnd('/') + '/tools/local_av_lan_session.sh'
    $native = @('--distribution', $Options.Distribution, '--exec', 'bash', $scriptPath,
        '--python', $Options.WslPython, '--results', $Options.WslResults,
        '--private-config', $Options.WslPrivateConfig,
        '--expected-package-sha256', $Options.ExpectedPackageSha256,
        '--startup-pairing', $startup,
        '--audio-overlap-policy', $audio, '--play')
    foreach ($pair in @(@('MaxAudioOverlapMs', '--max-audio-overlap-ms'),
                        @('MaxAudioPhaseMs', '--max-audio-phase-ms'))) {
        if ($Options.ContainsKey($pair[0]) -and ($null -ne $Options[$pair[0]])) {
            $raw = $Options[$pair[0]]
            if (($raw -isnot [int]) -and ($raw -isnot [long]) -and ($raw -isnot [string])) {
                throw 'Integer audio bounds are required.'
            }
            $text = [string]$raw
            $integer = 0
            if (($text -cnotmatch '^-?(0|[1-9][0-9]*)$') -or
                (-not [int]::TryParse($text, [Globalization.NumberStyles]::AllowLeadingSign,
                    [Globalization.CultureInfo]::InvariantCulture, [ref]$integer))) {
                throw 'Integer audio bounds are required.'
            }
            $native += @($pair[1], $integer.ToString([Globalization.CultureInfo]::InvariantCulture))
        }
    }
    return $native
}

function Invoke-LanWslSession {
    # WslExecutable is an internal test seam, not an entrypoint parameter.
    param([hashtable]$Options, [string]$WslExecutable)
    $script:LanSessionExitCode = 2
    $native = @(Get-LanWslArguments -Options $Options)
    if ([string]::IsNullOrEmpty($WslExecutable)) {
        $WslExecutable = Join-Path $env:SystemRoot 'System32\wsl.exe'
    }
    if (-not (Test-Path -LiteralPath $WslExecutable -PathType Leaf)) {
        throw 'WSL executable is unavailable.'
    }
    # Direct console invocation preserves Enter and native Ctrl-C forwarding.
    # Do not capture or pipe stdout: the Python Enter prompt has no newline.
    # PS7 native nonzero exits are verdicts, not preference-driven exceptions.
    $PSNativeCommandUseErrorActionPreference = $false
    & $WslExecutable @native
    $script:LanSessionExitCode = [int]$LASTEXITCODE
}

# Tests dot-source the functions and substitute a native argv probe, never WSL.
if ($MyInvocation.InvocationName -eq '.') { return }
if ($Help) {
    Write-Output @'
Usage: .\tools\local_av_lan_session.ps1 -Distribution Ubuntu `
  -WslCheckout /path/to/checkout -WslPython /installed/runtime/bin/python3.12 `
  -WslPrivateConfig /private/camera.json -WslResults /private/new-session `
  -ExpectedPackageSha256 APPROVED_SOURCE_SHA256 -Play

Optional: -StartupPairing common-keyframe -AudioOverlapPolicy bounded-serial-pcm
          -MaxAudioOverlapMs 1 -MaxAudioPhaseMs 1
Requires an existing configured WSL runtime/checkout. All paths are WSL paths.
One existing Enter gate; results stay in WSL. No installer or Windows bundle.
Add -CheckArguments to validate the same invocation without starting WSL.
'@
    exit 0
}
try {
    $options = @{
        Distribution = $Distribution; WslCheckout = $WslCheckout; WslPython = $WslPython
        WslPrivateConfig = $WslPrivateConfig; WslResults = $WslResults
        ExpectedPackageSha256 = $ExpectedPackageSha256; Play = [bool]$Play
        StartupPairing = $StartupPairing; AudioOverlapPolicy = $AudioOverlapPolicy
        MaxAudioOverlapMs = $MaxAudioOverlapMs; MaxAudioPhaseMs = $MaxAudioPhaseMs
    }
    if ($CheckArguments) {
        [void]@(Get-LanWslArguments -Options $options)
        Write-Output 'Arguments valid. WSL has NOT started.'
        exit 0
    }
    Invoke-LanWslSession -Options $options
    exit $script:LanSessionExitCode
}
catch {
    # Do not echo argument/config values through exception messages.
    [Console]::Error.WriteLine('Windows/WSL session could not start. Check arguments and WSL installation.')
    exit 2
}
