#!/usr/bin/env bash
# Attended Linux/WSL workflow; compose existing commands without changing media.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: local_av_lan_session.sh --python /installed/python --results NEW_DIRECTORY \
  --private-config LOCAL_JSON --expected-package-sha256 APPROVED_DIGEST --play \
  [--startup-pairing strict|common-keyframe] \
  [--audio-overlap-policy reject|bounded-serial-pcm] \
  [--max-audio-overlap-ms N] [--max-audio-phase-ms N]

One attended bounded capture, then offline saved-media verification. No packages
are installed and no configuration is copied or deleted. Requires Linux/WSL,
Bash and the existing installed Python/native output runtime. Enter still gates
acquisition. Results directory must be new; partial diagnostics are preserved.
EOF
}

fail() { printf '%s\n' "$1" >&2; exit 2; }

python_path='' results='' private_config='' play=false
capture_options=()
declare -A seen=()
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --play)
            [[ ! ${seen[$1]+present} ]] || fail 'Duplicate option.'
            seen[$1]=1
            play=true
            capture_options+=("$1")
            shift ;;
        --python|--results|--private-config|--expected-package-sha256|--startup-pairing|--audio-overlap-policy|--max-audio-overlap-ms|--max-audio-phase-ms)
            [[ $# -ge 2 && $2 != --* ]] || fail 'Option requires a value.'
            [[ ! ${seen[$1]+present} ]] || fail 'Duplicate option.'
            seen[$1]=1
            case "$1" in
                --python) python_path=$2 ;;
                --results) results=$2 ;;
                --private-config) private_config=$2; capture_options+=("$1" "$2") ;;
                *) capture_options+=("$1" "$2") ;;
            esac
            shift 2 ;;
        *) fail 'Unknown or workflow-managed option; use --help.' ;;
    esac
done
[[ $play == true && -n $private_config && -n $results && ${seen[--expected-package-sha256]+present} ]] || fail 'Python, results, private config, expected package hash and --play are required.'
[[ $python_path == /* && -f $python_path && -x $python_path ]] || fail 'Python must be an absolute executable file path.'
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f $base/local_av_lan_playback.py && -f $base/local_av_lan_verify.py ]] || fail 'Run this entrypoint from its complete repository checkout.'
mkdir -m 700 -- "$results" || fail 'Results must be a new writable directory.'
results=$(cd -- "$results" && pwd -P)
child=''
stop() {
    trap '' INT TERM
    # Discover owned jobs too: a signal can arrive after fork but before $! is
    # assigned. This shell starts no unrelated asynchronous jobs.
    local pid
    for pid in $(jobs -pr); do
        kill -TERM "$pid" 2>/dev/null || true
    done
    # Each owned Python CLI performs its own bounded worker/group cleanup.
    wait || true
    printf 'Session cancelled. Partial results retained: %s\n' "$results" >&2
    exit 130
}
trap stop INT TERM
run_step() {
    # Explicit stdin inheritance is required: Bash otherwise disconnects stdin
    # for asynchronous jobs, losing the existing operator Enter gate.
    "$@" <&0 &
    child=$!
    local code=0
    wait "$child" || code=$?
    child=''
    return "$code"
}
if run_step "$python_path" -I "$base/local_av_lan_playback.py" \
    --receipt "$results/capture.json" --packet-evidence "$results/packets" "${capture_options[@]}"; then
    printf 'Capture completed. Verifying saved media offline; camera is not restarted.\n'
else
    code=$?
    printf 'Capture did not complete (exit %s). Partial results retained: %s\n' "$code" "$results" >&2
    exit "$code"
fi
if run_step "$python_path" -I "$base/local_av_lan_verify.py" \
    --private-config "$private_config" --receipt "$results/capture.json" \
    --packet-evidence "$results/packets" --result "$results/verification.json"; then
    printf 'Session capture and saved-media verification completed: %s\n' "$results"
else
    code=$?
    printf 'Saved-media verification did not complete (exit %s). Capture results retained: %s\n' "$code" "$results" >&2
    exit "$code"
fi
