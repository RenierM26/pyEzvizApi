"""Exact-build-gated compressed reference source. Binary stdout; UI/forwarding caller-owned."""
from __future__ import annotations

import argparse
import importlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
from typing import Any
import uuid

C = runpy.run_path(str(Path(__file__).parent / 'reference_stream/compressed.py'))
R = C['REFERENCE']
require = R['require']


def main() -> int:  # noqa: PLR0912, PLR0915 - one explicit owned observer lifetime
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach', action='store_true', required=True)
    parser.add_argument('--emit-stream', action='store_true', required=True)
    parser.add_argument('--device', required=True)
    parser.add_argument('--frida-endpoint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--session', help='optional exact one-time handoff session identity')
    args = parser.parse_args()
    if os.name != 'posix' or not math.isfinite(args.seconds) or not 1 <= args.seconds <= 20 or os.isatty(1):
        parser.error('requires POSIX, bounded 1..20s observation and binary stdout pipe/file')
    if args.session and not re.fullmatch(r'[a-f0-9]{32}', args.session):
        parser.error('session must be 32 lowercase hex characters')
    policy = subprocess.run(['adb', '-s', args.device, 'shell', 'dumpsys', 'window', 'policy'],
        capture_output=True, text=True, check=True, timeout=10)
    require('mIsShowing=false' in policy.stdout, 'unlock reference device manually before attaching')
    R['lz4_decoder']()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    session = probe = script = capture = writer = None
    report: dict[str, Any] = dict(status='failed', reference_app_required=True,
        native_scheduler_replayed=False, per_frame_native_pixel_audit=False,
        physical_av_sync_measured=False, session=args.session or uuid.uuid4().hex)
    requested = [False]
    previous: dict[Any, Any] = {}
    def stop(_signum: int, _frame: Any) -> None:
        requested[0] = True
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, stop)
        frida = importlib.import_module('frida')
        session = frida.get_device_manager().add_remote_device(args.frida_endpoint).attach('Gadget')
        probe = session.create_script("rpc.exports={profile(){return {arch:Process.arch,pointerSize:Process.pointerSize,modules:['libPlayCtrl.so','libezstreamclient.so'].map(n=>{let m=Process.getModuleByName(n);return {name:n,path:m.path};})};}};")
        probe.load()
        cache: dict[str, bytes] = {}
        profile = R['verify_profile'](probe.exports_sync.profile(), lambda p: R['device_module'](args.device, p, cache))
        report['profile'] = profile
        probe.unload()
        probe = None
        capture = C['Capture'](args.output)
        writer = C['Writer'](args.output, sys.stdout.fileno(), stopped=lambda: requested[0])
        emitter = C['Emitter'](args.output, writer.send)
        writer.send(dict(kind='begin', session=report['session'], elf_sha256=profile['elf_sha256']))
        script = session.create_script(C['build_source']())
        script.on('message', capture.message)
        script.load()
        require(capture.ready.wait(3), 'observer readiness timeout')
        print('READY_FRESH_PREVIEW', file=sys.stderr, flush=True)
        started: float | None = None
        deadline = time.monotonic() + 15
        while True:
            if requested[0]:
                raise KeyboardInterrupt('source stop requested')
            rows = capture.snapshot()
            if started is None and any(r.get('event') == 'encoded_video' for r in rows):
                started = time.monotonic()
            if started is None:
                require(time.monotonic() < deadline, 'fresh camera preview startup timeout')
            elif time.monotonic() - started >= args.seconds:
                break
            emitter.pump(rows)
            time.sleep(0.01)
        report['device'] = script.exports_sync.finish()
        script.unload()
        script = None
        rows = capture.snapshot()  # Final un-emitted observations remain boundary-pending.
        writer.send(dict(kind='end', encoded_units=emitter.next_token - 1, pairs=len(emitter.pairs),
                         vqe_outputs=len(emitter.audio), rejected_native_attempts=len(emitter.rejected)))
        report.update(status='bounded-compressed-source-completed', records=writer.sequence,
            encoded_units_sent=emitter.next_token - 1, header_records_sent=len(emitter.headers),
            reference_pairs_sent=len(emitter.pairs), checkpoints_sent=len(emitter.samples),
            vqe_outputs_sent=len(emitter.audio), captured_encoded_units=sum(r.get('event') == 'encoded_video' for r in rows),
            native_rejected_attempts=emitter.rejected,
            captured_reference_callbacks=sum(r.get('event') == 'render_callback' for r in rows),
            captured_vqe_outputs=sum(r.get('event') == 'audio_vqe_output' for r in rows),
            source_closed_host_ns=time.monotonic_ns())
    except (Exception, KeyboardInterrupt) as failure:
        if isinstance(failure, KeyboardInterrupt):
            report['status'] = 'cancelled'
        report['error'] = f'{type(failure).__name__}: {failure}'
        print(report['error'], file=sys.stderr, flush=True)
    finally:
        cleanup = []
        for obj, method in ((script, 'unload'), (probe, 'unload'), (session, 'detach'),
                            (writer, 'close'), (capture, 'close')):
            if obj is not None:
                try:
                    getattr(obj, method)()
                except Exception as error:
                    cleanup.append(str(error))
        report['cleanup'] = cleanup
        if cleanup:
            report['status'] = 'failed'
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if requested[0] and not cleanup:
            report['status'] = 'cancelled'
        (args.output / 'source-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'bounded-compressed-source-completed' else (
        130 if report['status'] == 'cancelled' else 2)


if __name__ == '__main__':
    raise SystemExit(main())
