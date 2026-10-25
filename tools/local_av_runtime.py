"""Offline Linux/WSL runtime preflight; opens no camera or output devices.

Run with the exact proposed interpreter and -I. Readiness permits an offline
retained-media control, not live playback or target-host throughput claims.
"""
from __future__ import annotations

import argparse
from contextlib import suppress
import ctypes
import ctypes.util
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import subprocess
import sys
from typing import Any

PROFILE = 'guarded-media-runtime-preflight-v1'
MAX_RESULT = 65536
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_FILES = 512
ENCRYPTED = bytes.fromhex('000001e0002980000000000001420134a1119c1a165ddeb3ad0fffba9282ec34a1119c1a165ddeb3ad0fffba9282ec000001ba4400040004010001fff8')
CLEAR = bytes.fromhex('000001e000298000000000000142013031323334353637383961626364656630313233343536373839616263646566000001ba4400040004010001fff8')
IMPORTS = {'requests': 'requests', 'xmltodict': 'xmltodict', 'Crypto.Cipher.AES': 'pycryptodome',
           'cryptography.hazmat.primitives.ciphers': 'cryptography', 'paho.mqtt.client': 'paho-mqtt', 'av': 'av'}


def package_fingerprint(root: Path) -> str:
    """Bind installed Python sources and typing marker, not version alone or pyc."""
    paths = sorted([*root.rglob('*.py'), root / 'py.typed'])
    digest = hashlib.sha256()
    total = 0
    if not 0 < len(paths) <= MAX_PACKAGE_FILES:
        raise ValueError('package file count outside preflight bounds')
    for path in paths:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('package source must be a regular in-tree file')
        size = path.stat().st_size
        if size > MAX_PACKAGE_BYTES - total:
            raise ValueError('package source byte limit exceeded')
        raw = path.read_bytes()
        total += len(raw)
        if len(raw) != size:
            raise ValueError('package source changed while fingerprinting')
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def pcm_capability() -> dict[str, Any]:
    executable = shutil.which('ffplay')
    if executable is None:
        raise ValueError('ffplay unavailable')
    result = subprocess.run([executable, '-hide_banner', '-h', 'demuxer=s16le'],
        capture_output=True, timeout=3, check=True)
    if len(result.stdout) + len(result.stderr) > MAX_RESULT:
        raise ValueError('ffplay capability result too large')
    text = (result.stdout + result.stderr).decode('utf-8', errors='replace')
    mono = 'ch-layout' if re.search(r'^\s*-ch_layout\s', text, re.MULTILINE) else (
        'channels' if re.search(r'^\s*-channels\s', text, re.MULTILINE) else None)
    if mono is None:
        raise ValueError('ffplay lacks explicit mono raw-input option')
    return dict(executable=str(Path(executable).resolve()), mono_option=mono,
                capability_sha256=hashlib.sha256(result.stdout + result.stderr).hexdigest())


def media_smoke(module: dict[str, Any]) -> dict[str, Any]:
    """Public synthetic key/vector and a 12-byte sealed store; no camera key."""
    crypto: dict[str, Any] = {}
    chunks = module['PREPARE']['CAPTURE']['DECRYPT']['iter_decrypted'](
        (ENCRYPTED[i:i + 7] for i in range(0, len(ENCRYPTED), 7)), 'camera-key', crypto, codec='hevc')
    try:
        clear = b''.join(chunks)
    finally:
        chunks.close()
    if clear != CLEAR or not crypto['verified_decryption_end'] or crypto['cleanup_errors']:
        raise ValueError('synthetic decryption control failed')
    output = module['OUTPUT']
    pixels = (bytes(6), bytes(6))
    canonical = output['pair_digest'](*pixels, 2, 2)
    lease = output['CHANNEL']['Lease'](pixels, canonical)
    try:
        size = output['CHANNEL']['SHARED']['validate_store'](lease.store.fileno())
        if size != 12 or lease.frame.sha256 != hashlib.sha256(b''.join(pixels)).hexdigest():
            raise ValueError('sealed store extent/hash failed')
    finally:
        lease.close()
    if not lease.store.closed:
        raise ValueError('sealed store cleanup failed')
    return dict(synthetic_clear_sha256=hashlib.sha256(clear).hexdigest(),
        verified_decryption_end=True, sealed_bytes=size, sealed_store_closed=True)


def probe(expected: str) -> dict[str, Any]:
    report: dict[str, Any] = dict(profile=PROFILE, status='failed', error_type=None, checks=[],
        expected_package_sha256=expected, package_sha256=None,
        python_version=sys.version.split()[0], executable=sys.executable,
        isolated=bool(sys.flags.isolated), scope='offline-control-readiness-only',
        network_acquisition=False, output_devices_opened=False, physical_av_sync_measured=False)
    stage = 'platform'
    try:
        if not sys.platform.startswith('linux') or sys.version_info < (3, 12) or not sys.flags.isolated:
            raise ValueError('requires isolated Python >=3.12 on Linux/WSL')
        report['checks'].append(dict(name=stage, passed=True))
        stage = 'installed-package-identity'
        package = importlib.import_module('pyezvizapi')
        if package.__file__ is None:
            raise ValueError('installed package lacks a regular source root')
        report['package_sha256'] = package_fingerprint(Path(package.__file__).parent)
        if report['package_sha256'] != expected:
            raise ValueError('installed package source identity mismatch')
        report['checks'].append(dict(name=stage, passed=True))
        report['versions'] = {}
        for name, distribution in IMPORTS.items():
            stage = 'import:' + name
            importlib.import_module(name)
            report['versions'][distribution] = importlib.metadata.version(distribution)
            report['checks'].append(dict(name=stage, passed=True))
        stage = 'decoder-capabilities'
        av = importlib.import_module('av')
        for name in ('hevc', 'aac'):
            av.Codec(name, 'r')
        if 'mpeg' not in av.formats_available:
            raise ValueError('MPEG-PS demuxer unavailable')
        report['av_library_versions'] = av.library_versions
        report['checks'].append(dict(name=stage, passed=True))
        stage = 'guarded-tool-graph-and-smoke'
        entrypoint = Path(__file__).with_name('local_av_capture_playback.py')
        module = runpy.run_path(str(entrypoint))
        report['entrypoint_sha256'] = hashlib.sha256(entrypoint.read_bytes()).hexdigest()
        report['smoke'] = media_smoke(module)
        report['checks'].append(dict(name=stage, passed=True))
        stage = 'sdl-library'
        library = ctypes.util.find_library('SDL2-2.0') or 'libSDL2-2.0.so.0'
        sdl = ctypes.CDLL(library)
        for name in ('SDL_Init', 'SDL_CreateWindow', 'SDL_RenderPresent'):
            getattr(sdl, name)  # Resolve only: do not initialize SDL or open devices.
        report['sdl_library'] = library
        report['checks'].append(dict(name=stage, passed=True))
        stage = 'raw-pcm-capability'
        report['pcm'] = pcm_capability()
        report['checks'].append(dict(name=stage, passed=True))
        report['status'] = 'ready-for-offline-control'
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['checks'].append(dict(name=stage, passed=False, error_type=type(error).__name__))
        missing = getattr(error, 'name', None)
        if isinstance(missing, str) and re.fullmatch(r'[A-Za-z0-9_.]+', missing):
            report['missing_module'] = missing
    return report


def run_worker(expected: str, timeout: float) -> dict[str, Any]:
    """Bound the whole isolated probe and reap its process group on interruption."""
    child = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()),
        '--worker', '--expected-package-sha256', expected], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        raw, _stderr = child.communicate(timeout=timeout)
        if len(raw) > MAX_RESULT:
            raise ValueError('runtime result exceeds byte limit')
        report = json.loads(raw)
        if (report.get('profile') != PROFILE or report.get('expected_package_sha256') != expected
                or report.get('status') not in ('failed', 'ready-for-offline-control')
                or child.returncode != (0 if report['status'] == 'ready-for-offline-control' else 2)):
            raise ValueError('invalid runtime worker result')
        if report['status'] == 'ready-for-offline-control' and (
                report.get('package_sha256') != expected or report.get('isolated') is not True
                or report.get('scope') != 'offline-control-readiness-only'
                or report.get('network_acquisition') is not False or report.get('output_devices_opened') is not False
                or report.get('physical_av_sync_measured') is not False
                or not report.get('checks') or not all(c.get('passed') is True for c in report['checks'])):
            raise ValueError('incomplete runtime readiness evidence')
        return report
    finally:
        # Kill the group even if the worker exited: it may have left a helper.
        with suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        child.communicate(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-package-sha256', required=True)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (re.fullmatch('[0-9a-f]{64}', args.expected_package_sha256) is None
            or not 0 < args.timeout <= 30 or not sys.platform.startswith('linux')):
        parser.error('requires Linux, expected package SHA-256 and timeout >0..30 seconds')
    if args.worker:
        report = probe(args.expected_package_sha256)
        print(json.dumps(report))
        return 0 if report['status'] == 'ready-for-offline-control' else 2
    if args.receipt is None:
        parser.error('--receipt is required')
    with args.receipt.open('x', encoding='utf-8') as output:
        try:
            report = run_worker(args.expected_package_sha256, args.timeout)
        except (Exception, KeyboardInterrupt) as error:
            report = dict(profile=PROFILE, status='cancelled' if isinstance(error, KeyboardInterrupt) else 'failed',
                error_type=type(error).__name__, expected_package_sha256=args.expected_package_sha256,
                scope='offline-control-readiness-only', network_acquisition=False, output_devices_opened=False,
                physical_av_sync_measured=False)
        json.dump(report, output, indent=2)
        output.write('\n')
    return 0 if report['status'] == 'ready-for-offline-control' else 130 if report['status'] == 'cancelled' else 2


if __name__ == '__main__':
    raise SystemExit(main())
