"""Exact-interpreter preflight is offline evidence, not acquisition or playback."""
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_runtime.py'
M = runpy.run_path(str(SCRIPT))


@pytest.fixture
def probe_env(tmp_path, monkeypatch):
    package = tmp_path / 'pyezvizapi'
    package.mkdir()
    (package / '__init__.py').write_text('')
    (package / 'py.typed').write_text('')
    expected = M['package_fingerprint'](package)
    namespace = M['probe'].__globals__
    modules = {'pyezvizapi': SimpleNamespace(__file__=str(package / '__init__.py')),
        'av': SimpleNamespace(Codec=lambda *_args: None, formats_available={'mpeg'}, library_versions={})}
    importer = SimpleNamespace(import_module=lambda name: modules.get(name, SimpleNamespace()),
        metadata=SimpleNamespace(version=lambda _name: 'test-version'))
    monkeypatch.setitem(namespace, 'importlib', importer)
    monkeypatch.setitem(namespace, 'sys', SimpleNamespace(platform='linux', version_info=(3, 13),
        version='3.13 test', executable=sys.executable, flags=SimpleNamespace(isolated=1)))
    monkeypatch.setattr(M['runpy'], 'run_path', lambda _path: {})
    monkeypatch.setitem(namespace, 'media_smoke', lambda _module: {'sealed_store_closed': True})
    monkeypatch.setattr(M['ctypes'], 'CDLL', lambda _name: SimpleNamespace(SDL_Init=None, SDL_CreateWindow=None, SDL_RenderPresent=None))
    monkeypatch.setitem(namespace, 'pcm_capability', lambda: {'mono_option': 'ch-layout'})
    return expected, namespace, importer, package


def test_success_records_isolation_identity_and_no_device_claim(probe_env):
    expected, _namespace, _importer, _package = probe_env
    report = M['probe'](expected)
    assert report['status'] == 'ready-for-offline-control' and all(c['passed'] for c in report['checks'])
    assert report['isolated'] and report['package_sha256'] == expected
    assert not report['network_acquisition'] and not report['output_devices_opened']
    assert not report['physical_av_sync_measured'] and report['scope'] == 'offline-control-readiness-only'


@pytest.mark.parametrize('name', list(M['IMPORTS']))
def test_missing_dependency_is_reported_before_tool_smoke(probe_env, name):
    expected, _namespace, importer, _package = probe_env
    original = importer.import_module
    def fail(module):
        if module == name:
            raise ModuleNotFoundError('private detail', name=name)
        return original(module)
    importer.import_module = fail
    report = M['probe'](expected)
    assert report['status'] == 'failed' and report['missing_module'] == name
    assert report['checks'][-1]['name'] == 'import:' + name and not report['checks'][-1]['passed']
    assert 'private detail' not in repr(report) and 'smoke' not in report


def test_wrong_installed_source_hash_cannot_become_ready(probe_env):
    report = M['probe']('0' * 64)
    assert report['status'] == 'failed'
    assert report['checks'][-1]['name'] == 'installed-package-identity'


def test_nonisolated_interpreter_rejected_before_import(probe_env):
    expected, namespace, _importer, _package = probe_env
    namespace['sys'].flags.isolated = 0
    report = M['probe'](expected)
    assert report['status'] == 'failed' and report['checks'] == [dict(name='platform', passed=False, error_type='ValueError')]


@pytest.mark.parametrize('stage', ['smoke', 'sdl', 'pcm'])
def test_failed_native_capability_cannot_report_readiness(probe_env, monkeypatch, stage):
    expected, namespace, _importer, _package = probe_env
    def fail(*_args):
        raise OSError('private native detail')
    if stage == 'smoke':
        monkeypatch.setitem(namespace, 'media_smoke', fail)
    elif stage == 'sdl':
        monkeypatch.setattr(M['ctypes'], 'CDLL', fail)
    else:
        monkeypatch.setitem(namespace, 'pcm_capability', fail)
    report = M['probe'](expected)
    assert report['status'] == 'failed' and report['error_type'] == 'OSError'
    assert 'private native detail' not in repr(report)


def test_fingerprint_includes_filenames_and_typing_but_not_bytecode(tmp_path):
    (tmp_path / 'a.py').write_bytes(b'ab')
    (tmp_path / 'py.typed').write_bytes(b'')
    expected = hashlib.sha256()
    expected.update(b'a.py\0' + hashlib.sha256(b'ab').digest())
    expected.update(b'py.typed\0' + hashlib.sha256(b'').digest())
    assert M['package_fingerprint'](tmp_path) == expected.hexdigest()
    (tmp_path / 'ignored.pyc').write_bytes(b'ignored')
    assert M['package_fingerprint'](tmp_path) == expected.hexdigest()
    (tmp_path / 'a.py').rename(tmp_path / 'b.py')
    assert M['package_fingerprint'](tmp_path) != expected.hexdigest()


@pytest.mark.parametrize('kind', ['symlink', 'byte-limit', 'file-limit', 'missing-marker'])
def test_fingerprint_rejects_unbounded_or_nonregular_package(tmp_path, monkeypatch, kind):
    (tmp_path / 'py.typed').write_bytes(b'')
    path = tmp_path / 'a.py'
    path.write_bytes(b'abc')
    if kind == 'symlink':
        path.unlink()
        path.symlink_to(tmp_path / 'py.typed')
    elif kind == 'byte-limit':
        monkeypatch.setitem(M['package_fingerprint'].__globals__, 'MAX_PACKAGE_BYTES', 2)
    elif kind == 'file-limit':
        monkeypatch.setitem(M['package_fingerprint'].__globals__, 'MAX_PACKAGE_FILES', 1)
    else:
        (tmp_path / 'py.typed').unlink()
    with pytest.raises(ValueError):
        M['package_fingerprint'](tmp_path)


@pytest.mark.parametrize('text,expected', [(b'  -ch_layout <x>\n', 'ch-layout'),
    (b' -channels <x>\n', 'channels'), (b'-channels x\n-ch_layout x\n', 'ch-layout')])
def test_pcm_option_is_detected_without_opening_audio(monkeypatch, text, expected):
    monkeypatch.setattr(M['shutil'], 'which', lambda _name: '/usr/bin/ffplay')
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout=text, stderr=b'')
    monkeypatch.setattr(M['subprocess'], 'run', run)
    assert M['pcm_capability']()['mono_option'] == expected
    assert calls[0][0] == ['/usr/bin/ffplay', '-hide_banner', '-h', 'demuxer=s16le']
    assert calls[0][1]['timeout'] == 3


@pytest.mark.parametrize('kind', ['missing', 'unsupported', 'oversized'])
def test_pcm_capability_failure_is_closed(monkeypatch, kind):
    monkeypatch.setattr(M['shutil'], 'which', lambda _name: None if kind=='missing' else '/ffplay')
    monkeypatch.setattr(M['subprocess'], 'run', lambda *_args, **_kwargs: SimpleNamespace(
        stdout=b'x' * (M['MAX_RESULT']+1) if kind=='oversized' else b'no mono', stderr=b''))
    with pytest.raises(ValueError):
        M['pcm_capability']()


def test_real_crypto_and_kernel_seal_smoke_uses_public_fixture_only():
    if not hasattr(os, 'memfd_create'):
        pytest.skip('Linux sealed storage required')
    module = runpy.run_path(str(SCRIPT.with_name('local_av_capture_playback.py')))
    report = M['media_smoke'](module)
    assert report == dict(synthetic_clear_sha256=hashlib.sha256(M['CLEAR']).hexdigest(),
        verified_decryption_end=True, sealed_bytes=12, sealed_store_closed=True)


@pytest.mark.parametrize('kind', ['bad-profile', 'wrong-identity', 'bad-exit', 'oversized', 'timeout', 'interrupt'])
def test_worker_protocol_and_timeouts_reap_group(monkeypatch, kind):
    class Child:
        pid = 123456789
        returncode = 0
        calls = 0
        def communicate(self, **_kwargs):
            self.calls += 1
            if self.calls == 1 and kind in ('timeout', 'interrupt'):
                if kind == 'interrupt':
                    raise KeyboardInterrupt
                raise subprocess.TimeoutExpired('worker', 1)
            report = dict(profile='wrong' if kind=='bad-profile' else M['PROFILE'],
                expected_package_sha256='bad' if kind=='wrong-identity' else 'a'*64,
                status='ready-for-offline-control', package_sha256='a'*64, isolated=True,
                scope='offline-control-readiness-only', network_acquisition=False,
                output_devices_opened=False, physical_av_sync_measured=False,
                checks=[dict(passed=True)])
            return (b'x'*(M['MAX_RESULT']+1) if kind=='oversized' else json.dumps(report).encode(), b'')
    child = Child()
    if kind == 'bad-exit':
        child.returncode = 2
    calls = []
    monkeypatch.setattr(M['subprocess'], 'Popen', lambda *_args, **_kwargs: child)
    monkeypatch.setattr(M['os'], 'killpg', lambda *args: calls.append(args))
    with pytest.raises((ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)):
        M['run_worker']('a'*64, 1)
    assert len(calls) == 1 and calls[0][0] == child.pid and child.calls == 2


def test_cli_exact_isolated_interpreter_and_exclusive_receipt(tmp_path):
    if not ctypes.util.find_library('SDL2-2.0') or not shutil.which('ffplay') or not hasattr(os, 'memfd_create'):
        pytest.skip('optional Linux output libraries unavailable')
    pytest.importorskip('av')
    # -I must inspect the installed package, which need not be this checkout
    # in a shared developer venv. Private exact-runtime controls pin the wheel.
    code = ('import pathlib,runpy,pyezvizapi; m=runpy.run_path(' + repr(str(SCRIPT))
        + '); print(m[\"package_fingerprint\"](pathlib.Path(pyezvizapi.__file__).parent))')
    expected = subprocess.check_output([sys.executable, '-I', '-c', code], text=True).strip()
    path = tmp_path / 'receipt.json'
    command = [sys.executable, '-I', str(SCRIPT), '--expected-package-sha256', expected, '--receipt', str(path)]
    result = subprocess.run(command, capture_output=True, timeout=25, check=False)
    assert result.returncode == 0, (result.stderr, path.read_text())
    report = json.loads(path.read_text())
    assert report['status'] == 'ready-for-offline-control' and report['isolated']
    original = path.read_bytes()
    result = subprocess.run(command, capture_output=True, timeout=25, check=False)
    assert result.returncode != 0 and path.read_bytes() == original


def test_real_worker_timeout_kills_owned_helper_group(tmp_path, monkeypatch):
    if not sys.platform.startswith('linux'):
        pytest.skip('Linux process groups required')
    marker = tmp_path / 'owned.json'
    worker = tmp_path / 'worker.py'
    worker.write_text('import subprocess,sys,time,json,pathlib,os\n'
        "helper=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
        + 'pathlib.Path(' + repr(str(marker)) + ").write_text(json.dumps(dict(worker=os.getpid(),helper=helper.pid)))\n"
        + 'time.sleep(30)\n')
    monkeypatch.setitem(M['run_worker'].__globals__, '__file__', str(worker))
    with pytest.raises(subprocess.TimeoutExpired):
        M['run_worker']('a'*64, 2)
    pids = json.loads(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pids['worker'], 0)
    # The killed helper can briefly await the host init's reap as a zombie;
    # it must not remain running or own open process resources.
    stat = Path('/proc') / str(pids['helper']) / 'stat'
    try:
        state = stat.read_text()
    except FileNotFoundError:
        state = None  # Host init can reap between observation and read.
    if state is not None:
        assert state.split()[2] == 'Z'
