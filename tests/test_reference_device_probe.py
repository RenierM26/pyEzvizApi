"""Synthetic device controls are byte-identical, bounded and honest on failure."""
from contextlib import contextmanager, suppress
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from typing import Any

import pytest

BASE = Path(__file__).parents[1]
M = runpy.run_path(str(BASE / 'tools/reference_stream/device_probe.py'))


def config(**changes):
    return dict(codec='raw', pattern='mixed-v1', size=9000, count=2, timeout=5,
                endpoint='127.0.0.1:27049', **changes)


@pytest.mark.parametrize('pattern', M['PATTERNS'])
def test_actual_js_and_host_generator_produce_identical_known_bytes(pattern):
    node = shutil.which('node')
    if node is None:
        pytest.skip('optional Node required for JS execution')
    source = (BASE / 'tools/reference_stream/device-probe.js').read_text()
    code = source + '\nprocess.stdout.write(Buffer.from(probePayload(9000,' + json.dumps(pattern) + ')));'
    result = subprocess.run([node, '-e', code], check=True, capture_output=True, timeout=10)
    assert result.stdout == M['payload'](9000, pattern)
    assert len(result.stdout) == 9000


@pytest.mark.parametrize('key,value', [('size',0),('size',True),('count',33),('count',False),
    ('size',12*1024*1024+1),('timeout',float('nan')),('timeout',61),('pattern','unknown'),('codec','bad'),('window',True),('window',-1),('window',33)])
def test_invalid_config_fails_before_output_or_attach(tmp_path, key, value):
    data = config()
    data[key] = value
    with pytest.raises(ValueError):
        M['probe'](data, tmp_path / 'result')
    assert not (tmp_path / 'result').exists()


def test_total_uncompressed_budget_cannot_be_bypassed(tmp_path):
    data = config()
    data.update(size=12*1024*1024, count=21)
    with pytest.raises(ValueError, match='byte/count'):
        M['probe'](data, tmp_path / 'result')


@pytest.mark.parametrize('change', ['hash','pattern','size','synthetic'])
def test_claimed_synthetic_identity_must_match_host_expected_before_ack(tmp_path, change):
    data = config()
    blob = M['payload'](data['size'], data['pattern'])
    data['sha256'] = hashlib.sha256(blob).hexdigest()
    row = dict(event='native_pixels', synthetic=True, pattern=data['pattern'], bytes=len(blob),
               sha256=data['sha256'], device_mono_ns=1, transport_id=1)
    row[dict(hash='sha256',pattern='pattern',size='bytes',synthetic='synthetic')[change]] = 'invalid'
    posts: list[Any] = []
    capture = M['REFERENCE']['Capture'](tmp_path, post=posts.append)
    try:
        M['receive'](capture, dict(type='send',payload=row), blob, data, tmp_path/'partial.json')
        assert capture.error == 'synthetic payload identity mismatch'
        assert not capture.rows and not posts
        report = json.loads((tmp_path/'partial.json').read_text())
        assert report['verified_snapshots'] == 0
    finally:
        capture.close()


def test_partial_receipt_keeps_verified_original_and_ack_prefix(tmp_path):
    data = config()
    blob = M['payload'](data['size'], data['pattern'])
    data['sha256'] = hashlib.sha256(blob).hexdigest()
    row = dict(event='native_pixels', synthetic=True, pattern=data['pattern'], bytes=len(blob),
               sha256=data['sha256'], device_mono_ns=1, transport_id=1)
    capture = M['REFERENCE']['Capture'](tmp_path, post=lambda message: None)
    try:
        M['receive'](capture, dict(type='send', payload=row), blob, data, tmp_path/'partial.json')
        prefix = json.loads((tmp_path/'partial.json').read_text())
        assert prefix['verified_snapshots'] == 1 and prefix['payload_bytes'] == len(blob)
        assert prefix['observed_acknowledgements'] == 0  # post return is not device receipt
        assert prefix['host_posts'][0]['successful']
    finally:
        capture.close()


def test_rotated_order_failures_preserved_and_temporary_pixels_removed(tmp_path, monkeypatch):
    calls = []
    def trial(settings, folder):
        calls.append(settings)
        (folder/'native_pixels.bin').write_bytes(b'temporary')
        failed = settings['codec'] == 'zlib'
        return dict(status='failed' if failed else 'ok', error='codec failed' if failed else None,
                    verified_snapshots=1, worker_deadline_exceeded=False)
    monkeypatch.setitem(M['probe'].__globals__, 'supervised_trial', trial)
    output = tmp_path/'result'
    report = M['probe'](config(), output, 3)
    assert [item['codec'] for item in calls] == ['raw','zlib','lz4','zlib','lz4','raw','lz4','raw','zlib']
    assert len({item['sha256'] for item in calls}) == 1
    assert report['status'] == 'failed' and len(report['trials']) == 9
    assert report['android_transport_measured'] and not report['playback_measured']
    assert list(output.iterdir()) == [output/'probe.json']
    assert (output.stat().st_mode & 0o777) == 0o700
    with pytest.raises(FileExistsError):
        M['probe'](config(), output)


def test_watchdog_abort_does_not_start_contaminated_followup_trials(tmp_path, monkeypatch):
    def trial(settings, folder):
        return dict(status='failed', error='deadline', verified_snapshots=1,
                    worker_deadline_exceeded=True, device=None)
    monkeypatch.setitem(M['probe'].__globals__, 'supervised_trial', trial)
    report = M['probe'](config(), tmp_path/'result')
    assert report['status'] == 'failed' and len(report['trials']) == 1
    assert report['trials'][0]['device'] is None


def test_real_worker_timeout_reaps_process_and_retains_atomic_prefix(tmp_path, monkeypatch):
    original = subprocess.Popen
    children = []
    code = "import json,time;from pathlib import Path;Path('partial.json').write_text(json.dumps(dict(verified_snapshots=1,payload_bytes=9000)));time.sleep(30)"
    def slow_worker(args, **kwargs):
        process = original([sys.executable, '-c', code], cwd=tmp_path, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(M['subprocess'], 'Popen', slow_worker)
    result = M['supervised_trial'](config(), tmp_path)
    assert result['status'] == 'failed' and result['worker_deadline_exceeded']
    assert result['verified_snapshots'] == 1 and result['device'] is None
    assert children[0].poll() is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(children[0].pid, 0)


@pytest.mark.parametrize('repeats', [0,4,True])
def test_invalid_repeats_do_not_create_output(tmp_path, repeats):
    with pytest.raises(ValueError, match='repeats'):
        M['probe'](config(), tmp_path/'result', repeats)
    assert not (tmp_path/'result').exists()


@pytest.mark.parametrize('case', ['raw','compressed','fallback','failure','oversize','bad-codec'])
def test_shared_js_codec_preserves_row_fallback_and_failure_semantics(case):
    node = shutil.which('node')
    if node is None:
        pytest.skip('optional Node required for JS execution')
    source = (BASE/'tools/reference_stream/snapshot-codec.js').read_text()
    harness = r'''
const assert=require('node:assert/strict');
const calls=[],spans=[],allocations=[];
const Module={load:()=>({getExportByName:name=>name})};
function NativeFunction(name) {
 if(name==='LZ4_compressBound')return ()=>CASE==='oversize'?14*1024*1024:200;
 if(name==='LZ4_compress_default')return ()=>CASE==='failure'?0:CASE==='fallback'?100:50;
 throw Error('unexpected export');
}
const Memory={alloc:n=>{allocations.push(n);return {
 writeByteArray:()=>{},writeU32:()=>{},readByteArray:size=>new ArrayBuffer(size)
};}};
const row={event:'native_pixels',bytes:100,sha256:'original'},data=new ArrayBuffer(100);
const timed=(stage,n,fn)=>{spans.push([stage,n]);return fn();};
if(CASE==='bad-codec')assert.throws(()=>snapshotCodec('bad',timed,()=>{}),/unsupported/);
else {
 const send=snapshotCodec(CASE==='raw'?'raw':'lz4',timed,(row,bytes)=>calls.push([row,bytes]));
 if(CASE==='failure'||CASE==='oversize') {
  assert.throws(()=>send(row,data),/compression failed|buffer bound/);assert.equal(calls.length,0);
 } else {
  send(row,data);assert.equal(calls.length,1);assert.equal(row.encoding,undefined);
  assert.equal(calls[0][0].sha256,'original');
  if(CASE==='compressed') {
   assert.equal(calls[0][0].encoding,'lz4');assert.equal(calls[0][1].byteLength,50);
  } else {assert.equal(calls[0][0],row);assert.equal(calls[0][1],data);}
  if(CASE==='raw'){assert.equal(spans.length,0);assert.equal(allocations.length,0);}
 }
}
'''
    subprocess.run([node,'-e',source+'\nconst CASE='+json.dumps(case)+';\n'+harness],
                   check=True, capture_output=True, text=True, timeout=10)


def test_checkpoint_write_failure_is_not_silently_successful(tmp_path, monkeypatch):
    def failed_write(path, report):
        raise OSError('storage failure')
    monkeypatch.setitem(M['receive'].__globals__, 'write_receipt', failed_write)
    capture = M['REFERENCE']['Capture'](tmp_path)
    try:
        M['receive'](capture, dict(type='send', payload=dict(event='ready', device_mono_ns=1)),
                     None, config(), tmp_path/'partial.json')
        assert capture.error == 'checkpoint: storage failure'
        with pytest.raises(ValueError, match='checkpoint'):
            capture.snapshot()
    finally:
        capture.close()


def test_supervisor_cancel_retains_current_prefix_before_temporary_cleanup(tmp_path, monkeypatch):
    class Process:
        returncode = None
        def wait(self, timeout):
            raise KeyboardInterrupt
    def launch(args, **kwargs):
        (tmp_path/'partial.json').write_text(json.dumps(dict(verified_snapshots=1,payload_bytes=9000)))
        return Process()
    monkeypatch.setattr(M['subprocess'], 'Popen', launch)
    monkeypatch.setitem(M['supervised_trial'].__globals__, 'stop_worker',
                        lambda process: setattr(process, 'returncode', -2))
    result = M['supervised_trial'](config(), tmp_path)
    assert result['status'] == 'cancelled' and result['verified_snapshots'] == 1
    assert not result['worker_deadline_exceeded'] and result['device'] is None


def test_cancelled_trial_is_filed_and_no_followup_starts(tmp_path, monkeypatch):
    def trial(settings, folder):
        return dict(status='cancelled', error='operator cancelled',verified_snapshots=1,
                    worker_deadline_exceeded=False)
    monkeypatch.setitem(M['probe'].__globals__, 'supervised_trial', trial)
    report = M['probe'](config(), tmp_path/'result')
    assert report['status'] == 'cancelled' and len(report['trials']) == 1
    assert report['trials'][0]['verified_snapshots'] == 1
    assert json.loads((tmp_path/'result/probe.json').read_text()) == report


@pytest.mark.parametrize('signal_name', ['SIGINT', 'SIGTERM'])
@pytest.mark.parametrize('during_launch', [False, True])
def test_real_supervisor_signals_clean_isolated_worker_and_file_prefix(tmp_path, during_launch, signal_name):
    # Signal only the supervisor, not its child's new session. The regression
    # must prove child reaping, retained prefix and handler restoration.
    code = r'''
import json,os,runpy,signal,subprocess,sys,time
from pathlib import Path
module=runpy.run_path(sys.argv[1]);root=Path(sys.argv[2]);during=sys.argv[3]=='True'
signum=getattr(signal,sys.argv[4])
original=subprocess.Popen;children=[]
child="import json,time,os;from pathlib import Path;Path('partial.json').write_text(json.dumps(dict(verified_snapshots=1,payload_bytes=9000)));Path('child.pid').write_text(str(os.getpid()));time.sleep(30)"
def launch(args,**kwargs):
 process=original([sys.executable,'-c',child],cwd=Path(args[-1]).parent,**kwargs);children.append(process)
 until=time.monotonic()+5
 while not (root/'child.pid').exists() and time.monotonic()<until:time.sleep(.01)
 if during:os.kill(os.getpid(),signum)
 else:
  import threading
  threading.Timer(.1,lambda:os.kill(os.getpid(),signum)).start()
 return process
module['subprocess'].Popen=launch
previous={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
settings=dict(codec='raw',pattern='mixed-v1',size=9000,count=2,timeout=20,endpoint='unused')
result=module['supervised_trial'](settings,root)
assert all(signal.getsignal(sig)==handler for sig,handler in previous.items())
assert children[0].poll() is not None
try:os.killpg(children[0].pid,0)
except ProcessLookupError:pass
else:raise AssertionError('isolated worker survived supervisor signal')
(root/'result.json').write_text(json.dumps(result))
'''
    try:
        result = subprocess.run([sys.executable,'-c',code,
                                 str(BASE/'tools/reference_stream/device_probe.py'),str(tmp_path),
                                 str(during_launch),signal_name], capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == 0, result.stderr
        receipt = json.loads((tmp_path/'result.json').read_text())
        assert receipt['status'] == 'cancelled' and receipt['verified_snapshots'] == 1
        assert not receipt['worker_deadline_exceeded'] and receipt['device'] is None
    finally:
        # Bound cleanup even if testing an unfixed supervisor leaves its child alive.
        pid_path = tmp_path/'child.pid'
        if pid_path.exists():
            with suppress(ProcessLookupError):
                os.killpg(int(pid_path.read_text()), M['signal'].SIGKILL)


@pytest.mark.parametrize('timed_out', [False, True])
def test_signal_recorded_during_handler_restoration_is_observed(tmp_path, monkeypatch, timed_out):
    @contextmanager
    def restoring_handlers():
        requested = [False]
        try:
            yield requested
        finally:
            requested[0] = True  # signal delivered after worker result, during scoped restoration
    monkeypatch.setitem(M['supervised_trial'].__globals__, 'supervisor_termination', restoring_handlers)
    monkeypatch.setitem(M['supervised_trial'].__globals__, 'supervise_process',
        lambda *args: dict(status='failed' if timed_out else 'ok', verified_snapshots=1,
                           worker_deadline_exceeded=timed_out))
    result = M['supervised_trial'](config(), tmp_path)
    assert result['status'] == ('failed' if timed_out else 'cancelled')
    assert result['verified_snapshots'] == 1


@pytest.mark.parametrize('windows', [(), (0,0), (True,), (-1,), (33,), (0,1,2,3)])
def test_invalid_windows_fail_before_output_or_attach(tmp_path, windows):
    with pytest.raises(ValueError, match='windows'):
        M['probe'](config(), tmp_path/'result', windows=windows)
    assert not (tmp_path/'result').exists()


def test_window_matrix_preserves_every_combination_and_rotates(tmp_path, monkeypatch):
    calls = []
    def trial(settings, folder):
        calls.append((settings['codec'], settings['window'], settings['sha256']))
        return dict(status='ok', worker_deadline_exceeded=False)
    monkeypatch.setitem(M['probe'].__globals__, 'supervised_trial', trial)
    report = M['probe'](config(), tmp_path/'result', 3, (0,1,4))
    assert report['status'] == 'ok' and len(calls) == 27
    expected = {(codec,window) for codec in M['CODECS'] for window in (0,1,4)}
    assert all({item[:2] for item in calls[start:start+9]} == expected for start in (0,9,18))
    assert [calls[i][:2] for i in (0,9,18)] == [('raw',0),('zlib',1),('lz4',4)]
    assert len({item[2] for item in calls}) == 1
    assert {(t['codec'],t['window']) for t in report['trials']} == expected


@pytest.mark.parametrize('window', [0,1,4,32])
@pytest.mark.parametrize('scenario', ['complete','freeze','bad-ack','duplicate-after-credit','send-failure'])
def test_actual_js_window_is_ack_driven_bounded_and_frozen(window, scenario):
    node = shutil.which('node')
    if node is None:
        pytest.skip('optional Node required for JS execution')
    source = '\n'.join((BASE/'tools/reference_stream'/name).read_text() for name in (
        'transport-ack.js','snapshot-codec.js','device-probe.js'))
    harness = r'''
const assert=require('node:assert/strict');
const messages=[],receivers=[],tasks=[];let ticks=0,failSend=false;
const Process={arch:'arm',pointerSize:4,getModuleByName:()=>({getExportByName:()=>0})};
const Memory={alloc:()=>({readU32:()=>1,add:()=>({readU32:()=>++ticks})})};
function NativeFunction(){return ()=>0;}
const Checksum={compute:()=>'expected'};
function send(row,data){
 if(data&&failSend)throw Error('injected send failure');
 messages.push({row,data});
}
function recv(type,callback){assert.equal(type,'snapshot-ack');receivers.push(callback);}
function setImmediate(fn){tasks.push(fn);}
const binary=()=>messages.filter(m=>m.data);
const ack=id=>receivers.shift()({payload:{id}});
const drain=()=>{while(tasks.length)tasks.shift()();};
const probe=createDeviceProbe({codec:'raw',window:WINDOW,size:9,count:7,
 pattern:'mixed-v1',sha256:'expected'});
probe.prepare();probe.burst();
assert.equal(binary().length,WINDOW===0?7:Math.min(WINDOW,7));
assert.equal(tasks.length,0); // no polling or refill without a received acknowledgement
if(SCENARIO==='complete'){
 for(let id=1;id<=7;id++){assert.ok(binary().some(m=>m.row.transport_id===id));ack(id);drain();}
 const done=probe.finish();
 assert.equal(done.flow.emitted,7);assert.equal(done.flow.acknowledged,7);
 assert.equal(done.flow.inflight,0);assert.deepEqual(done.acknowledgements.pending_ids,[]);
 assert.equal(done.flow.peak_inflight,WINDOW===0?7:Math.min(WINDOW,7));
 assert.ok(done.burst_returned_ns>=done.burst_started_ns);
 if(WINDOW>0&&WINDOW<7)assert.ok(done.burst_rpc_returned_ns<done.burst_returned_ns);
 else assert.ok(done.burst_rpc_returned_ns>=done.burst_returned_ns);
}else if(SCENARIO==='freeze'){
 ack(1);const before=binary().length;
 const done=probe.finish();drain();ack(2);drain();
 assert.equal(binary().length,before);assert.equal(done.flow.acknowledged,1);
 assert.equal(done.flow.emitted,before);
 assert.equal(done.acknowledgements.pending_ids.length,before-1);
 if(WINDOW===1)assert.equal(done.burst_returned_ns,null);
}else if(SCENARIO==='duplicate-after-credit'){
 const before=binary().length;ack(1);ack(1);drain();
 assert.equal(binary().length,before);assert.equal(probe.finish().flow.acknowledged,1);
 assert.ok(messages.some(m=>m.row.event==='error'&&m.row.where==='transport_ack'));
}else if(SCENARIO==='bad-ack'){
 const before=binary().length;ack(99);drain();
 assert.equal(binary().length,before);assert.equal(probe.finish().flow.acknowledged,0);
 assert.ok(messages.some(m=>m.row.event==='error'&&m.row.where==='transport_ack'));
}else{
 failSend=true;ack(1);drain();
 const done=probe.finish();
 if(WINDOW>0&&WINDOW<7){
  assert.ok(messages.some(m=>m.row.event==='error'&&m.row.where==='window_pump'));
  assert.equal(done.flow.send_attempts,Math.min(WINDOW,7)+1);
  assert.equal(done.flow.emitted,Math.min(WINDOW,7));
 }
 assert.equal(done.flow.acknowledged,1);
}
'''
    subprocess.run([node,'-e',source+'\nconst WINDOW='+str(window)+';const SCENARIO='+json.dumps(scenario)+';\n'+harness],
                   check=True,capture_output=True,text=True,timeout=10)
