"""Acknowledgement boundaries: verified host data, no invented one-way latency."""

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess
from typing import Any
import zlib

import pytest

BASE = Path(__file__).parents[1]
M = runpy.run_path(str(BASE / 'tools/app_reference_stream.py'))


def payload(index=1, encoding='raw'):
    original = b'original pixels' * 100
    wire = zlib.compress(original, 1) if encoding == 'zlib' else original
    return dict(type='send', payload=dict(event='native_pixels', device_mono_ns=1,
        transport_id=index, bytes=len(original), encoding=encoding, transport_bytes=len(wire),
        sha256=hashlib.sha256(original).hexdigest())), wire, original


@pytest.mark.parametrize('encoding', ['raw', 'zlib'])
def test_ack_only_after_verified_original_and_event_are_flushed(tmp_path, encoding):
    message, wire, original = payload(encoding=encoding)
    posts = []
    def post(value):
        rows = [json.loads(line) for line in (tmp_path / 'events.jsonl').read_text().splitlines()]
        assert len(rows) == 1
        assert (tmp_path / rows[0]['file']).read_bytes() == original
        posts.append(value)
    capture = M['Capture'](tmp_path, post=post)
    try:
        capture.message(message, wire)
        assert capture.error is None
        assert posts == [dict(type='snapshot-ack', payload=dict(id=1))]
        ack = capture.acknowledgements[0]
        assert ack['successful']
        assert ack['callback_entered_ns'] <= ack['persisted_ns'] <= ack['post_started_ns'] <= ack['post_returned_ns']
    finally:
        capture.close()


@pytest.mark.parametrize('damage', ['hash', 'truncated', 'sequence', 'disabled', 'audio'])
def test_bad_snapshot_never_acknowledged(tmp_path, damage):
    message, wire, _ = payload()
    posts: list[Any] = []
    if damage == 'hash':
        message['payload']['sha256'] = '0' * 64
    elif damage == 'truncated':
        wire = wire[:-1]
    elif damage == 'sequence':
        message['payload']['transport_id'] = True
    elif damage == 'audio':
        message['payload']['event'] = 'audio_vqe_output'
    capture = M['Capture'](tmp_path, post=None if damage == 'disabled' else posts.append)
    try:
        capture.message(message, wire)
        assert capture.error
        assert not capture.acknowledgements and not posts
        assert not list(tmp_path.glob('*.bin'))
    finally:
        capture.close()


def test_ack_post_failure_preserves_verified_prefix_and_failed_attempt(tmp_path):
    def post(value):
        raise OSError('transport disconnected')
    capture = M['Capture'](tmp_path, post=post)
    try:
        message, wire, original = payload()
        capture.message(message, wire)
        assert capture.error == 'transport disconnected'
        assert len(capture.rows) == 1
        assert (tmp_path / capture.rows[0]['file']).read_bytes() == original
        assert not capture.acknowledgements[0]['successful']
        assert capture.acknowledgements[0]['post_returned_ns'] is None
        capture.message(*payload()[:2])
        assert len(capture.acknowledgements) == 1
    finally:
        capture.close()


@pytest.mark.parametrize('next_id', [1, 3, None])
def test_duplicate_gap_or_missing_id_preserves_previous_ack(tmp_path, next_id):
    posts: list[Any] = []
    capture = M['Capture'](tmp_path, post=posts.append)
    try:
        capture.message(*payload()[:2])
        capture.message(*payload(next_id)[:2])
        assert capture.error == 'invalid snapshot transport sequence'
        assert len(capture.rows) == len(posts) == 1
    finally:
        capture.close()


def test_host_ack_metadata_is_bounded_to_32_snapshots(tmp_path):
    capture = M['Capture'](tmp_path, post=lambda value: None)
    try:
        for index in range(1, 34):
            capture.message(*payload(index)[:2])
        assert capture.error == 'invalid snapshot transport sequence'
        assert len(capture.rows) == len(capture.acknowledgements) == 32
    finally:
        capture.close()


@pytest.mark.parametrize('case', ['roundtrip', 'disabled', 'unknown', 'duplicate', 'limit', 'send-failure', 'freeze'])
def test_actual_device_helper_with_mock_clock_transport_and_receiver(case):
    node = shutil.which('node')
    if node is None:
        pytest.skip('optional Node needed for device JS execution')
    harness = r'''
const assert = require('node:assert/strict');
let now=100, listener, emitted=[], records=[], errors=[];
const helper=snapshotAcknowledgements(CASE!=='disabled',()=>now,
 (row,data)=>{emitted.push([row,data]);if(CASE==='send-failure')throw Error('send failed');now+=10;},
 (kind,fn)=>{assert.equal(kind,'snapshot-ack');listener=fn;},
 (event,fields)=>records.push({event,...fields}), (where,e)=>errors.push(String(e)));
const row={event:'native_pixels'}, bytes=new ArrayBuffer(3);
if(CASE==='send-failure') {
 assert.throws(()=>helper.send(row,bytes),/send failed/);
 const result=helper.finish(); assert.equal(result.sent[0].send_returned_ns,null);
 assert.deepEqual(result.pending_ids,[1]);
} else if(CASE==='limit') {
 for(let i=0;i<32;i++)helper.send(row,bytes);
 assert.throws(()=>helper.send(row,bytes),/limit/);
 assert.equal(helper.finish().sent.length,32);
} else {
 helper.send(row,bytes); assert.equal(row.transport_id,undefined);
 if(CASE==='disabled') {
  assert.equal(listener,undefined);assert.equal(emitted[0][0],row);
  assert.deepEqual(helper.finish().sent,[]);
 } else if(CASE==='freeze') {
  const result=helper.finish();listener({payload:{id:1}});
  assert.deepEqual(result.pending_ids,[1]);assert.equal(records.length,0);
  assert.throws(()=>helper.send(row,bytes),/limit/);
 } else {
  now=1000;listener({payload:{id:CASE==='unknown'?99:1}});
  if(CASE==='unknown') {
   assert.equal(errors.length,1);assert.deepEqual(helper.finish().pending_ids,[1]);
  } else {
   if(CASE==='duplicate') {listener({payload:{id:1}});assert.equal(errors.length,1);}
   assert.equal(records.length,1);assert.equal(records[0].started_ns,100);
   assert.equal(records[0].completed_ns,1000);assert.equal(records[0].bytes,3);
   const result=helper.finish();assert.deepEqual(result.pending_ids,[]);
   assert.equal(result.sent[0].send_returned_ns,110);
  }
 }
}
'''
    source = (BASE / 'tools/reference_stream/transport-ack.js').read_text()
    subprocess.run([node, '-e', source + '\nconst CASE=' + json.dumps(case) + ';\n' + harness],
                   check=True, capture_output=True, text=True, timeout=10)


def test_metadata_only_request_cannot_generate_a_payload_ack(tmp_path):
    posts: list[Any] = []
    capture = M['Capture'](tmp_path, post=posts.append)
    try:
        capture.message(payload()[0], None)
        assert capture.error == 'snapshot acknowledgement requires binary data'
        assert not posts and not capture.rows
    finally:
        capture.close()


@pytest.mark.parametrize('before', [False, None])
def test_comparison_exposes_changed_or_unknown_instrumentation(before):
    compare = runpy.run_path(str(BASE / 'tools/reference_stream/compare.py'))['compare']
    report = compare(dict(transport_acks=before), dict(transport_acks=True))
    assert 'transport_acks' in report['settings_mismatches']
    assert ('transport_acks' in report['settings_missing']) == (before is None)
    assert not report['sustained_realtime_verified']


@pytest.mark.parametrize('batched', [True, False])
def test_device_ack_is_metadata_not_a_new_binary_request(tmp_path, batched):
    capture = M['Capture'](tmp_path, post=lambda message: None)
    try:
        capture.message(*payload()[:2])
        row = dict(event='transport_ack', transport_id=1, device_mono_ns=10,
                   stage='snapshot_send_to_ack', started_ns=1, completed_ns=10)
        capture.message(dict(type='send', payload=dict(batch=[row]) if batched else row), None)
        assert capture.error is None
        assert capture.snapshot()[-1]['event'] == 'transport_ack'
        assert len(capture.acknowledgements) == 1 and capture.acknowledged == {1}
        capture.message(dict(type='send', payload=dict(batch=[row])), None)
        assert capture.error == 'unknown or duplicate collector transport acknowledgement'
    finally:
        capture.close()


@pytest.mark.parametrize('identity', [1, True, None])
def test_unrequested_device_ack_cannot_fabricate_round_trip(tmp_path, identity):
    capture = M['Capture'](tmp_path)
    try:
        capture.message(dict(type='send', payload=dict(event='transport_ack',
                        transport_id=identity, device_mono_ns=1)), None)
        assert capture.error == 'unknown or duplicate collector transport acknowledgement'
        assert not capture.rows and not capture.acknowledged
    finally:
        capture.close()
