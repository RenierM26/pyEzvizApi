"""Retire unused copies only after every permitted pair has been emitted."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

SOURCE = Path(__file__).parents[1] / 'tools/reference_stream/h9c-armv7.js'


def run(case):
    node = shutil.which('node')
    if node is None:
        pytest.skip('optional Node required for snapshot ownership control')
    source = SOURCE.read_text()
    capture = source[source.index('function capturePixels('):source.index('// Lossless transport')]
    render = source[source.index('function checkRenderPixels('):source.index('function register(')]
    prelude = r"""'use strict';
const inputSnapshots=new Map(),capturedKeys=new Set(),emitted=[],logs=[];
let capturedPairs=0,pixelBytes=0,stopped=false,copies=0;
const pairLimit=CASE==='two_pairs'?2:1,pixelLimit=CASE==='byte_limit'?1:240*1024*1024;
function sourceKey(sid,raw,frame){return [sid,raw,frame].join(':');}
function log(event,fields){logs.push({event,...fields});}
function mono(){return 1;}
function flush(){}
function readable(){return true;}
function timed(stage,n,fn){return fn();}
const Checksum={compute(algo,bytes){return 'hash:'+bytes.tag;}};
function snapshotSend(row,bytes){
 if(CASE==='send_failure' && row.sid===225)throw Error('synthetic send failure');
 emitted.push({event:row.event,frame:row.frame,sid:row.sid,tag:bytes.tag,hash:row.sha256});
}
function header(sid,frame){const h=Array(49).fill(0);h[1]=sid;h[7]=100+frame;h[10]=frame;return h;}
function payload(tag){return {isNull(){return false;},readByteArray(n){copies++;return {byteLength:n,tag};}};}
function view(h){return {add(offset){return {readU32(){return h[offset/4]||0;}};}};}
function put(sid,frame){capturePixels(frame,view(header(sid,frame)),payload('input:'+sid+':'+frame),32);}
function node(frame){return {add(offset){return {
 readPointer(){return payload('render:'+(offset===0?224:225)+':'+frame);},
 readU32(){
  if(offset===0x10||offset===0x104)return 24;
  if(offset>=0x124)return header(225,frame)[(offset-0x124)/4]||0;
  return header(224,frame)[(offset-0x28)/4]||0;
 }
 };}};}
"""
    harness = r"""
put(224,0);
if(CASE!=='missing_pair')put(225,0);
put(224,1);
let failure=null;
try{checkRenderPixels(node(0));}catch(e){failure=String(e);}
const first={held:inputSnapshots.size,keys:capturedKeys.size,pairs:capturedPairs};
if(CASE==='two_pairs'){put(225,1);put(224,2);checkRenderPixels(node(1));}
const beforeLate=copies;
if(CASE==='one_pair')put(225,2);
console.log(JSON.stringify({first,held:inputSnapshots.size,keys:capturedKeys.size,pairs:capturedPairs,
 copies,beforeLate,emitted,logs,failure}));
"""
    code = 'const CASE=' + json.dumps(case) + ';\n' + prelude + capture + render + harness
    result = subprocess.run([node, '-e', code], capture_output=True, text=True,
                            check=True, timeout=10)
    return json.loads(result.stdout)


def test_last_pair_retires_unused_samples_after_all_four_emits():
    r = run('one_pair')
    assert r['pairs'] == 1 and r['held'] == r['keys'] == 0
    assert r['copies'] == r['beforeLate']
    assert [(e['event'], e['sid'], e['frame']) for e in r['emitted']] == [
        ('native_pixels', 224, 0), ('native_render_pixels', 224, 0),
        ('native_pixels', 225, 0), ('native_render_pixels', 225, 0)]
    assert all(e['hash'] == 'hash:' + e['tag'] for e in r['emitted'])
    assert r['logs'] == [dict(event='input_samples_retired', count=1, bytes=32,
                              reason='pair_limit_reached')]


def test_future_pair_keeps_prerequisite_until_last_permitted_pair():
    r = run('two_pairs')
    assert r['first'] == dict(held=1, keys=1, pairs=1)
    assert r['held'] == r['keys'] == 0 and r['pairs'] == 2
    assert len(r['emitted']) == 8 and r['emitted'][4]['tag'] == 'input:224:1'
    assert r['logs'][0]['count'] == 1 and r['logs'][0]['bytes'] == 32


@pytest.mark.parametrize('case,held', [('missing_pair', 2), ('byte_limit', 3)])
def test_missing_selection_or_byte_budget_preserves_pending_inputs(case, held):
    r = run(case)
    assert r['held'] == held and r['pairs'] == 0 and not r['emitted']
    assert not r['logs']


def test_partial_send_failure_preserves_unemitted_selected_input():
    r = run('send_failure')
    assert 'synthetic send failure' in r['failure']
    assert r['held'] == r['keys'] == 2
    assert len(r['emitted']) == 2 and not r['logs']
