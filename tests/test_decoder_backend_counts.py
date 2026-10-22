"""Exercise the same bounded accumulator loaded by the private native observer."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

SOURCE = Path(__file__).parents[1] / 'tools/reference_stream/backend-counts.js'
AUDIT = SOURCE.parents[1] / 'app_decoder_backend_counts.cjs'


def run(script):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js required for observer accumulator control')
    result = subprocess.run([node, '-e', SOURCE.read_text() + '\n' + script],
                            capture_output=True, text=True, timeout=10, check=True)
    return json.loads(result.stdout)


def test_context_status_and_attempt_isolation_with_detached_snapshots():
    result = run("""
const a = decoderBackendCounts(), b = decoderBackendCounts();
a.record('0x10', 0); a.record('0x20', -10); a.record('0x10', 0);
b.record('0x10', 5);
const old = a.snapshot(); old.contexts[0].result_counts['0'] = 999;
a.record('0x10', -2147483648);
console.log(JSON.stringify([a.snapshot(), b.snapshot()]));
""")
    assert result == [dict(profile='decoder-backend-counts-v1', valid=True, calls=4,
                          contexts=[dict(context='0x10', result_counts={'0': 2, '-2147483648': 1}),
                                    dict(context='0x20', result_counts={'-10': 1})]),
                      dict(profile='decoder-backend-counts-v1', valid=True, calls=1,
                           contexts=[dict(context='0x10', result_counts={'5': 1})])]


def test_no_backend_call_is_not_an_invented_success():
    assert run('console.log(JSON.stringify(decoderBackendCounts().snapshot()));') == dict(
        profile='decoder-backend-counts-v1', valid=True, calls=0, contexts=[])


@pytest.mark.parametrize('context,result', [
    ('bad', 0), ('0x' + 'a' * 17, 0), ('__proto__', 0), (10, 0),
    ('0x10', True), ('0x10', 0.5), ('0x10', 2**31), ('0x10', -(2**31) - 1),
])
def test_invalid_data_poisons_summary(context, result):
    output = run(f"""
const c = decoderBackendCounts(); let caught = 0;
try {{ c.record({json.dumps(context)}, {json.dumps(result)}); }} catch(e) {{ caught++; }}
try {{ c.record('0x10', 0); }} catch(e) {{ caught++; }}
console.log(JSON.stringify({{caught, summary: c.snapshot()}}));
""")
    assert output['caught'] == 2
    assert output['summary']['valid'] is False
    assert output['summary']['calls'] == 0


@pytest.mark.parametrize('fill,overflow,calls', [
    ("for(let i=0;i<4096;i++)c.record('0x10',0);", "c.record('0x10',0);", 4096),
    ("for(let i=0;i<8;i++)c.record('0x'+i.toString(16),0);", "c.record('0xff',0);", 8),
    ("for(let i=0;i<16;i++)c.record('0x10',i);", "c.record('0x10',16);", 16),
])
def test_limits_retain_prefix_but_invalidate_summary(fill, overflow, calls):
    output = run(f"""
const c = decoderBackendCounts(); {fill}
const before = c.snapshot(); let error = null;
try {{ {overflow} }} catch(e) {{ error = String(e); }}
console.log(JSON.stringify({{before, after:c.snapshot(), error}}));
""")
    assert output['before']['valid'] is True
    assert output['before']['calls'] == output['after']['calls'] == calls
    assert output['before']['contexts'] == output['after']['contexts']
    assert output['after']['valid'] is False
    assert 'limit' in output['error']


def entry(call=1, sid=224):
    meta = [0] * 58
    meta[10], meta[16], meta[19] = sid, 100, 1
    return dict(event='encoded_video', id=call, meta_words=meta)


def backend(call=1, **changes):
    row = dict(event='software_backend_return', id=call, sid=224, raw=100, frame=1,
               codec_context='0x10', result=0)
    return row | changes


def audit(rows):
    return run(f"""
const audit = require({json.dumps(str(AUDIT))});
try {{ console.log(JSON.stringify(audit.summarizeBackendReturns({json.dumps(rows)}))); }}
catch (e) {{ console.log(JSON.stringify({{error:String(e)}})); }}
""")


def test_raw_audit_exact_id_join_keeps_pending_and_native_failure_separate():
    result = audit([entry(), entry(2, 225), backend(), backend(2, sid=225, result=-5),
                    dict(event='encoded_video_return', id=2, result=-10)])
    assert result['backend_returns'] == 2 and result['pending_attempts'] == 1
    a, b = result['attempts']
    assert a['native_result'] is None and a['native_return_observed'] is False
    assert b['native_result'] == -10 and b['native_return_observed'] is True
    assert b['backend_summary']['contexts'][0]['result_counts'] == {'-5': 1}
    assert result['source_completeness'] == 'unknown-from-events-alone'
    assert result['error_cause_identified'] is result['physical_output_verified'] is False


@pytest.mark.parametrize('rows,match', [
    ([backend()], 'orphan'),
    ([entry(), entry()], 'duplicate'),
    ([entry(), backend(raw=101)], 'identity mismatch'),
    ([entry(), backend(sid=225)], 'identity mismatch'),
    ([entry(), backend(frame=2)], 'identity mismatch'),
    ([entry(), dict(event='encoded_video_return', id=1, result=0), backend()], 'completed'),
    ([entry(), dict(event='encoded_video_return', id=1, result=True)], 'invalid native result'),
    ([entry(), dict(event='encoded_video_return', id=1, result=0, backend_summary={})], 'pre-aggregated'),
    ([entry(True)], 'invalid native attempt'),
    ([None], 'object required'),
])
def test_raw_audit_rejects_ambiguous_or_mixed_observations(rows, match):
    assert match in audit(rows)['error']


@pytest.mark.parametrize('content,valid', [
    (b'{}\n', True), (b'{}', True), (b' ' * 8193, False),
    (b'{}\n' * 20001, False), (b'[]\n', False),
])
def test_bounded_file_reader(tmp_path, content, valid):
    path = tmp_path / 'events.jsonl'
    path.write_bytes(content)
    result = run(f"""
const audit = require({json.dumps(str(AUDIT))});
try {{ const rows=audit.readRows({json.dumps(str(path))});
 console.log(JSON.stringify(audit.summarizeBackendReturns(rows))); }}
catch (e) {{ console.log(JSON.stringify({{error:String(e)}})); }}
""")
    assert ('error' not in result) is valid
