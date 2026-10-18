"""Native crop snapshots use distinct chroma planes, never grayscale-only controls."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'app_native_pixel_audit.py'
MODULE = runpy.run_path(str(TOOL))


def sample():
    before = [0] * 49
    for i, value in {0: 3, 1: 224, 3: 8, 4: 8, 5: 66, 7: 3000, 10: 1,
                     33: 133, 34: 3, 35: 2, 37: 8, 38: 8, 39: 2}.items():
        before[i] = value
    after = before.copy()
    after[4] = 6
    source = bytes(range(64)) + bytes(range(80, 96)) + bytes(range(160, 176))
    rendered = source[:48] + source[64:76] + source[80:92]
    row = dict(id='sample:0', input_header=before, render_header=after,
               input_offset=0, render_offset=0,
               input_sha256=hashlib.sha256(source).hexdigest(),
               render_sha256=hashlib.sha256(rendered).hexdigest())
    return row, source, rendered


def run_audit(row, source, rendered):
    return MODULE['audit'](io.BytesIO(source), io.BytesIO(rendered),
                           io.BytesIO((json.dumps(row) + '\n').encode()))


def test_distinct_native_planes_crop_preserves_order():
    row, source, rendered = sample()
    report = run_audit(row, source, rendered)
    assert report['samples_verified'] == 1
    assert report['input_bytes'] == 96
    assert report['render_bytes'] == 72
    assert report['chroma_order_verified'] is False
    assert report['physical_display_verified'] is False
    assert report['provenance'] == 'caller-manifest-not-authenticated'
    result = report['samples'][0]
    assert result['ordered_plane_sha256'] == [hashlib.sha256(p).hexdigest() for p in
                                             (source[:48], source[64:76], source[80:92])]
    assert result['raw_timestamp'] == 3000
    assert result['media_ms'] == 66


@pytest.mark.parametrize('change', ['swap', 'interleave', 'luma', 'chroma'])
def test_pixel_mismatch_even_with_self_consistent_capture_hash(change):
    row, source, rendered = sample()
    if change == 'swap':
        rendered = rendered[:48] + rendered[60:] + rendered[48:60]
    elif change == 'interleave':
        rendered = rendered[:48] + bytes(v for pair in zip(rendered[48:60], rendered[60:],
                                                           strict=True) for v in pair)
    else:
        data = bytearray(rendered)
        data[0 if change == 'luma' else 60] ^= 1
        rendered = bytes(data)
    row['render_sha256'] = hashlib.sha256(rendered).hexdigest()
    with pytest.raises(ValueError, match='differ from ordered planar'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize(('index', 'value'), [(0, 2), (1, 226), (3, 10), (4, 10),
    (33, 4), (34, 1), (35, 1), (37, 0), (37, 7), (37, 4098), (38, 7), (39, 1),
    (39, 8), (40, 2), (41, 2), (42, 2)])
def test_unsupported_native_layout(index, value):
    row, source, rendered = sample()
    row['input_header'][index] = value
    with pytest.raises(ValueError, match='unsupported native planar'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize('index', [1, 5, 7, 10, 39, 43])
def test_changed_header_identity_or_geometry(index):
    row, source, rendered = sample()
    row['render_header'][index] += 1
    with pytest.raises(ValueError, match='preserve every word'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize('value', [[], [0] * 48, [0] * 50, [True] * 49, [-1] * 49,
                                    [2**32] * 49, None])
def test_bad_descriptor(value):
    row, source, rendered = sample()
    row['input_header'] = value
    with pytest.raises(ValueError, match='49 uint32'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize('field', ['input_sha256', 'render_sha256'])
def test_capture_hash_tampering(field):
    row, source, rendered = sample()
    row[field] = '0' * 64
    with pytest.raises(ValueError, match='digest mismatch'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize('field', ['input_offset', 'render_offset'])
@pytest.mark.parametrize('value', [True, -1, 1, 0.0])
def test_contiguous_exact_offsets(field, value):
    row, source, rendered = sample()
    row[field] = value
    with pytest.raises(ValueError, match='contiguous complete'):
        run_audit(row, source, rendered)


@pytest.mark.parametrize('side', [0, 1])
@pytest.mark.parametrize('extra', [False, True])
def test_truncated_or_unaccounted_bytes(side, extra):
    row, source, rendered = sample()
    data = [source, rendered]
    data[side] = data[side] + b'X' if extra else data[side][:-1]
    with pytest.raises(ValueError, match='coverage' if extra else 'byte length'):
        run_audit(row, *data)


def test_multiple_samples_and_duplicate_rejection():
    row, source, rendered = sample()
    second = deepcopy(row)
    second.update(id='sample:1', input_offset=len(source), render_offset=len(rendered))
    second['input_header'][1] = second['render_header'][1] = 225
    manifest = '\n'.join(json.dumps(r) for r in (row, second)).encode()
    report = MODULE['audit'](io.BytesIO(source * 2), io.BytesIO(rendered * 2), io.BytesIO(manifest))
    assert [r['lens'] for r in report['samples']] == [0, 1]
    second['id'] = row['id']
    with pytest.raises(ValueError, match='unique bounded'):
        MODULE['audit'](io.BytesIO(source * 2), io.BytesIO(rendered * 2),
                        io.BytesIO('\n'.join(json.dumps(r) for r in (row, second)).encode()))


@pytest.mark.parametrize('payload', [b'', b'[]', b'null', b'{' , b' ' * 8193])
def test_bad_or_empty_manifest(payload):
    with pytest.raises(ValueError):
        MODULE['audit'](io.BytesIO(), io.BytesIO(), io.BytesIO(payload))


def test_total_and_sample_limits(monkeypatch):
    row, source, rendered = sample()
    monkeypatch.setitem(MODULE['audit'].__globals__, 'MAX_TOTAL_BYTES', 100)
    with pytest.raises(ValueError, match='total byte limit'):
        run_audit(row, source, rendered)
    monkeypatch.setitem(MODULE['audit'].__globals__, 'MAX_TOTAL_BYTES', 1000)
    monkeypatch.setitem(MODULE['audit'].__globals__, 'MAX_SAMPLES', 0)
    with pytest.raises(ValueError, match='manifest limit'):
        run_audit(row, source, rendered)


def test_cli_private_files_and_failure(tmp_path):
    row, source, rendered = sample()
    paths = [tmp_path / name for name in ('input.bin', 'render.bin', 'map.jsonl')]
    for path, data in zip(paths, (source, rendered, json.dumps(row).encode()), strict=True):
        path.write_bytes(data)
    result = subprocess.run([sys.executable, str(TOOL), *map(str, paths)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['samples_verified'] == 1
    paths[1].write_bytes(b'')
    result = subprocess.run([sys.executable, str(TOOL), *map(str, paths)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert not result.stdout
    assert 'native pixel audit failed:' in result.stderr


@pytest.mark.parametrize('case', json.loads((TOOL.parents[1] / 'tests' / 'fixtures' /
                                            'app_native_crop_oracle.json').read_text()))
def test_original_arm_coloured_plane_controls(case):
    row, _, _ = sample()
    width, height, bottom = case['width'], case['height'], case['bottom']
    visible = height - bottom
    y = bytes((i * 17 + 3) % 256 for i in range(width * height))
    first = bytes((i * 7 + 51) % 256 for i in range(width * height // 4))
    second = bytes((i * 11 + 149) % 256 for i in range(width * height // 4))
    source = y + first + second
    rendered = y[:width * visible] + first[:width * visible // 4] + second[:width * visible // 4]
    assert len(rendered) == case['bytes']
    assert hashlib.sha256(rendered).hexdigest() == case['sha256']
    for field in ('input_header', 'render_header'):
        for index, value in {3: width, 4: height, 37: width, 38: height, 39: bottom}.items():
            row[field][index] = value
    row['render_header'][4] = visible
    row.update(input_sha256=hashlib.sha256(source).hexdigest(), render_sha256=case['sha256'])
    assert run_audit(row, source, rendered)['samples_verified'] == 1


def test_zero_bottom_crop():
    row, source, _ = sample()
    row['input_header'][39] = row['render_header'][39] = 0
    row['render_header'][4] = 8
    row['render_sha256'] = row['input_sha256']
    assert run_audit(row, source, source)['samples'][0]['bottom_rows'] == 0


def renderer_sample():
    row, source, rendered = sample()
    row['renderer_layout'] = dict(renderer_format=1, width=8, height=6, sid=224,
        raw_timestamp=3000, frame_index=1, payload_matches=True,
        uploads=[dict(offset=offset, width=width, height=height, format=5, texture=index + 1)
                 for index, (offset, width, height) in enumerate([(0, 8, 6), (60, 4, 3), (48, 4, 3)])],
        samplers=[dict(name=name, unit=index, texture=index + 1)
                  for index, name in enumerate(('Ytexture', 'Utexture', 'Vtexture'))])
    return row, source, rendered


def run_renderer_audit(row, source, rendered, enabled=True):
    return MODULE['audit'](io.BytesIO(source), io.BytesIO(rendered),
                           io.BytesIO(json.dumps(row).encode()), verify_renderer=enabled)


def test_explicit_renderer_binding_fingerprint():
    row, source, rendered = renderer_sample()
    report = run_renderer_audit(row, source, rendered)
    assert report['chroma_order_verified'] is True
    assert report['chroma_order_source'] == 'caller-render-observations-native-format-1-profile'
    assert report['provenance'] == 'caller-manifest-not-authenticated'
    result = report['samples'][0]
    canonical = rendered[:48] + rendered[60:] + rendered[48:60]
    assert result['canonical_pixel_sha256'] == hashlib.sha256(canonical).hexdigest()
    assert result['canonical_pixel_sha256'] != result['render_sha256']
    assert result['native_pixel_format'] == 'yvu420p'
    assert result['canonical_pixel_format'] == 'yuv420p'
    assert result['canonical_plane_sha256'] == [hashlib.sha256(p).hexdigest()
                                               for p in (rendered[:48], rendered[60:], rendered[48:60])]


def test_crop_only_does_not_infer_chroma_order_from_optional_fields():
    row, source, rendered = renderer_sample()
    row['renderer_layout']['renderer_format'] = 3
    report = run_renderer_audit(row, source, rendered, enabled=False)
    assert report['chroma_order_verified'] is False
    assert report['chroma_order_source'] is None
    assert 'canonical_pixel_sha256' not in report['samples'][0]


@pytest.mark.parametrize(('key', 'value'), [('renderer_format', 3), ('renderer_format', True),
    ('width', 10), ('height', 8), ('sid', 225), ('raw_timestamp', 3001), ('frame_index', 2),
    ('payload_matches', False), ('payload_matches', 1)])
def test_renderer_rejects_wrong_profile_or_identity(key, value):
    row, source, rendered = renderer_sample()
    row['renderer_layout'][key] = value
    with pytest.raises(ValueError, match='format 1 and exact native picture'):
        run_renderer_audit(row, source, rendered)


@pytest.mark.parametrize('value', [None, {}, [], 1])
def test_renderer_mode_requires_explicit_observations(value):
    row, source, rendered = renderer_sample()
    row['renderer_layout'] = value
    with pytest.raises(ValueError):
        run_renderer_audit(row, source, rendered)


@pytest.mark.parametrize('key', ['uploads', 'samplers'])
@pytest.mark.parametrize('value', [None, [], [{}, {}], [{}, {}, {}, {}]])
def test_renderer_rejects_incomplete_or_extra_bindings(key, value):
    row, source, rendered = renderer_sample()
    row['renderer_layout'][key] = value
    with pytest.raises(ValueError, match='three ordered'):
        run_renderer_audit(row, source, rendered)


@pytest.mark.parametrize(('key', 'value'), [('offset', 48), ('offset', 60.0), ('width', 8),
    ('height', 6), ('format', 6), ('texture', True), ('texture', 0), ('texture', 2**32),
    ('texture', 1)])
def test_renderer_rejects_wrong_plane_upload(key, value):
    row, source, rendered = renderer_sample()
    row['renderer_layout']['uploads'][1][key] = value
    with pytest.raises(ValueError, match='native format-1 YVU profile'):
        run_renderer_audit(row, source, rendered)


@pytest.mark.parametrize(('key', 'value'), [('name', 'Vtexture'), ('unit', 2), ('unit', True),
                                           ('texture', 3), ('texture', 2.0)])
def test_renderer_rejects_wrong_sampler_binding(key, value):
    row, source, rendered = renderer_sample()
    row['renderer_layout']['samplers'][1][key] = value
    with pytest.raises(ValueError, match='sampler is not bound'):
        run_renderer_audit(row, source, rendered)


@pytest.mark.parametrize('case', json.loads((TOOL.parents[1] / 'tests' / 'fixtures' /
                                            'app_native_texture_oracle.json').read_text()))
def test_original_arm_upload_selection_controls(case):
    row, _, _ = renderer_sample()
    width, height = case['width'], case['height']
    pixels = width * height
    source = (bytes((i * 17 + 3) % 256 for i in range(pixels))
              + bytes((i * 7 + 51) % 256 for i in range(pixels // 4))
              + bytes((i * 11 + 149) % 256 for i in range(pixels // 4)))
    for field in ('input_header', 'render_header'):
        for index, value in {3: width, 4: height, 37: width, 38: height, 39: 0}.items():
            row[field][index] = value
    row.update(input_sha256=hashlib.sha256(source).hexdigest(),
               render_sha256=hashlib.sha256(source).hexdigest())
    layout = row['renderer_layout']
    layout.update(width=width, height=height)
    layout['uploads'] = [dict(offset=u['offset'], width=u['width'], height=u['height'],
                              format=u['format'], texture=u['slot'] + 1) for u in case['uploads']]
    # Each native upload digest independently validates the retained control bytes.
    for upload in case['uploads']:
        offset = upload['offset']
        assert hashlib.sha256(source[offset:offset + upload['width'] * upload['height']]).hexdigest() == upload['sha256']
    if case['renderer_format'] == 1:
        result = run_renderer_audit(row, source, source)['samples'][0]
        assert result['canonical_plane_sha256'] == [u['sha256'] for u in case['uploads']]
    else:
        # Native format 3 uses opposite chroma offsets; never accept it as format 1.
        with pytest.raises(ValueError, match='native format-1 YVU profile'):
            run_renderer_audit(row, source, source)


def test_renderer_cli_opt_in(tmp_path):
    row, source, rendered = renderer_sample()
    paths = [tmp_path / name for name in ('input.bin', 'render.bin', 'map.jsonl')]
    for path, data in zip(paths, (source, rendered, json.dumps(row).encode()), strict=True):
        path.write_bytes(data)
    result = subprocess.run([sys.executable, str(TOOL), *map(str, paths), '--verify-yv12-renderer'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['chroma_order_verified'] is True
    row.pop('renderer_layout')
    paths[2].write_text(json.dumps(row))
    result = subprocess.run([sys.executable, str(TOOL), *map(str, paths), '--verify-yv12-renderer'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert not result.stdout
