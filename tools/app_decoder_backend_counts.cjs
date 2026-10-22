'use strict';
// Offline raw-event audit. No device attach, media access, decoding or output.
const fs = require('node:fs');
const {decoderBackendCounts} = require('./reference_stream/backend-counts.js');

function requireValue(value, message) { if (!value) throw Error(message); }
function int(value, low, high) { return Number.isInteger(value) && value >= low && value <= high; }
function summarizeBackendReturns(rows) {
 requireValue(rows.length <= 20000, 'metadata row limit');
 const attempts = new Map();
 for (const row of rows) {
  requireValue(row !== null && typeof row === 'object' && !Array.isArray(row), 'metadata object required');
  if (!['encoded_video', 'encoded_video_return', 'software_backend_return'].includes(row.event)) continue;
  requireValue(int(row.id, 1, 600), 'invalid native attempt ID');
  if (row.event === 'encoded_video') {
   const m = row.meta_words;
   requireValue(!attempts.has(row.id), 'duplicate native input');
   requireValue(Array.isArray(m) && m.length === 58 && m.every(n => int(n, 0, 4294967295)), 'invalid native metadata');
   requireValue(m[10] === 224 || m[10] === 225, 'unsupported lens');
   attempts.set(row.id, {id:row.id, sid:m[10], raw:m[16], frame:m[19],
    native_return_observed:false, native_result:null, backend:decoderBackendCounts()});
  } else {
   const a = attempts.get(row.id);
   requireValue(a && !a.native_return_observed, 'orphan or already completed native attempt');
   if (row.event === 'software_backend_return') {
    requireValue(row.sid === a.sid && row.raw === a.raw && row.frame === a.frame, 'backend identity mismatch');
    a.backend.record(row.codec_context, row.result);
   } else {
    requireValue(!Object.hasOwn(row, 'backend_summary'), 'expected raw returns, not pre-aggregated input');
    requireValue(int(row.result, -2147483648, 2147483647), 'invalid native result');
    a.native_return_observed = true;
    a.native_result = row.result;
   }
  }
 }
 const result = Array.from(attempts.values(), a => ({id:a.id, sid:a.sid, raw:a.raw, frame:a.frame,
  native_return_observed:a.native_return_observed, native_result:a.native_result,
  backend_summary:a.backend.snapshot()}));
 return {profile:'decoder-backend-audit-v1', metadata_only:true, attempts:result,
  backend_returns:result.reduce((n, a) => n + a.backend_summary.calls, 0),
  pending_attempts:result.filter(a => !a.native_return_observed).length,
  source_completeness:'unknown-from-events-alone', error_cause_identified:false,
  physical_output_verified:false};
}

function readRows(path) {
 const fd = fs.openSync(path, 'r'), buffer = Buffer.alloc(8192), rows = [];
 let tail = Buffer.alloc(0);
 function append(line) {
  requireValue(line.length <= 8192 && rows.length < 20000, 'metadata row/line limit');
  rows.push(JSON.parse(line.toString('utf8')));
 }
 try {
  let size;
  while ((size = fs.readSync(fd, buffer, 0, buffer.length, null)) !== 0) {
   const data = Buffer.concat([tail, buffer.subarray(0, size)]);
   let start = 0, end;
   while ((end = data.indexOf(10, start)) !== -1) {
    append(data.subarray(start, end + 1)); start = end + 1;
   }
   tail = Buffer.from(data.subarray(start));
   requireValue(tail.length <= 8192, 'metadata line limit');
  }
  if (tail.length) append(tail);
 } finally { fs.closeSync(fd); }
 return rows;
}

if (require.main === module) {
 try {
  requireValue(process.argv.length === 3, 'usage: node tools/app_decoder_backend_counts.cjs events.jsonl');
  process.stdout.write(JSON.stringify(summarizeBackendReturns(readRows(process.argv[2])), null, 2) + '\n');
 } catch (error) { process.stderr.write(String(error) + '\n'); process.exitCode = 1; }
}
module.exports = {summarizeBackendReturns, readRows};
