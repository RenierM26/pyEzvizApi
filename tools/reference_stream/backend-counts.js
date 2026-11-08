'use strict';
// Metadata only. One instance per native input attempt, not per lens or thread.
// These are API-return counts, never decoded-frame or physical-output counts.
function decoderBackendCounts() {
 const contexts = new Map();
 let calls = 0, failed = false;
 function invalid(message) { failed = true; throw Error(message); }
 return {
  record(context, result) {
   if (failed) throw Error('backend summary already invalid');
   if (typeof context !== 'string' || !/^0x[0-9a-f]{1,16}$/.test(context))
    invalid('invalid codec context');
   if (!Number.isInteger(result) || result < -2147483648 || result > 2147483647)
    invalid('invalid backend result');
   if (calls >= 4096) invalid('backend call limit');
   if (!contexts.has(context) && contexts.size >= 8) invalid('backend context limit');
   const counts = contexts.get(context) || new Map();
   if (!counts.has(result) && counts.size >= 16) invalid('backend status limit');
   counts.set(result, (counts.get(result) || 0) + 1);
   contexts.set(context, counts);
   calls++;
  },
  snapshot() {
   return {
    profile: 'decoder-backend-counts-v1', valid: !failed, calls,
    contexts: Array.from(contexts, ([context, counts]) => ({
     context, result_counts: Object.fromEntries(counts)
    }))
   };
  }
 };
}
if (typeof module !== 'undefined') module.exports = {decoderBackendCounts};
