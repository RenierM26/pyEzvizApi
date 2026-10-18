'use strict';
// No waits, payload retention, flow control or clock synchronization.
function snapshotAcknowledgements(enabled, clock, emit, receive, record, fail) {
 const sent = new Map();
 let frozen = false;
 function listen() {
  receive('snapshot-ack', message => {
   if (frozen) return;
   listen();
   try {
    const id = message.payload && message.payload.id, item = sent.get(id);
    if (!Number.isInteger(id) || !item || item.acknowledged_ns !== null)
     throw Error('unknown or duplicate snapshot acknowledgement');
    item.acknowledged_ns = clock();
    record('transport_ack', {transport_id:id, stage:'snapshot_send_to_ack',
     started_ns:item.started_ns, completed_ns:item.acknowledged_ns,
     bytes:item.transport_bytes, successful:true});
   } catch (e) { fail('transport_ack', e); }
  });
 }
 if (enabled) listen();
 return {
  send(row, bytes) {
   if (!enabled) { emit(row, bytes); return; }
   if (frozen || sent.size >= 32) throw Error('snapshot acknowledgement limit');
   const id = sent.size + 1;
   const item = {transport_id:id, event:row.event, encoding:row.encoding || 'raw',
    transport_bytes:bytes.byteLength, started_ns:clock(),
    send_returned_ns:null, acknowledged_ns:null};
   sent.set(id, item);
   emit(Object.assign({}, row, {transport_id:id}), bytes);
   item.send_returned_ns = clock();
  },
  finish() {
   frozen = true;
   return {enabled, clock:'device-monotonic', sent:Array.from(sent.values()),
    pending_ids:Array.from(sent.values()).filter(r => r.acknowledged_ns === null).map(r => r.transport_id)};
  }
 };
}
