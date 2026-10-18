'use strict';
// The Python owner verifies exact ELF hashes before loading this script.
if (!REFERENCE_CONFIG.verified || Process.arch !== 'arm' || Process.pointerSize !== 4)
 throw Error('unverified reference build/ABI');
const pairLimit=REFERENCE_CONFIG.pairs, pixelLimit=240*1024*1024;

const p=Process.getModuleByName('libPlayCtrl.so'),mem=Memory.alloc(8),clk=new NativeFunction(Process.getModuleByName('libc.so').getExportByName('clock_gettime'),'int',['int','pointer'],{scheduling:'exclusive'});
function mono(){clk(1,mem);return mem.readU32()*1e9+mem.add(4).readU32();}
let queue=[],seq=0,stopped=false;let pixelBytes=0;const samples=new Map(),sampleCounts=new Map();const contexts=new Map(),objects=new Map(),dataQueues=new Set();
function log(event,fields){const record=Object.assign({event,device_mono_ns:mono()},fields);if(!stopped){if(queue.length>=20000){stopped=true;send({event:'error',device_mono_ns:mono(),message:'metadata queue limit'});}else queue.push(record);}}
function timed(stage,bytes,fn){const start=mono();let ok=false;try{const result=fn();ok=true;return result;}finally{log('stage_timing',{stage,bytes,started_ns:start,completed_ns:mono(),successful:ok});}}
function flush(){if(queue.length){const batch=queue;queue=[];send({batch});}}
setInterval(flush,250);
function sym(pattern){const a=p.enumerateExports().filter(e=>pattern.test(e.name));if(a.length!==1)throw Error('Symbol '+pattern+' count '+a.length);return a[0].address;}
function parent(tid){let s=contexts.get(tid)||[];return s[s.length-1]||null;}
function node(n){if(n.isNull())return null;return {ptr:n.toString(),media_ms:n.add(0x3c).readU32(),raw:n.add(0x44).readU32(),frame:n.add(0x50).readU32(),sid:n.add(0x2c).readU32(),complete:n.add(0xf0).readU32(),secondary_media_ms:n.add(0x138).readU32(),secondary_raw:n.add(0x140).readU32(),secondary_frame:n.add(0x14c).readU32(),secondary_sid:n.add(0x128).readU32()};}
function sourceKey(sid,raw,frame){return [sid,raw,frame].join(':');}
function readable(p,n){const r=Process.findRangeByAddress(p);return r&&r.protection.indexOf('r')>=0&&p.add(n).compare(r.base.add(r.size))<=0;}
let capturedPairs=0;const inputSnapshots=new Map(),capturedKeys=new Set();
function capturePixels(id,v,ptr,n){
 if(stopped||capturedPairs>=pairLimit||ptr.isNull()||n<=0||n>12582912||!readable(ptr,n))return;
 const h=Array.from({length:49},(_,i)=>v.add(i*4).readU32());
 if(h[1]!==224&&h[1]!==225)return;
 const k=sourceKey(h[1],h[7],h[10]);
 if(inputSnapshots.size>=24){const oldest=inputSnapshots.keys().next().value;inputSnapshots.delete(oldest);log('input_sample_evicted',{key:oldest});}
 inputSnapshots.set(k,{call:id,header:h,bytes:timed('input_snapshot_copy',n,()=>ptr.readByteArray(n)),at:mono()});capturedKeys.add(k);
}
// Lossless transport only: the host still receives and audits both full snapshots.
let zipBound=null,zipCompress=null;
const transport=REFERENCE_CONFIG.transport||'raw';
if(transport==='zlib'){
 const z=Module.load('libz.so');
 zipBound=new NativeFunction(z.getExportByName('compressBound'),'uint',['uint'],{scheduling:'exclusive'});
 zipCompress=new NativeFunction(z.getExportByName('compress2'),'int',['pointer','pointer','pointer','uint','int'],{scheduling:'exclusive'});
}else if(transport==='lz4'){
 const z=Module.load('liblz4.so');
 zipBound=new NativeFunction(z.getExportByName('LZ4_compressBound'),'int',['int'],{scheduling:'exclusive'});
 zipCompress=new NativeFunction(z.getExportByName('LZ4_compress_default'),'int',['pointer','pointer','int','int'],{scheduling:'exclusive'});
}else if(transport!=='raw')throw Error('unsupported snapshot transport');
function snapshotSend(row,bytes){
 if(zipCompress){
  const compressed=timed('snapshot_compression',bytes.byteLength,()=>{
   const bound=zipBound(bytes.byteLength);
   if(bound>12*1024*1024+65536)throw Error('compressed buffer bound');
   const input=Memory.alloc(bytes.byteLength),out=Memory.alloc(bound),length=Memory.alloc(4);
   input.writeByteArray(bytes);length.writeU32(bound);
   let size;
   if(transport==='zlib'){
    if(zipCompress(out,length,input,bytes.byteLength,1)!==0)throw Error('compression failed');
    size=length.readU32();
   }else size=zipCompress(input,out,bytes.byteLength,bound);
   if(size<=0)throw Error('compression failed');
   if(size>bound)throw Error('compressed buffer length');
   return size<bytes.byteLength?out.readByteArray(size):null;
  });
  if(compressed){send(Object.assign({},row,{encoding:transport,transport_bytes:compressed.byteLength}),compressed);return;}
 }
 send(row,bytes);
}
function checkRenderPixels(n){
 if(capturedPairs>=pairLimit||stopped)return;
 const selected=[];
 for(const[base,meta]of[[0,0x28],[0xf4,0x124]]){
  const h=Array.from({length:49},(_,i)=>n.add(meta+i*4).readU32());
  const k=sourceKey(h[1],h[7],h[10]),source=inputSnapshots.get(k);
  const ptr=n.add(base).readPointer(),size=n.add(base+0x10).readU32();
  if(!source||ptr.isNull()||size<=0||size>12582912||!readable(ptr,size))return;
  selected.push({key:k,source,header:h,bytes:timed('render_snapshot_copy',size,()=>ptr.readByteArray(size))});
 }
 const size=selected.reduce((n,s)=>n+s.source.bytes.byteLength+s.bytes.byteLength,0);
 if(pixelBytes+size>pixelLimit)return;
 capturedPairs++;pixelBytes+=size;flush();
 for(const s of selected){
  const h=s.source.header,hash=timed('input_snapshot_hash',s.source.bytes.byteLength,()=>Checksum.compute('sha256',s.source.bytes));
  timed('input_snapshot_send',s.source.bytes.byteLength,()=>snapshotSend({event:'native_pixels',device_mono_ns:s.source.at,call:s.source.call,sid:h[1],raw:h[7],frame:h[10],bytes:s.source.bytes.byteLength,sha256:hash,header_words:h},s.source.bytes));
  const renderHash=timed('render_snapshot_hash',s.bytes.byteLength,()=>Checksum.compute('sha256',s.bytes));
  timed('render_snapshot_send',s.bytes.byteLength,()=>snapshotSend({event:'native_render_pixels',device_mono_ns:mono(),sid:h[1],raw:h[7],frame:h[10],bytes:s.bytes.byteLength,input_bytes:s.source.bytes.byteLength,sha256:renderHash,input_sha256:hash,header_words:s.header},s.bytes));
  inputSnapshots.delete(s.key);capturedKeys.delete(s.key);
 }
}
function register(o){objects.set(o.toString(),o);for(const off of[0x1a0,0x1a4]){const q=o.add(off).readPointer();if(!q.isNull())dataQueues.add(q.toString());}}
function error(where,e){log('error',{where,message:String(e)});}
Interceptor.attach(p.getExportByName('PlayM4_SyncToAudio'),{onEnter(a){log('sync',{enabled:a[1].toInt32()});}});
Interceptor.attach(sym(/CMPManager9VideoPlayE/),{onEnter(a){this.id=++seq;this.tid=this.threadId;this.o=a[0];let s=contexts.get(this.tid)||[];s.push(this.id);contexts.set(this.tid,s);try{log('schedule_enter',{call:this.id,arg1:a[1].toUInt32(),picture_ms:a[2].toUInt32(),elapsed_ms:a[3].toUInt32(),frame_speed:this.context.sp.readFloat(),speed:this.o.add(0x2c0).readFloat(),bias:this.o.add(0x2bc).readU32(),origin_ms:this.o.add(0x2b4).readU32(),pending_rebase:this.o.add(0x2b0).readU32(),node_limit:this.o.add(0x378).readU32(),smooth:this.o.add(0x2e4).readU32(),adjust:this.o.add(0x31c).readS32(),mode:this.o.add(0x278).readU32(),frame_interval:this.o.add(0xcc).readU32(),sync:this.o.add(0x358).readU32()});}catch(e){error('schedule',e);}},onLeave(r){log('schedule_return',{call:this.id,result:r.toInt32()});contexts.get(this.tid).pop();}});
for(const [pattern,kind]of [[/CMPManager15DisplayOneFrameE/,'display_request'],[/CVideoDisplay17ThrowOneFrameDataEv/,'drop_request'],[/CVideoDisplay29RenderData_AssignedYuvAddressE/,'assigned_render'],[/CVideoDisplay22RenderData_CopyYuvDataE/,'copy_render']]){
 Interceptor.attach(sym(pattern),{onEnter(a){this.id=++seq;log(kind,{call:this.id,schedule:parent(this.threadId),obj:a[0].toString(),caller:this.returnAddress.sub(p.base).toString()});},onLeave(r){log(kind+'_return',{call:this.id,result:r.toInt32()});}});
}
Interceptor.attach(sym(/CVideoDisplay14FillupDataNodeE/),{onEnter(a){this.o=a[0];this.n=a[1];this.v=a[2];this.id=++seq;register(this.o);this.desc={sid:this.v.add(4).readU32(),media_ms:this.v.add(0x14).readU32(),raw:this.v.add(0x1c).readU32(),frame:this.v.add(0x28).readU32()};},onLeave(r){try{log('fill',{call:this.id,obj:this.o.toString(),source:this.desc,node:node(this.n),result:r.toInt32()});}catch(e){error('fill',e);}}});
for(const [pattern,kind]of [[/CVideoDisplay22CountRenderDataTimeUseE/,'render_callback'],[/CVideoDisplay32ThrowMultiDataNodeAndReturnFrameE/,'multi_discard'],[/CVideoDisplay35ReturnDecodedFrameAndSaveLastBufferE/,'return_decoded']]){
 Interceptor.attach(sym(pattern),{onEnter(a){try{register(a[0]);if(kind==='render_callback')checkRenderPixels(a[1]);log(kind,{schedule:parent(this.threadId),obj:a[0].toString(),node:node(a[1]),caller:this.returnAddress.sub(p.base).toString()});}catch(e){error(kind,e);}}});
}
Interceptor.attach(sym(/CVideoDisplay23MultiTrack_DataNodeCopyE/),{onEnter(a){try{log('node_copy',{obj:a[0].toString(),dst:a[1].toString(),source:node(a[2])});}catch(e){error('node_copy',e);}}});
Interceptor.attach(sym(/CDataCtrl11GetDataNodeEv/),{onEnter(a){this.active=dataQueues.has(a[0].toString());this.q=a[0];this.caller=this.returnAddress.sub(p.base).toString();},onLeave(r){if(!this.active)return;try{log('node_peek',{queue:this.q.toString(),schedule:parent(this.threadId),node:node(r),caller:this.caller});}catch(e){error('node_peek',e);}}});
Interceptor.attach(sym(/CDataCtrl10CommitReadEv/),{onEnter(a){if(dataQueues.has(a[0].toString()))log('node_commit',{queue:a[0].toString(),schedule:parent(this.threadId),caller:this.returnAddress.sub(p.base).toString()});}});
Interceptor.attach(sym(/CRenderer12GetNodeCountE/),{onEnter(a){this.a=a[1];this.b=a[2];this.id=parent(this.threadId);},onLeave(r){if(this.id)log('node_count',{schedule:this.id,result:r.toInt32(),data:this.a.readU32(),spare:this.b.readU32()});}});
Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('usleep'),{onEnter(a){let c=parent(this.threadId);if(c)log('sleep',{schedule:c,usec:a[0].toUInt32(),caller:this.returnAddress.sub(p.base).toString()});}});
Interceptor.attach(sym(/CVideoDisplay28InputData_AssignedYuvAddressE/),{onEnter(a){this.id=++seq;try{register(a[0]);let v=a[3];log('decoded_picture',{call:this.id,obj:a[0].toString(),sid:v.add(4).readU32(),media_ms:v.add(0x14).readU32(),raw:v.add(0x1c).readU32(),frame:v.add(0x28).readU32(),payload_is_null:a[1].isNull(),payload_bytes:a[2].toUInt32(),codec:v.add(0x84).readU32(),tracks:v.add(0x8c).readU32(),header_words:Array.from({length:49},(_,i)=>v.add(i*4).readU32())});capturePixels(this.id,v,a[1],a[2].toUInt32());}catch(e){error('decoded_picture',e);}},onLeave(r){log('decoded_picture_return',{call:this.id,result:r.toInt32()});}});
const pendingCopies=new Map();
Interceptor.attach(sym(/CVideoDisplay23MultiTrack_DataNodeCopyE/),{onEnter(a){pendingCopies.set(this.threadId,{dst:a[1].toString(),node:node(a[2])});}});
Interceptor.attach(sym(/CDataCtrl11CommitWriteEv/),{onEnter(a){this.active=this.returnAddress.sub(p.base).toString()==='0x147ca7';if(this.active){this.q=a[0].toString();this.copy=pendingCopies.get(this.threadId)||null;}},onLeave(r){if(this.active){log('video_queue_admitted',{queue:this.q,copy:this.copy,result:r.toInt32()});pendingCopies.delete(this.threadId);}}});
Interceptor.attach(sym(/CRenderer35MultiTrack_PushDataToRenderDataListE/),{onEnter(){this.caller=this.returnAddress.sub(p.base).toString();},onLeave(r){log('staging_return',{caller:this.caller,result:r.toInt32()});}});

const ez=Process.getModuleByName('libezstreamclient.so');
const display=ez.enumerateExports().filter(e=>e.name==='_Z22onMediaDisplayCallbackPciiiiPv');
if(display.length===1)Interceptor.attach(display[0].address,{onEnter(a){log('app_display',{bytes:a[1].toUInt32(),width:a[2].toInt32(),height:a[3].toInt32(),media_ms:a[4].toUInt32()});}});
function colourSym(part){return sym(new RegExp(part));}
const cActive=new Map(),cNative=new Map();let cCount=0;
Interceptor.attach(colourSym('CGLESRender15UpdateFrameData'),{onEnter(a){this.tid=this.threadId;const native=cNative.get(this.tid);this.c=capturedPairs<pairLimit&&!!native&&capturedKeys.has(sourceKey(native.header.sid,native.header.raw,native.header.frame)); if(this.c){this.id=++seq;cActive.set(this.tid,{id:this.id,base:a[1]});log('update',{id:this.id,format:a[0].add(4).readU32(),width:a[2].toInt32(),height:a[3].toInt32(),cNative:cNative.get(this.tid)?{header:cNative.get(this.tid).header,payload_matches:a[1].equals(cNative.get(this.tid).payload)}:null});}},onLeave(r){if(this.c){log('update_return',{id:this.id,result:r.toInt32()});cActive.delete(this.tid);}}});
Interceptor.attach(colourSym('GLESTexture7SetData'),{onEnter(a){const c=cActive.get(this.threadId);if(c)log('plane_upload',{id:c.id,width:a[1].toInt32(),height:a[2].toInt32(),format:a[3].toInt32(),offset:this.context.sp.readPointer().sub(c.base).toInt32(),texture:a[0].add(0x10).readU32()});}});
let cShaders=0;Interceptor.attach(colourSym('GLESShaderManager10InitShader'),{onEnter(a){if(cShaders++<6)log('shader',{vertex:a[1].readUtf8String(),fragment:a[2].readUtf8String()});}});
let cSamplers=0;Interceptor.attach(colourSym('GLESShaderManager10SetTexture'),{onEnter(a){if(cActive.has(this.threadId))log('sampler',{name:a[1].readUtf8String(),arg2:a[2].toInt32(),arg3:a[3].toInt32()});}});
let cRender=0;Interceptor.attach(colourSym('CAndroidRender7DisplayE'),{onEnter(a){this.tid=this.threadId;const lens=a[0].add(8).readU32(),node=a[1],h=node.add(lens===0?0x28:0x124),payload=node.add(lens===0?0:0xf4).readPointer();cNative.set(this.tid,{header:{sid:h.add(4).readU32(),raw:h.add(0x1c).readU32(),frame:h.add(0x28).readU32()},payload});if(cRender++<4)log('android_display',{format:a[0].add(0x14).readU32(),engine:a[0].add(0xc).readU32(),output_type:a[0].add(0x13c).readU32(),lens});},onLeave(){cNative.delete(this.tid);}});

let audioSeq=0,audioBytes=0;
function audioBlob(event,ptr,n,fields){if(stopped||n!==2048||audioBytes+n>8388608)return;audioBytes+=n;const bytes=ptr.readByteArray(n);flush();send(Object.assign({event,device_mono_ns:mono(),bytes:n,sha256:Checksum.compute('sha256',bytes)},fields),bytes);}
Interceptor.attach(sym(/CAudioPlay9InputData/),{onEnter(a){try{audioBlob('audio_decoded',a[1],a[2].toUInt32(),{id:++audioSeq,media_ms:a[3].add(0x14).readU32(),rate:a[3].add(4).readU32()});}catch(e){error('decoded_audio',e);}}});
const audioFormats=new Map();
Interceptor.attach(ez.getExportByName('ezviz_vqe_create_handle'),{onEnter(a){this.format={rate:a[0].toInt32(),samples:a[1].toInt32(),channels:a[2].toInt32()};},onLeave(r){audioFormats.set(r.toString(),this.format);log('vqe_format',this.format);}});
Interceptor.attach(ez.getExportByName('ezviz_vqe_process'),{onEnter(a){this.id=++audioSeq;this.out=a[2];const f=audioFormats.get(a[0].toString());this.valid=!!f&&f.rate===16000&&f.samples===1024&&f.channels===1;if(!this.valid){log('vqe_unverified_format',{call:this.id});return;}try{audioBlob('audio_vqe_input',a[1],2048,{call:this.id});}catch(e){error('vqe_input',e);}},onLeave(r){if(!this.valid)return;try{if(r.toInt32()===0&&!this.out.readPointer().isNull())audioBlob('audio_vqe_output',this.out.readPointer(),2048,{call:this.id,status:r.toInt32()});else log('vqe_failure',{call:this.id,status:r.toInt32()});}catch(e){error('vqe_output',e);}}});

rpc.exports={finish(){stopped=true;flush();return {bytes:pixelBytes,capturedPairs};}};log('ready',{});flush();
