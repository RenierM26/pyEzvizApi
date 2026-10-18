'use strict';
function probePayload(size,pattern){
 if(!Number.isInteger(size)||size<1||size>12*1024*1024||!['mixed-v1','striped-v1','noise-v1'].includes(pattern))throw Error('invalid synthetic payload');
 const bytes=new Uint8Array(size);let state=0x12345678;
 for(let i=0;i<size;i++){
  state=(Math.imul(state,1664525)+1013904223)>>>0;
  const striped=pattern==='striped-v1'||(pattern==='mixed-v1'&&((i>>>12)%3)===0);
  bytes[i]=striped?(i*17+(i>>>12))&255:state>>>24;
 }
 return bytes.buffer;
}
function createDeviceProbe(config){
 if(Process.arch!=='arm'||Process.pointerSize!==4)throw Error('synthetic probe requires ARMv7 ABI');
 const mem=Memory.alloc(8),clk=new NativeFunction(Process.getModuleByName('libc.so').getExportByName('clock_gettime'),'int',['int','pointer'],{scheduling:'exclusive'});
 function mono(){clk(1,mem);return mem.readU32()*1e9+mem.add(4).readU32();}
 const window=config.window===undefined?0:config.window;
 if(!Number.isInteger(window)||window<0||window>32)throw Error('invalid acknowledgement window');
 let stages=[],bytes=null,hash=null,started=null,ended=null,rpcReturned=null;
 let next=0,emitted=0,inflight=0,peak=0,acknowledged=0,stopped=false,scheduled=false;
 const record=(event,fields)=>{
  send(Object.assign({event,device_mono_ns:mono()},fields));
  if(event==='transport_ack'){
   inflight--;acknowledged++;
   if(window>0&&!stopped&&next<config.count&&!scheduled){
    scheduled=true;
    setImmediate(()=>{
     scheduled=false;if(stopped)return;
     try{pump();}catch(e){stopped=true;record('error',{where:'window_pump',message:String(e)});}
    });
   }
  }
 };
 const acks=snapshotAcknowledgements(true,mono,send,recv,record,
  (where,e)=>{stopped=true;record('error',{where,message:String(e)});});
 function timed(stage,n,fn){const at=mono();let ok=false;try{const result=fn();ok=true;return result;}
  finally{stages.push({stage,bytes:n,started_ns:at,completed_ns:mono(),successful:ok});}}
 const emit=snapshotCodec(config.codec,timed,(row,data)=>acks.send(row,data));
 function pump(){
  while(!stopped&&next<config.count&&(window===0||inflight<window)){
   next++;inflight++;peak=Math.max(peak,inflight);
   emit({event:'native_pixels',synthetic:true,pattern:config.pattern,
    device_mono_ns:mono(),bytes:config.size,sha256:hash},bytes);
   emitted++;
  }
  if(next===config.count&&ended===null)ended=mono();
 }
 return {
  prepare(){
   if(bytes!==null)throw Error('probe already prepared');
   bytes=probePayload(config.size,config.pattern);hash=Checksum.compute('sha256',bytes);
   if(hash!==config.sha256)throw Error('synthetic host/device fingerprint mismatch');
   return {arch:Process.arch,pointer_size:Process.pointerSize,sha256:hash};
  },
  burst(){
   if(stopped||bytes===null||started!==null||!Number.isInteger(config.count)||config.count<1||config.count>32||config.size*config.count>240*1024*1024)throw Error('invalid probe burst');
   started=mono();
   pump();rpcReturned=mono();
  },
  finish(){
   stopped=true;
   return {acknowledgements:acks.finish(),stages,burst_started_ns:started,burst_returned_ns:ended,burst_rpc_returned_ns:rpcReturned,
    flow:{window,mode:window===0?'synchronous-burst':'acknowledgement-window',
     send_attempts:next,emitted,acknowledged,inflight,peak_inflight:peak}};
  }
 };
}
