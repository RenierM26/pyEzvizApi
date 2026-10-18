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
 let stages=[],bytes=null,hash=null,started=null,ended=null;
 const record=(event,fields)=>send(Object.assign({event,device_mono_ns:mono()},fields));
 const acks=snapshotAcknowledgements(true,mono,send,recv,record,
  (where,e)=>record('error',{where,message:String(e)}));
 function timed(stage,n,fn){const at=mono();let ok=false;try{const result=fn();ok=true;return result;}
  finally{stages.push({stage,bytes:n,started_ns:at,completed_ns:mono(),successful:ok});}}
 const emit=snapshotCodec(config.codec,timed,(row,data)=>acks.send(row,data));
 return {
  prepare(){
   if(bytes!==null)throw Error('probe already prepared');
   bytes=probePayload(config.size,config.pattern);hash=Checksum.compute('sha256',bytes);
   if(hash!==config.sha256)throw Error('synthetic host/device fingerprint mismatch');
   return {arch:Process.arch,pointer_size:Process.pointerSize,sha256:hash};
  },
  burst(){
   if(bytes===null||started!==null||!Number.isInteger(config.count)||config.count<1||config.count>32||config.size*config.count>240*1024*1024)throw Error('invalid probe burst');
   started=mono();
   for(let i=0;i<config.count;i++)emit({event:'native_pixels',synthetic:true,
    pattern:config.pattern,device_mono_ns:mono(),bytes:config.size,sha256:hash},bytes);
   ended=mono();
  },
  finish(){return {acknowledgements:acks.finish(),stages,burst_started_ns:started,burst_returned_ns:ended};}
 };
}
