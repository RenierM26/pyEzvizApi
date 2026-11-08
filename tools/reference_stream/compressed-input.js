// Loaded with the exact-build-gated h9c observer. No codec or camera setting changes.
let encodedSeq=0,encodedBytes=0;
Interceptor.attach(p.getExportByName('_ZN21hk_mobile_playcontrol16CHKMultiVDecoder11DecodeFrameEPhjPv'),{
 onEnter(a){
  this.encoded=null;
  if(stopped)return;
  try{
   const n=a[2].toUInt32(),meta=a[3];
   if(n<1||n>2097152||!readable(a[1],n)||!readable(meta,232))throw Error('unsupported encoded buffer extent');
   if(encodedSeq>=600||encodedBytes+n>67108864)throw Error('encoded capture budget');
   const words=Array.from({length:58},(_,i)=>meta.add(i*4).readU32());
   const bytes=a[1].readByteArray(n),id=++encodedSeq;encodedBytes+=n;
   this.encoded=id;
   flush();send({event:'encoded_video',device_mono_ns:mono(),id,bytes:n,
    decoder_owner:a[0].toString(),meta_words:words,sha256:Checksum.compute('sha256',bytes)},bytes);
  }catch(e){error('encoded_input',e);}
 },
 onLeave(ret){
  if(this.encoded!==null){
   log('encoded_video_return',{id:this.encoded,result:ret.toInt32()});
  }
 }
});
