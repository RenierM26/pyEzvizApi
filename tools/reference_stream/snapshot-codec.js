'use strict';
// Shared by live observation and synthetic transport controls. ARMv7 size_t ABI.
function snapshotCodec(transport,timed,emit){
let zipBound=null,zipCompress=null;
if(transport==='zlib'){
 const z=Module.load('libz.so');
 zipBound=new NativeFunction(z.getExportByName('compressBound'),'uint',['uint'],{scheduling:'exclusive'});
 zipCompress=new NativeFunction(z.getExportByName('compress2'),'int',['pointer','pointer','pointer','uint','int'],{scheduling:'exclusive'});
}else if(transport==='lz4'){
 const z=Module.load('liblz4.so');
 zipBound=new NativeFunction(z.getExportByName('LZ4_compressBound'),'int',['int'],{scheduling:'exclusive'});
 zipCompress=new NativeFunction(z.getExportByName('LZ4_compress_default'),'int',['pointer','pointer','int','int'],{scheduling:'exclusive'});
}else if(transport!=='raw')throw Error('unsupported snapshot transport');
return function(row,bytes){
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
  if(compressed){emit(Object.assign({},row,{encoding:transport,transport_bytes:compressed.byteLength}),compressed);return;}
 }
 emit(row,bytes);
};
}
