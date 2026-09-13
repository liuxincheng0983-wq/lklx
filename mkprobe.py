import re, io

src = open('index.html', encoding='utf-8').read()

probe = """<script>
(function(){
  window.__AN=0; window.__APX=null;
  function patch(P,arr){
    if(!P||!P.drawElements) return;
    arr.forEach(function(k){ var o=P[k]; if(typeof o!=='function')return;
      P[k]=function(){ window.__AN++;
        var r=o.apply(this,arguments);
        if(!window.__APX && window.__AN>5){ try{
          var gl=this,h=gl.drawingBufferHeight,b=new Uint8Array(4*90*90);
          gl.readPixels(60,Math.floor(h/2)-45,90,90,gl.RGBA,gl.UNSIGNED_BYTE,b);
          var s=0,nz=0,n=b.length/4;
          for(var i=0;i<b.length;i+=4){ if(b[i]+b[i+1]+b[i+2]>10)nz++; s+=b[i]+b[i+1]+b[i+2]; }
          window.__APX={有内容:nz+'/'+n,平均亮度:(s/n/3).toFixed(1)};
        }catch(e){ window.__APX='err:'+e.message; } }
        return r; };
    });
  }
  patch(window.WebGLRenderingContext&&WebGLRenderingContext.prototype,['drawElements','drawArrays']);
  patch(window.WebGL2RenderingContext&&WebGL2RenderingContext.prototype,['drawElements','drawArrays']);
})();
</script>
"""

out = src.replace('<script src="app.js', probe + '<script src="app.js', 1)
assert probe in out, '注入失败'
open('probe.html', 'w', encoding='utf-8').write(out)
print('probe.html 已生成', len(out), '字节')
