import re
h = open('index.html', encoding='utf-8').read()
P = """<script>
(function(){
  var NB=0, BEST=null, N=0;
  function smp(gl){
    try{
      var w=gl.drawingBufferWidth,h=gl.drawingBufferHeight;
      var x=Math.floor(w*0.3),y=Math.floor(h*0.35),s=120;
      var b=new Uint8Array(4*s*s);
      gl.readPixels(x,y,s,s,gl.RGBA,gl.UNSIGNED_BYTE,b);
      var nz=0,n=b.length/4,R=0,G=0,B=0;
      for(var i=0;i<b.length;i+=4){if(b[i]+b[i+1]+b[i+2]>12)nz++;R+=b[i];G+=b[i+1];B+=b[i+2];}
      if(!BEST||nz>BEST._n)BEST={有内容:nz+'/'+n,平均RGB:(R/n).toFixed(0)+','+(G/n).toFixed(0)+','+(B/n).toFixed(0),_n:nz};
    }catch(e){}
  }
  function patch(P){ if(!P||!P.drawElements) return;
    ['drawElements','drawArrays'].forEach(function(k){
      var o=P[k];
      P[k]=function(){ N++; if(N%150===0) smp(this); return o.apply(this,arguments); };
    });
  }
  patch(window.WebGLRenderingContext&&WebGLRenderingContext.prototype);
  patch(window.WebGL2RenderingContext&&WebGL2RenderingContext.prototype);
  window.__AN=function(){return N;};
  window.__APX=function(){return BEST;};
})();
</script>
"""
out = re.sub(r'(<script src="app\.js[^"]*"></script>)', P + r'\1', h, count=1)
assert out != h, '未找到 app.js 脚本标签'
open('probe.html', 'w', encoding='utf-8').write(out)
print('probe.html 已生成', len(out), '字节')
