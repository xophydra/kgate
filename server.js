const http=require('http'),fs=require('fs');
const out=fs.existsSync('/tmp/out.txt')?fs.readFileSync('/tmp/out.txt','utf8'):'no output';
http.createServer((q,s)=>{
 if(q.url==='/healthz'){s.writeHead(200,{'content-type':'text/plain'});s.end('ok');return;}
 s.writeHead(200,{'content-type':'text/plain'});s.end(out);
}).listen(3000);
