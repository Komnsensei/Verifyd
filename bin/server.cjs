const http = require('http');
const fs = require('fs');
const path = require('path');
const PORT = process.env.PORT || 8080;
const WEB = path.join(__dirname, '../web-lite');
http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({status:'ok',service:'verifyd',version:'1.0'}));
    return;
  }
  const f = req.url === '/' ? path.join(WEB,'index.html') : path.join(WEB, req.url);
  if (!fs.existsSync(f)) { res.writeHead(404); res.end('not found'); return; }
  res.writeHead(200);
  fs.createReadStream(f).pipe(res);
}).listen(PORT, () => console.log('Verifyd on port ' + PORT));
