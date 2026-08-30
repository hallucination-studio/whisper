import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve('src/host/assets');
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/assets/app.css', ['app.css', 'text/css; charset=utf-8']],
  ['/assets/app.js', ['app.js', 'text/javascript; charset=utf-8']],
]);

createServer(async (request, response) => {
  const asset = assets.get(new URL(request.url, 'http://127.0.0.1').pathname);
  if (!asset) {
    response.writeHead(404).end();
    return;
  }
  try {
    let body = await readFile(resolve(root, asset[0]), 'utf8');
    body = body.replace('__MAX_TIME_BUCKETS__', '64');
    response.writeHead(200, { 'content-type': asset[1], 'cache-control': 'no-store' }).end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(4173, '127.0.0.1');
