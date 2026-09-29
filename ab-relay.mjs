/**
 * ab-relay.mjs — 多上游中转服务（Orkestr 容器版）
 *
 * 作用：Cloudflare Worker 的独立出口中转。Worker 出口是共享数据中心 IP，
 *       易被上游按 IP 限流/封禁；本容器持有独立出口 IP，由它去访问上游。
 *
 * 与函数版（orelay_handler.py）的关键区别：
 *   函数单次请求硬上限约 26s 且响应整体缓冲 → agnes 长文本流式响应会被截断（客户端断连）；
 *   本容器超时 180s，且 req/res 全程 pipe（真 SSE 透传）→ 长流式不再断连。
 *
 * 路由：
 *   POST/GET /v1/*      -> https://api.appbms.com       （AppBMS 生图，ECDSA 签名链路出口）
 *   POST/GET /agnes/*   -> https://apihub.agnes-ai.cn   （Agnes，OpenAI 兼容，换出口 IP 规避 429）
 *   GET      /__ping    -> pong-v3                      （保活用，见 keeper.js）
 *
 * 鉴权：/v1/* 与 /agnes/* 必须带 X-Proxy-Key，值等于本容器环境变量 RELAY_KEY；
 *       该头在转发前被剥离，不透传给上游。
 *
 * 环境变量：
 *   RELAY_KEY  必填  与 Cloudflare Worker 的 AB_PROXY_KEY / AGNES_PROXY_KEY 一致
 *   PORT       可选  PaaS 注入（默认 8080）
 *   BIND       可选  默认 0.0.0.0
 */
import http from 'node:http';
import https from 'node:https';

const PORT = Number(process.env.PORT || 8080);
const BIND = process.env.BIND || '0.0.0.0';
const RELAY_KEY = (process.env.RELAY_KEY || '').trim();

const AB_UPSTREAM = 'https://api.appbms.com';
const AGNES_UPSTREAM = 'https://apihub.agnes-ai.cn';
const UPSTREAM_TIMEOUT_MS = 180000;

/* 转发前需要剥离的请求头：host 会被重写；x-proxy-key 是本次中转的鉴权头；
 * 其余 cf-* / x-forwarded-* 是边缘注入的头，透传会干扰上游。 */
const STRIP_REQ = new Set([
  'host', 'x-proxy-key', 'content-length', 'connection', 'keep-alive',
  'transfer-encoding', 'upgrade', 'te', 'trailer',
  'cf-worker', 'cf-connecting-ip', 'cf-ray', 'cf-ew-via', 'cf-visitor', 'cdn-loop',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto',
  'x-forwarded-server', 'x-real-ip',
]);
/* 响应头：只剥离分帧相关头，让 Node 重新分帧；content-encoding 保留（pipe 原始字节，客户端自行解压）。
 * 注意绝不能 strip content-type —— SSE 的 text/event-stream 必须原样回给客户端。 */
const STRIP_RES = new Set(['content-length', 'transfer-encoding', 'connection', 'keep-alive']);

const log = (...a) => console.log(new Date().toISOString(), ...a);

if (!RELAY_KEY) {
  log('WARN: RELAY_KEY 未设置，所有 /v1/* 与 /agnes/* 请求都会被拒（403 bad proxy key）');
}

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

/** 把一次请求整体 pipe 到上游，并把上游响应 stream 回客户端（不缓冲）。 */
function proxy(req, res, upstream, fwdPath) {
  const target = new URL(upstream + fwdPath);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (!STRIP_REQ.has(k.toLowerCase())) headers[k] = v;
  }
  headers['host'] = target.host;
  headers['accept-encoding'] = 'identity';

  const opts = {
    method: req.method,
    hostname: target.hostname,
    port: 443,
    path: target.pathname + target.search,
    headers,
    timeout: UPSTREAM_TIMEOUT_MS,
  };

  const pr = https.request(opts, (pres) => {
    const rh = {};
    for (const [k, v] of Object.entries(pres.headers)) {
      if (!STRIP_RES.has(k.toLowerCase())) rh[k] = v;
    }
    /* SSE / 流式：不设 content-length，Node 自动 chunked，逐块下发 */
    res.writeHead(pres.statusCode || 502, rh);
    pres.pipe(res);
  });

  pr.on('timeout', () => {
    log('upstream timeout', req.method, fwdPath);
    pr.destroy(new Error('upstream timeout'));
  });
  pr.on('error', (e) => {
    log('upstream error:', e.message, req.method, fwdPath);
    if (!res.headersSent) json(res, 502, { error: 'upstream: ' + e.message });
    else try { res.end(); } catch (_) {}
  });

  req.pipe(pr);
}

const server = http.createServer((req, res) => {
  const u = req.url || '/';

  if (u === '/__ping' || u.startsWith('/__ping?')) {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('pong-v3');
    return;
  }

  let upstream, fwdPath;
  if (u.startsWith('/agnes/')) {
    upstream = AGNES_UPSTREAM;
    fwdPath = u.slice('/agnes'.length); /* /agnes/v1/chat/... -> /v1/chat/... */
  } else if (u.startsWith('/v1/')) {
    upstream = AB_UPSTREAM;
    fwdPath = u;
  } else {
    json(res, 403, { error: 'only /v1/* or /agnes/* allowed' });
    return;
  }

  if (!RELAY_KEY || (req.headers['x-proxy-key'] || '').trim() !== RELAY_KEY) {
    json(res, 403, { error: 'bad proxy key' });
    return;
  }

  proxy(req, res, upstream, fwdPath);
});

server.listen(PORT, BIND, () => {
  log('ab-relay listening on ' + BIND + ':' + PORT + '  /v1/*->' + AB_UPSTREAM + '  /agnes/*->' + AGNES_UPSTREAM);
});