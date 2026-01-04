#!/usr/bin/env bash
set -e

APP_DIR="/opt/pf-web"
SERVICE_NAME="pf-web"
PORT_DEFAULT="3000"

echo "========================================"
echo " PF-Web v3-lite 一键安装（支持端口映射 listen->target）"
echo "========================================"

if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请用 root 执行"
  exit 1
fi

read -rp "面板监听端口 PORT [默认 ${PORT_DEFAULT}]: " PORT
PORT=${PORT:-$PORT_DEFAULT}

read -rp "设置 ADMIN_TOKEN（网页登录用，建议强密码）: " ADMIN_TOKEN
if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "[ERR] ADMIN_TOKEN 不能为空"
  exit 1
fi

echo
echo "白名单模式说明："
echo "  1) 输入 ANY      => 不限制目标IP（网页可随便填）"
echo "  2) 输入 IP 列表   => 只允许这些目标IP（更安全）"
echo "  3) 留空          => 只允许【网页里管理】的白名单"
echo
read -rp "设置 TARGET_ALLOWLIST（ANY 或 逗号分隔IP 或 留空）: " TARGET_ALLOWLIST

read -rp "是否手动指定外网网卡 WAN_IF？(回车自动识别 / 如 eth0 ens5): " WAN_IF

echo
echo "[*] 将安装到：$APP_DIR"
echo "[*] PORT=$PORT"
echo "[*] TARGET_ALLOWLIST=${TARGET_ALLOWLIST:-'(file-only)'}"
echo "[*] WAN_IF=${WAN_IF:-auto}"
echo

echo "[1/6] 安装基础依赖..."
apt-get update -y >/dev/null
apt-get install -y curl ca-certificates gnupg iptables >/dev/null
apt-get install -y iptables-legacy >/dev/null 2>&1 || true

echo "[2/6] 安装 Node.js..."
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
  apt-get install -y nodejs >/dev/null
fi
node -v
npm -v

echo "[3/6] 生成项目文件..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/public"

cat > "$APP_DIR/package.json" <<'JSON'
{
  "name": "pf-web-lite",
  "type": "module",
  "version": "3.0.0-lite",
  "dependencies": {
    "express": "^4.19.2"
  },
  "scripts": {
    "start": "node server.js"
  }
}
JSON

cat > "$APP_DIR/server.js" <<'JS'
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { execFile } from "child_process";
import net from "net";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "change-me";
const WAN_IF = (process.env.WAN_IF || "").trim();
const TARGET_ALLOWLIST_RAW = (process.env.TARGET_ALLOWLIST || "").trim();
const TARGET_ALLOWLIST = TARGET_ALLOWLIST_RAW
  ? TARGET_ALLOWLIST_RAW.split(",").map(s => s.trim()).filter(Boolean)
  : [];

const DATA_FILE = path.join(__dirname, "data.json");

function loadData() {
  if (!fs.existsSync(DATA_FILE)) return { nextId: 1, rules: [], allowlist: [] };
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf-8");
    const obj = JSON.parse(raw);
    return {
      nextId: Number(obj.nextId || 1),
      rules: Array.isArray(obj.rules) ? obj.rules : [],
      allowlist: Array.isArray(obj.allowlist) ? obj.allowlist : []
    };
  } catch {
    return { nextId: 1, rules: [], allowlist: [] };
  }
}
function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
let data = loadData();

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`${cmd} ${args.join(" ")}\n${stderr || err.message}`));
      resolve((stdout || "").toString());
    });
  });
}

async function detectWanIf() {
  const out = await run("bash", ["-lc", `ip route get 1.1.1.1 | awk '{print $5; exit}'`]);
  return out.trim();
}

function isPort(n){
  return Number.isInteger(n) && n >= 0 && n <= 65535;
}

/**
 * 端口映射输入格式：
 * - 同端口： "80,443"
 * - 端口段同端口： "10000-10010"
 * - 映射： "12345->80"
 * - 批量映射： "12345->80,12346->443"
 *
 * 返回：[{listen:12345,target:80}, ...] 或 {range:{from,to}}（同段同端口）
 */
function parsePortMappings(input) {
  const s = String(input || "").trim();
  if (!s) throw new Error("ports is required");

  // 端口段（只支持同段同端口映射）
  if (s.includes("-") && !s.includes("->") && !s.includes(",")) {
    const [a, b] = s.split("-").map(x => x.trim());
    const pa = Number(a), pb = Number(b);
    if (!isPort(pa) || !isPort(pb) || pa > pb) throw new Error("invalid port range");
    return { range: { from: pa, to: pb } };
  }

  // 列表/映射
  const parts = s.split(",").map(x => x.trim()).filter(Boolean);
  if (!parts.length) throw new Error("invalid ports");

  const mappings = [];
  for (const p of parts) {
    if (p.includes("->")) {
      const [l, t] = p.split("->").map(x => x.trim());
      const listen = Number(l), target = Number(t);
      if (!isPort(listen) || !isPort(target)) throw new Error(`invalid mapping: ${p}`);
      mappings.push({ listen, target });
    } else {
      const n = Number(p);
      if (!isPort(n)) throw new Error(`invalid port: ${p}`);
      mappings.push({ listen: n, target: n });
    }
  }

  // 去重（以 listen 为准，后者覆盖前者）
  const map = new Map();
  for (const m of mappings) map.set(m.listen, m.target);
  return [...map.entries()].map(([listen, target]) => ({ listen, target }));
}

/**
 * 白名单校验：
 * - env 包含 ANY：放开
 * - 否则：env 白名单命中 或 文件 allowlist 命中 才允许
 */
function checkAllowlist(targetIp) {
  if (TARGET_ALLOWLIST.includes("ANY")) return true;
  if (TARGET_ALLOWLIST.length > 0 && TARGET_ALLOWLIST.includes(targetIp)) return true;
  return data.allowlist.includes(targetIp);
}

async function ensureForwarding() {
  await run("sysctl", ["-w", "net.ipv4.ip_forward=1"]);
}

/**
 * 添加规则：
 * - 现在支持 listen_port -> target_port
 * - 每条规则 comment = PFWEB:<id>
 */
async function applyIptablesAdd(rule) {
  const wan = WAN_IF || await detectWanIf();
  if (!wan) throw new Error("cannot detect WAN_IF; set env WAN_IF=eth0/ens5");

  await ensureForwarding();

  const comment = `PFWEB:${rule.id}`;
  const protos = rule.proto === "both" ? ["tcp", "udp"] : [rule.proto];

  const addOne = async (protocol, listenPort, targetPort) => {
    // PREROUTING: match listenPort -> DNAT to target_ip:targetPort
    await run("iptables", [
      "-t", "nat", "-A", "PREROUTING",
      "-i", wan,
      "-p", protocol,
      "--dport", String(listenPort),
      "-m", "comment", "--comment", comment,
      "-j", "DNAT",
      "--to-destination", `${rule.target_ip}:${targetPort}`
    ]);

    // POSTROUTING: MASQUERADE for return traffic to target_ip:targetPort
    await run("iptables", [
      "-t", "nat", "-A", "POSTROUTING",
      "-p", protocol,
      "-d", rule.target_ip,
      "--dport", String(targetPort),
      "-m", "comment", "--comment", comment,
      "-j", "MASQUERADE"
    ]);
  };

  if (rule.range) {
    // 端口段同端口：listenPort=targetPort
    for (const pr of protos) {
      for (let p = rule.range.from; p <= rule.range.to; p++) {
        await addOne(pr, p, p);
      }
    }
    return;
  }

  for (const pr of protos) {
    for (const m of rule.mappings) {
      await addOne(pr, m.listen, m.target);
    }
  }
}

// 删除：按 comment 找到所有 -A 规则，逐条 -D
async function applyIptablesDeleteById(id) {
  const tag = `PFWEB:${id}`;
  const prer = await run("bash", ["-lc", `iptables -t nat -S PREROUTING | grep -- '${tag}' || true`]);
  const post = await run("bash", ["-lc", `iptables -t nat -S POSTROUTING | grep -- '${tag}' || true`]);

  const lines = (prer + "\n" + post).split("\n").map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    const del = line.replace(/^-A /, "-D ");
    await run("bash", ["-lc", `iptables -t nat ${del}`]);
  }
}

// 防重复：同 target_ip + proto + 映射内容完全一致就拒绝
function ruleSignature(r){
  const base = `${r.target_ip}|${r.proto}|`;
  if (r.range) return base + `range:${r.range.from}-${r.range.to}`;
  const items = [...r.mappings].sort((a,b)=>a.listen-b.listen).map(x=>`${x.listen}->${x.target}`).join(",");
  return base + `map:${items}`;
}

function existsSameRule(sig){
  return data.rules.find(r => r.sig === sig)?.id;
}

function tcpLatencyMs(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;

    const finish = (ok, err) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ ok, ms: Date.now() - start, error: ok ? null : (err || "connect_failed") });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (e) => finish(false, e.code || e.message));

    socket.connect(port, host);
  });
}

/* -------------------- API -------------------- */

app.get("/api/info", auth, async (req, res) => {
  res.json({
    ok: true,
    wan_if: WAN_IF || "(auto)",
    allowlist_mode: TARGET_ALLOWLIST.includes("ANY") ? "ANY" : "WHITELIST",
    env_allowlist: TARGET_ALLOWLIST
  });
});

app.get("/api/rules", auth, (req, res) => {
  // 展示时把 mappings/range 原样返回
  res.json([...data.rules].sort((a,b)=>b.id-a.id));
});

app.post("/api/rules", auth, async (req, res) => {
  try {
    const target_ip = String(req.body.target_ip || "").trim();
    const portsRaw = String(req.body.ports || "").trim();
    const proto = String(req.body.proto || "tcp").trim().toLowerCase();

    if (!target_ip) throw new Error("target_ip is required");
    if (!portsRaw) throw new Error("ports is required");
    if (!["tcp", "udp", "both"].includes(proto)) throw new Error("proto must be tcp/udp/both");

    if (!checkAllowlist(target_ip)) {
      throw new Error("target_ip not in allowlist (use ANY mode or add it in whitelist page)");
    }

    const parsed = parsePortMappings(portsRaw);

    const id = data.nextId++;
    const rule = {
      id,
      target_ip,
      proto,
      created_at: new Date().toISOString(),
      raw: portsRaw
    };

    if (parsed.range) {
      rule.range = parsed.range;
    } else {
      rule.mappings = parsed; // [{listen,target},...]
    }

    rule.sig = ruleSignature(rule);
    const sameId = existsSameRule(rule.sig);
    if (sameId) throw new Error(`same rule already exists: id=${sameId}`);

    data.rules.push(rule);
    saveData();

    await applyIptablesAdd(rule);

    res.json({ ok: true, id });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.delete("/api/rules/:id", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) throw new Error("invalid id");

    await applyIptablesDeleteById(id);
    data.rules = data.rules.filter(r => r.id !== id);
    saveData();

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.get("/api/allowlist", auth, (req, res) => {
  res.json([...data.allowlist].sort().map(ip => ({ ip })));
});

app.post("/api/allowlist", auth, (req, res) => {
  try {
    const ip = String(req.body.ip || "").trim();
    if (!ip) throw new Error("ip required");
    if (!data.allowlist.includes(ip)) data.allowlist.push(ip);
    saveData();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.delete("/api/allowlist/:ip", auth, (req, res) => {
  try {
    const ip = String(req.params.ip || "").trim();
    data.allowlist = data.allowlist.filter(x => x !== ip);
    saveData();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

app.get("/api/latency", auth, async (req, res) => {
  try {
    const host = String(req.query.host || "").trim();
    const port = Number(req.query.port);

    if (!host) throw new Error("host required");
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("invalid port");

    if (!checkAllowlist(host)) {
      throw new Error("host not in allowlist (use ANY mode or add it in whitelist page)");
    }

    const r = await tcpLatencyMs(host, port, 2000);
    res.json(r);
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PF-Web v3-lite running on :${PORT}`);
});
JS

cat > "$APP_DIR/public/index.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>PF-Web v3-lite</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b0f14; color:#e6edf3; margin:0;}
    .wrap{max-width:1050px; margin:0 auto; padding:20px;}
    .card{background:#111827; border:1px solid #223044; border-radius:14px; padding:16px; margin-bottom:14px;}
    input,select,button{border-radius:10px; border:1px solid #2a3b55; background:#0b1220; color:#e6edf3; padding:10px 12px; outline:none;}
    button{cursor:pointer; background:#1f6feb; border-color:#1f6feb;}
    button.danger{background:#ef4444; border-color:#ef4444;}
    button.ghost{background:transparent; border-color:#2a3b55;}
    .row{display:flex; gap:10px; flex-wrap:wrap;}
    .row > *{flex:1; min-width:180px;}
    table{width:100%; border-collapse:collapse;}
    th,td{padding:10px; border-bottom:1px solid #223044; text-align:left; vertical-align:top;}
    .muted{color:#9aa7b2; font-size:12px;}
    .pill{display:inline-block; padding:3px 8px; border-radius:999px; background:#0b1220; border:1px solid #2a3b55; font-size:12px;}
    .topbar{display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;}
    ul{margin:10px 0 0; padding-left:18px;}
    li{margin:6px 0;}
    .split{display:grid; grid-template-columns: 1fr 1fr; gap:14px;}
    @media (max-width: 900px){ .split{grid-template-columns: 1fr;} }
    code{background:#0b1220;border:1px solid #2a3b55;border-radius:8px;padding:2px 6px;}
  </style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <h2 style="margin:0;">PF-Web v3-lite（端口映射 listen→target）</h2>
    <div class="row" style="max-width:520px;">
      <input id="token" placeholder="ADMIN_TOKEN（Bearer）" />
      <button class="ghost" onclick="saveToken()">保存</button>
      <button class="ghost" onclick="refreshAll()">刷新</button>
    </div>
  </div>

  <div class="card">
    <div class="muted" id="info">加载中...</div>
    <div class="muted" style="margin-top:8px;">
      端口填写示例：<br>
      1) 同端口：<code>80,443</code><br>
      2) 端口段同端口：<code>10000-10010</code><br>
      3) 端口映射：<code>12345-&gt;80</code><br>
      4) 批量映射：<code>12345-&gt;80,12346-&gt;443</code>
    </div>
  </div>

  <div class="split">

    <div class="card">
      <h3 style="margin-top:0;">新增转发规则</h3>
      <div class="row">
        <input id="target_ip" placeholder="目标IP（如 12.32.21.1 / 10.66.66.1）" />
        <input id="ports" placeholder="端口：12345->80,12346->443 或 80,443" />
        <select id="proto">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="both">TCP+UDP</option>
        </select>
        <button onclick="addRule()">添加</button>
      </div>
      <div class="muted" style="margin-top:8px;">如果不是 ANY 模式，需要先把目标IP加入右侧白名单。</div>
    </div>

    <div class="card">
      <h3 style="margin-top:0;">目标 IP 白名单管理</h3>
      <div class="row">
        <input id="allow_ip" placeholder="添加白名单IP（如 12.32.21.1）">
        <button onclick="addAllow()">添加白名单</button>
      </div>
      <ul id="allowlist"></ul>
    </div>

  </div>

  <div class="card">
    <div class="topbar">
      <h3 style="margin:0;">规则列表</h3>
    </div>
    <div style="overflow:auto;">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>目标</th>
            <th>端口规则</th>
            <th>协议</th>
            <th>创建时间</th>
            <th>延迟检测</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

</div>

<script>
  function getToken(){ return localStorage.getItem("PFWEB_TOKEN") || ""; }
  function saveToken(){
    localStorage.setItem("PFWEB_TOKEN", document.getElementById("token").value.trim());
    alert("已保存 token");
  }
  document.getElementById("token").value = getToken();

  async function api(url, opts={}){
    const token = getToken();
    const headers = Object.assign({
      "Content-Type":"application/json",
      "Authorization":"Bearer " + token
    }, opts.headers||{});
    const res = await fetch(url, Object.assign({}, opts, {headers}));
    const data = await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  async function loadInfo(){
    try{
      const r = await api("/api/info");
      document.getElementById("info").innerHTML =
        `模式：<b>${r.allowlist_mode}</b> ｜ WAN_IF：<b>${r.wan_if}</b> ｜ env_allowlist：<b>${(r.env_allowlist||[]).join(",") || "(none)"}</b>`;
    }catch(e){
      document.getElementById("info").innerHTML = `<span style="color:#ffb4b4;">${e.message}</span>`;
    }
  }

  async function loadAllowlist(){
    const ul = document.getElementById("allowlist");
    ul.innerHTML = `<li class="muted">加载中...</li>`;
    try{
      const list = await api("/api/allowlist");
      if(!list.length){
        ul.innerHTML = `<li class="muted">暂无白名单</li>`;
        return;
      }
      ul.innerHTML = list.map(i => `
        <li>
          <span class="pill">${i.ip}</span>
          <button class="danger" style="margin-left:8px;" onclick="delAllow('${i.ip}')">删除</button>
        </li>
      `).join("");
    }catch(e){
      ul.innerHTML = `<li style="color:#ffb4b4;">${e.message}</li>`;
    }
  }

  async function addAllow(){
    try{
      const ip = document.getElementById("allow_ip").value.trim();
      if(!ip) return alert("请输入 IP");
      await api("/api/allowlist", {method:"POST", body: JSON.stringify({ip})});
      document.getElementById("allow_ip").value = "";
      await loadAllowlist();
      alert("已添加白名单：" + ip);
    }catch(e){
      alert("添加白名单失败：" + e.message);
    }
  }

  async function delAllow(ip){
    if(!confirm("删除白名单：" + ip + " ?")) return;
    try{
      await api("/api/allowlist/" + encodeURIComponent(ip), {method:"DELETE"});
      await loadAllowlist();
    }catch(e){
      alert("删除白名单失败：" + e.message);
    }
  }

  async function loadRules(){
    const tbody = document.getElementById("tbody");
    tbody.innerHTML = `<tr><td colspan="7" class="muted">加载中...</td></tr>`;
    try{
      const rules = await api("/api/rules");
      if(!rules.length){
        tbody.innerHTML = `<tr><td colspan="7" class="muted">暂无规则</td></tr>`;
        return;
      }
      tbody.innerHTML = rules.map(r => `
        <tr>
          <td><span class="pill">#${r.id}</span></td>
          <td>${r.target_ip}</td>
          <td>${r.raw || ''}</td>
          <td>${r.proto}</td>
          <td class="muted">${r.created_at}</td>
          <td>
            <div class="row" style="gap:6px;">
              <button class="ghost" onclick="testLatency('${r.target_ip}', 80, this)">测80</button>
              <button class="ghost" onclick="testLatency('${r.target_ip}', 443, this)">测443</button>
              <button class="ghost" onclick="testCustom('${r.target_ip}', this)">自定义</button>
            </div>
          </td>
          <td><button class="danger" onclick="delRule(${r.id})">删除</button></td>
        </tr>
      `).join("");
    }catch(e){
      tbody.innerHTML = `<tr><td colspan="7" style="color:#ffb4b4;">${e.message}</td></tr>`;
    }
  }

  async function addRule(){
    try{
      const body = {
        target_ip: document.getElementById("target_ip").value.trim(),
        ports: document.getElementById("ports").value.trim(),
        proto: document.getElementById("proto").value
      };
      const r = await api("/api/rules", {method:"POST", body: JSON.stringify(body)});
      alert("添加成功 ID=" + r.id);
      await loadRules();
    }catch(e){
      alert("添加失败：" + e.message);
    }
  }

  async function delRule(id){
    if(!confirm("确认删除规则 #" + id + " ?")) return;
    try{
      await api("/api/rules/" + id, {method:"DELETE"});
      await loadRules();
    }catch(e){
      alert("删除失败：" + e.message);
    }
  }

  async function testLatency(host, port, btn){
    const old = btn.textContent;
    btn.textContent = "测速中...";
    btn.disabled = true;
    try{
      const r = await api(`/api/latency?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`);
      alert(`${host}:${port}  ${r.ok ? "OK" : "FAIL"}  ${r.ms}ms  ${r.error ? r.error : ""}`);
    }catch(e){
      alert("测速失败：" + e.message);
    }finally{
      btn.textContent = old;
      btn.disabled = false;
    }
  }

  async function testCustom(host, btn){
    const port = prompt("输入要检测的端口：", "443");
    if(!port) return;
    await testLatency(host, Number(port), btn);
  }

  async function refreshAll(){
    await loadInfo();
    await loadAllowlist();
    await loadRules();
  }

  refreshAll();
</script>
</body>
</html>
HTML

echo "[4/6] 安装依赖（仅 express）..."
cd "$APP_DIR"
npm install --omit=dev >/dev/null

echo "[5/6] 写入环境变量..."
cat > "$APP_DIR/.env" <<EOF
ADMIN_TOKEN=${ADMIN_TOKEN}
TARGET_ALLOWLIST=${TARGET_ALLOWLIST}
PORT=${PORT}
WAN_IF=${WAN_IF}
EOF

echo "[6/6] 创建 systemd 服务并启动..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=PF-Web v3-lite Port Forward Manager
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
systemctl status "${SERVICE_NAME}" --no-pager -l || true

SERVER_IP=$(curl -4 -s --max-time 2 https://ipinfo.io/ip || echo "你的服务器IP")
echo
echo "========================================"
echo "[OK] 安装完成（PF-Web v3-lite）"
echo "访问地址: http://${SERVER_IP}:${PORT}"
echo "示例：本机12345 -> 目标80：填写 ports 为 12345->80"
echo "日志: journalctl -u ${SERVICE_NAME} -f"
echo "========================================"
