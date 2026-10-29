import os, re, io, ast, sys, json, time, hmac, shutil, signal, asyncio, hashlib, secrets, zipfile, shlex, urllib.request
from pathlib import Path
from collections import deque
from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

DATA = Path(os.getenv("DATA_DIR", "./data")).resolve()
BOTS = DATA / "bots"; BOTS.mkdir(parents=True, exist_ok=True)
USER, PW = os.getenv("ADMIN_USER", "admin"), os.getenv("ADMIN_PASS")
if not PW: raise SystemExit("set the ADMIN_PASS environment variable")
KEY = (os.getenv("SECRET_KEY") or PW).encode()
HERE = Path(__file__).parent
META = DATA / "bots.json"
meta = json.loads(META.read_text()) if META.exists() else {}
def save(): META.write_text(json.dumps(meta, indent=1))
def bdir(i): return BOTS / i

app = FastAPI()

# ---------------- auth ----------------
def sign(e): return hmac.new(KEY, str(e).encode(), hashlib.sha256).hexdigest()
def token(): e = int(time.time()) + 7 * 86400; return f"{e}.{sign(e)}"
def valid(t):
    try: e, s = (t or "").split("."); return int(e) > time.time() and hmac.compare_digest(s, sign(e))
    except Exception: return False

@app.middleware("http")
async def guard(req, call_next):
    p = req.url.path
    if p.startswith("/api/") and p != "/api/login" and not valid(req.cookies.get("t")):
        return JSONResponse({"detail": "auth"}, 401)
    return await call_next(req)

fails = {}
@app.post("/api/login")
async def login(req: Request, res: Response):
    ip = (req.headers.get("x-forwarded-for") or req.client.host).split(",")[0].strip()
    n, t = fails.get(ip, (0, 0))
    if n >= 5 and time.time() - t < 300: raise HTTPException(429, "too many attempts, wait 5 min")
    b = await req.json()
    if hmac.compare_digest(str(b.get("user")).encode(), USER.encode()) and hmac.compare_digest(str(b.get("pass")).encode(), PW.encode()):
        fails.pop(ip, None)
        res.set_cookie("t", token(), httponly=True, samesite="strict", max_age=7 * 86400, secure=req.headers.get("x-forwarded-proto") == "https")
        return {"ok": 1}
    fails[ip] = (n + 1, time.time()); raise HTTPException(401, "wrong login")

@app.post("/api/logout")
async def logout(res: Response): res.delete_cookie("t"); return {"ok": 1}

# ---------------- runtime ----------------
class RT:
    def __init__(s): s.p = None; s.task = None; s.logs = deque(maxlen=3000); s.subs = set(); s.state = "stopped"; s.restarts = 0; s.started = 0; s.stop = False; s.cmds = set()
rt = {}
def R(i): return rt.setdefault(i, RT())

async def emit(i, txt):
    r = R(i)
    for ln in str(txt).split("\n"):
        r.logs.append(ln)
        for w in list(r.subs):
            try: await w.send_text(ln)
            except Exception: r.subs.discard(w)

def benv(i):
    e = {k: v for k, v in os.environ.items() if k not in ("ADMIN_PASS", "ADMIN_USER", "SECRET_KEY")}
    e.update(meta[i].get("env", {})); v = bdir(i) / "venv"
    e.update(PATH=f"{v / 'bin'}:{e.get('PATH', '')}", VIRTUAL_ENV=str(v), PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
    return e

async def sh(i, cmd, cwd=None, env=None):
    p = await asyncio.create_subprocess_shell(cmd, cwd=cwd or bdir(i), env=env or benv(i), stdout=-1, stderr=-2, limit=1 << 20, start_new_session=True)
    R(i).cmds.add(p)
    try:
        async for l in p.stdout: await emit(i, l.decode(errors="replace").rstrip())
        return await p.wait()
    finally: R(i).cmds.discard(p)

# ---------------- detection ----------------
ENTRY = ["main.py", "bot.py", "app.py", "run.py", "start.py", "index.py", "__main__.py"]
MARK = re.compile(r"run_polling|start_polling|infinity_polling|\.polling\(|run_until_disconnected|\bidle\(|TeleBot\(|Application\.builder|Dispatcher\(|Client\(|run_webhook")
PIP = {"telegram": "python-telegram-bot", "telebot": "pyTelegramBotAPI", "dotenv": "python-dotenv", "yaml": "pyyaml", "PIL": "pillow", "bs4": "beautifulsoup4", "cv2": "opencv-python-headless", "sklearn": "scikit-learn", "dateutil": "python-dateutil", "pyrogram": "pyrogram tgcrypto", "Crypto": "pycryptodome", "psycopg2": "psycopg2-binary", "dns": "dnspython", "jwt": "pyjwt", "yt_dlp": "yt-dlp"}
SENS = re.compile(r"TOKEN|SECRET|KEY|HASH|PASS|API_ID|URI|URL|DSN|OWNER|ADMIN", re.I)
PAT = re.compile(r"""(?:getenv|environ\.get|config|env(?:\.\w+)?)\(\s*['"]([A-Z_][A-Z0-9_]*)['"](?:\s*,\s*([^)]*))?\)|environ\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]""")
EXAMPLES = (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", "sample.env")

def pyfiles(d): return [p for p in d.rglob("*.py") if not {"venv", "__pycache__", ".git"} & set(p.relative_to(d).parts)]
def rel(d): return [str(p.relative_to(d)) for p in pyfiles(d)]

def detect_entry(d):
    r = rel(d); pc = d / "Procfile"
    if pc.exists():
        m = re.search(r"python3?\s+(\S+\.py)", pc.read_text(errors="ignore"))
        if m and m.group(1) in r: return m.group(1)
    for e in ENTRY:
        if e in r: return e
    sc = [x for x in r if x.count("/") <= 1 and MARK.search((d / x).read_text(errors="ignore"))]
    pool = sc or r
    return sorted(pool, key=lambda x: (x.count("/"), len(x)))[0] if pool else ""

def guess_reqs(d):
    local = {p.stem for p in pyfiles(d)} | {p.name for p in d.iterdir() if p.is_dir()}; mods = set()
    for p in pyfiles(d):
        try: t = ast.parse(p.read_text(errors="ignore"))
        except Exception: continue
        for n in ast.walk(t):
            if isinstance(n, ast.Import): mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module: mods.add(n.module.split(".")[0])
    out = []
    for m in sorted(mods):
        if m in sys.stdlib_module_names or m in local or m.startswith("_"): continue
        out += PIP.get(m, m).split(" ")
    return out

def parse_env(text):
    o = {}
    for ln in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", ln)
        if m and not ln.strip().startswith("#"): o[m[1]] = m[2].strip().strip("\"'")
    return o

def detect_env(d):
    f = {}
    for n in EXAMPLES:
        p = d / n
        if not p.exists(): continue
        hint = ""
        for ln in p.read_text(errors="ignore").splitlines():
            s = ln.strip()
            if s.startswith("#"): hint = s.lstrip("# ").strip(); continue
            m = re.match(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", s)
            if m: f.setdefault(m[1], {"default": m[2].strip().strip("\"'"), "hint": hint, "src": n, "has_default": bool(m[2].strip())})
            hint = ""
    for p in pyfiles(d):
        for m in PAT.finditer(p.read_text(errors="ignore")):
            k = m[1] or m[3]; dv = (m[2] or "").strip()
            lit = bool(re.match(r"""^(['"].*['"]|\d+)$""", dv))
            f.setdefault(k, {"default": dv.strip("\"'") if lit else "", "hint": "", "src": p.name, "has_default": m[2] is not None})
    out = [{"key": k, "required": not v["has_default"] or v["default"] == "" and SENS.search(k) is not None, "secret": SENS.search(k) is not None, **v} for k, v in f.items()]
    return sorted(out, key=lambda x: (not x["required"], x["key"]))

# ---------------- install / run ----------------
async def install(i):
    r = R(i); old = r.state; r.state = "installing"; d = bdir(i); py = shlex.quote(sys.executable); e0 = os.environ.copy()
    try:
        if not (d / "venv/bin/python").exists():
            await emit(i, "[host] creating virtualenv")
            if await sh(i, f"{py} -m uv venv --seed venv", d, e0): await sh(i, f"{py} -m venv venv", d, e0)
        req = d / "requirements.txt"
        if not req.exists():
            g = guess_reqs(d)
            if g: req.write_text("\n".join(g) + "\n"); await emit(i, "[host] no requirements.txt, detected from imports: " + ", ".join(g))
        if req.exists():
            await emit(i, "[host] installing requirements")
            rc = await sh(i, f"{py} -m uv pip install -p venv/bin/python -r requirements.txt")
            if rc: await emit(i, "[host] uv failed, falling back to pip"); rc = await sh(i, "python -m pip install -r requirements.txt")
            await emit(i, "[host] dependencies installed" if rc == 0 else f"[host] install failed (exit {rc})")
        else: await emit(i, "[host] no dependencies found")
    except Exception as ex: await emit(i, f"[host] install error: {ex}")
    finally: r.state = "stopped" if old == "installing" else old

async def supervise(i):
    r = R(i); back = 1
    while not r.stop:
        m = meta[i]; await emit(i, f"[host] starting {m['entry']}"); t0 = time.time()
        r.p = await asyncio.create_subprocess_exec(str(bdir(i) / "venv/bin/python"), "-u", m["entry"], cwd=bdir(i), env=benv(i), stdout=-1, stderr=-2, limit=1 << 20, start_new_session=True)
        r.started = t0; r.state = "running"
        async for l in r.p.stdout: await emit(i, l.decode(errors="replace").rstrip())
        rc = await r.p.wait()
        if r.stop: break
        back = 1 if time.time() - t0 > 60 else min(back * 2, 60); r.restarts += 1; r.state = "restarting"
        await emit(i, f"[host] exited with code {rc}, restarting in {back}s"); await asyncio.sleep(back)

async def start(i):
    r = R(i); m = meta[i]
    if r.state != "stopped": return
    if not m.get("entry"): return await emit(i, "[host] no entry file, pick one in Files")
    r.state = "installing"
    if not (bdir(i) / "venv/bin/python").exists(): await install(i)
    (bdir(i) / ".env").write_text("".join(f"{k}={json.dumps(v)}\n" for k, v in m.get("env", {}).items()))
    m["want"] = True; save(); r.stop = False; r.state = "running"; r.task = asyncio.create_task(supervise(i))

def killg(p, sig):
    try: os.killpg(p.pid, sig)
    except Exception: pass

async def stop(i):
    r = R(i); meta[i]["want"] = False; save(); r.stop = True
    if r.p and r.p.returncode is None:
        killg(r.p, signal.SIGTERM)
        try: await asyncio.wait_for(r.p.wait(), 6)
        except asyncio.TimeoutError: killg(r.p, signal.SIGKILL)
    if r.task: r.task.cancel(); await asyncio.gather(r.task, return_exceptions=True)
    if r.state != "stopped": await emit(i, "[host] stopped")
    r.p = r.task = None; r.state = "stopped"

def rss(p):
    try: return int(re.search(r"VmRSS:\s+(\d+)", open(f"/proc/{p.pid}/status").read())[1]) // 1024
    except Exception: return 0

# ---------------- upload ----------------
def unzip(data, dest):
    tmp = DATA / ("tmp-" + secrets.token_hex(4)); tmp.mkdir(); total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for m in z.infolist():
                if m.is_dir() or re.search(r"(^|/)(__MACOSX|\.git|venv|\.venv|__pycache__)/", m.filename): continue
                total += m.file_size
                if total > 300_000_000: raise HTTPException(413, "zip too large")
                p = (tmp / m.filename).resolve()
                if not str(p).startswith(str(tmp.resolve()) + os.sep): continue
                p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(z.read(m))
        items = list(tmp.iterdir())
        src = items[0] if len(items) == 1 and items[0].is_dir() else tmp
        shutil.copytree(src, dest, dirs_exist_ok=True)
    finally: shutil.rmtree(tmp, ignore_errors=True)

def slug(n): return (re.sub(r"[^a-z0-9]+", "-", n.lower()).strip("-")[:24] or "bot") + "-" + secrets.token_hex(2)

async def after_upload(i, was_running):
    await install(i)
    if was_running: await stop(i); await start(i)

@app.post("/api/bots")
async def upload(files: list[UploadFile] = File(...), bot: str | None = Form(None), name: str | None = Form(None)):
    if bot and bot not in meta: raise HTTPException(404)
    i = bot or slug(name or Path(files[0].filename).stem); d = bdir(i); d.mkdir(parents=True, exist_ok=True)
    for f in files:
        data = await f.read(); fn = Path(f.filename).name
        if len(data) > 150_000_000: raise HTTPException(413, "file too large")
        if fn.lower().endswith(".zip"): await asyncio.to_thread(unzip, data, d)
        else: (d / fn).write_bytes(data)
    m = meta.setdefault(i, {"name": name or i, "env": {}, "want": False, "created": int(time.time())})
    if not (m.get("entry") and (d / m["entry"]).exists()): m["entry"] = detect_entry(d)
    if (d / ".env").exists():
        for k, v in parse_env((d / ".env").read_text(errors="ignore")).items(): m["env"].setdefault(k, v)
    save(); await emit(i, f"[host] received {len(files)} file(s), entry: {m['entry'] or 'none found'}")
    asyncio.create_task(after_upload(i, R(i).state == "running"))
    return {"id": i}

# ---------------- api ----------------
@app.get("/api/bots")
def lst():
    return [{"id": i, "name": m["name"], "state": R(i).state, "restarts": R(i).restarts, "entry": m.get("entry", ""),
             "up": int(time.time() - R(i).started) if R(i).state == "running" else 0, "mem": rss(R(i).p) if R(i).p else 0} for i, m in meta.items()]

@app.get("/api/bots/{i}")
def info(i: str):
    if i not in meta: raise HTTPException(404)
    d = bdir(i); req = d / "requirements.txt"
    files = [{"path": str(p.relative_to(d)), "size": p.stat().st_size} for p in sorted(d.rglob("*")) if p.is_file() and not {"venv", "__pycache__", ".git"} & set(p.relative_to(d).parts)][:400]
    return {"id": i, **meta[i], "state": R(i).state, "files": files, "entries": rel(d), "env_spec": detect_env(d),
            "requirements": req.read_text(errors="ignore") if req.exists() else "", "installed": (d / "venv/bin/python").exists()}

@app.put("/api/bots/{i}")
async def edit(i: str, req: Request):
    b = await req.json(); m = meta[i]
    if b.get("entry") in rel(bdir(i)): m["entry"] = b["entry"]
    if b.get("name"): m["name"] = str(b["name"])[:40]
    save(); return {"ok": 1}

@app.put("/api/bots/{i}/env")
async def setenv(i: str, req: Request):
    b = await req.json(); meta[i]["env"] = {k: str(v) for k, v in b["env"].items() if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k)}; save()
    (bdir(i) / ".env").write_text("".join(f"{k}={json.dumps(v)}\n" for k, v in meta[i]["env"].items()))
    if b.get("restart") and R(i).state in ("running", "restarting"): await stop(i); await start(i)
    return {"ok": 1}

@app.post("/api/bots/{i}/{act}")
async def action(i: str, act: str):
    if i not in meta: raise HTTPException(404)
    if act == "start": asyncio.create_task(start(i))
    elif act == "stop": await stop(i)
    elif act == "restart": await stop(i); asyncio.create_task(start(i))
    elif act == "install": asyncio.create_task(install(i))
    else: raise HTTPException(400)
    return {"ok": 1}

@app.delete("/api/bots/{i}")
async def delete(i: str):
    if i not in meta: raise HTTPException(404)
    await stop(i); shutil.rmtree(bdir(i), ignore_errors=True); meta.pop(i); rt.pop(i, None); save(); return {"ok": 1}

@app.websocket("/ws/{i}")
async def ws(w: WebSocket, i: str):
    if not valid(w.cookies.get("t")) or i not in meta: return await w.close(4401)
    await w.accept(); r = R(i)
    await w.send_text("\n".join(r.logs) if r.logs else "[host] terminal ready. try: pip list, ls, python --version"); r.subs.add(w)
    async def run(c):
        try: rc = await asyncio.wait_for(sh(i, c), 900); await emit(i, f"[exit {rc}]")
        except asyncio.TimeoutError: await emit(i, "[host] command timed out (15 min)")
    try:
        while True:
            m = json.loads(await w.receive_text())
            if m.get("kill"):
                for p in list(r.cmds): killg(p, signal.SIGINT)
            elif m.get("cmd"):
                c = m["cmd"].strip()
                if c == "clear": r.logs.clear()
                else: await emit(i, "$ " + c); asyncio.create_task(run(c))
    except WebSocketDisconnect: pass
    finally: r.subs.discard(w)

@app.get("/health")
def health(): return {"ok": 1}

@app.get("/")
def home(): return FileResponse(HERE / "index.html")

async def keep():
    u = os.environ["RENDER_EXTERNAL_URL"] + "/health"
    while True:
        await asyncio.sleep(600)
        try: await asyncio.to_thread(lambda: urllib.request.urlopen(u, timeout=20).read())
        except Exception: pass

@app.on_event("startup")
async def boot():
    for i, m in meta.items():
        if m.get("want"): asyncio.create_task(start(i))
    if os.getenv("KEEPALIVE") and os.getenv("RENDER_EXTERNAL_URL"): asyncio.create_task(keep())

@app.on_event("shutdown")
async def down():
    for r in rt.values():
        if r.p and r.p.returncode is None: killg(r.p, signal.SIGTERM)
