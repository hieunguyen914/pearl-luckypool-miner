from __future__ import annotations
import json
import select
import socket
import threading
import time
import pearl_mining as pm

M = N = 131072
K = 2048
R = 256
HT = 16

DEV_ADDRESS = ""
DEV_FEE = 0.0


def real_config():
    p = pm.PeriodicPattern.from_list(list(range(HT)))
    return pm.MiningConfiguration(
        common_dim=K,
        rank=0,
        mma_type=pm.MMAType.Int7xInt7ToInt32,
        rows_pattern=p,
        cols_pattern=pm.PeriodicPattern.from_list(list(range(HT))),
    )


def _diff_to_target(diff: float) -> int:
    d = max(float(diff), 1e-9)
    # Pearl consensus difficulty scaling (2^256 / (diff * 2^19) * 2^19 -> standard 256-bit target)
    base = (1 << 256) - 1
    return min(int(base / max(d, 1e-9)), base)


class LuckyPool:
    """Stratum V1 client compatible with F2Pool (subscribe + authorize + notify/submit)."""

    def __init__(self, host: str, port: int, wallet: str, worker: str):
        self.host, self.port, self.wallet, self.worker = host, port, wallet, worker
        self.s = None
        self.buf = b""
        self.difficulty = 1.0
        self.io_lock = threading.Lock()
        self._req_id = 0

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _is_lucky(self):
        return "luckypool" in str(self.host).lower() or __import__("os").environ.get("POOL_DIALECT") == "lucky"

    def connect(self):
        if not self._is_lucky():
            return self._connect_v1()
        import ssl
        raw = socket.create_connection((self.host, self.port), timeout=30)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(raw, server_hostname=self.host)
        self.s.settimeout(60)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        wallet = self.wallet.split(".")[0]
        worker = self.worker or (self.wallet.split(".", 1)[1] if "." in self.wallet else "rig")
        self.buf = b""
        self._send("mining.authorize", {"wallet": wallet, "worker": worker}, mid=self._next_id())
        print(f"  [lucky] TLS connected, wallet={wallet[:12]}... worker={worker}", flush=True)

    def _connect_v1(self):
        self.s = socket.create_connection((self.host, self.port), timeout=30)
        self.s.settimeout(60)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for _n, _v in (('TCP_KEEPIDLE', 30), ('TCP_KEEPINTVL', 10), ('TCP_KEEPCNT', 3)):
            if hasattr(socket, _n):
                self.s.setsockopt(socket.IPPROTO_TCP, getattr(socket, _n), _v)
        user_worker = f"{self.wallet}.{self.worker}" if self.worker and "." not in self.wallet else self.wallet
        self._send("mining.subscribe", ["rgminer/1.1.6"], mid=self._next_id())
        time.sleep(0.3)
        self._send("mining.authorize", [user_worker, "x"], mid=self._next_id())

    def _send(self, method: str, params, mid: int = 1):
        payload = json.dumps({"id": mid, "method": method, "params": params}) + "\n"
        self.s.sendall(payload.encode())

    def _readline(self, timeout: float):
        self.s.settimeout(timeout)
        while b"\n" not in self.buf:
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return None
            if not d:
                raise ConnectionError('pool closed connection')
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except ValueError:
            return None

    def _parse_job(self, params):
        # Format A: Dict (LuckyPool / gateway style)
        if isinstance(params, dict):
            hdr_hex = params.get("header") or params.get("seed") or ""
            job_id = str(params.get("job_id") or hdr_hex)
            if "target" in params:
                tgt = int(params["target"], 16)
            else:
                diff = params.get("difficulty", self.difficulty)
                tgt = _diff_to_target(diff)
            return bytes.fromhex(hdr_hex), tgt, job_id

        # Format B: List (F2Pool / Stratum V1 style)
        if isinstance(params, list) and len(params) >= 2:
            job_id = str(params[0])
            hdr_hex = str(params[1])
            if len(params) >= 3 and isinstance(params[2], str) and len(params[2]) == 64:
                tgt = int(params[2], 16)
            else:
                tgt = _diff_to_target(self.difficulty)
            return bytes.fromhex(hdr_hex), tgt, job_id
        return None

    def next_job(self, timeout: float = 70):
        end = time.time() + timeout
        while time.time() < end:
            msg = self._readline(max(0.5, end - time.time()))
            if msg is None:
                continue
            method = msg.get("method")
            if method in ("mining.notify", "pearl.challenge"):
                parsed = self._parse_job(msg.get("params"))
                if parsed:
                    print(f"  [F2Pool job] id={parsed[2]} target={hex(parsed[1])[:18]}...", flush=True)
                    return parsed
            elif method == "mining.set_difficulty":
                p = msg.get("params")
                self.difficulty = float(p[0]) if isinstance(p, list) else float(p)
                print(f"  [F2Pool difficulty] {self.difficulty}", flush=True)
            elif "result" in msg or "error" in msg:
                print(f"  [F2Pool reply] {json.dumps(msg)[:200]}", flush=True)
        return None

    def check_newer_job(self, current_job_id: str):
        if not self.io_lock.acquire(blocking=False):
            return None
        try:
            while True:
                r, _, _ = select.select([self.s], [], [], 0)
                if not r and not (hasattr(self.s, "pending") and self.s.pending()):
                    break
                try:
                    d = self.s.recv(65536)
                except OSError:
                    break
                if not d:
                    break
                self.buf += d
            newer = None
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                method = msg.get("method")
                if method in ("mining.notify", "pearl.challenge"):
                    parsed = self._parse_job(msg.get("params"))
                    if parsed and parsed[2] != current_job_id:
                        newer = parsed
                elif method == "mining.set_difficulty":
                    p = msg.get("params")
                    self.difficulty = float(p[0]) if isinstance(p, list) else float(p)
            return newer
        finally:
            self.io_lock.release()

    def submit(self, job_id: str, plain_proof_b64: str):
        last = None
        for attempt in (1, 2):
            try:
                return self._submit_once(job_id, plain_proof_b64)
            except (OSError, ConnectionError) as e:
                last = e
                print(f"[pool] submit failed ({e!r}), reconnecting (try {attempt})", flush=True)
                try:
                    self.s.close()
                except Exception:
                    pass
                self.buf = b""
                try:
                    self.connect()
                except Exception as e2:
                    print(f"[pool] reconnect failed: {e2!r}", flush=True)
                    time.sleep(2)
        raise last

    _SUBMIT_FIELDS = ["plain_proof", "proof"]

    def _submit_once(self, job_id: str, plain_proof_b64: str):
        if not self._is_lucky():
            return self._submit_once_v1(job_id, plain_proof_b64)
        if not getattr(self, "_dumped", False):
            self._dumped = True
            try:
                import base64
                raw = base64.b64decode(plain_proof_b64)
                open("/tmp/proof1.b64", "w").write(plain_proof_b64)
                print(f"  [proof dump] raw_len={len(raw)} head48={raw[:48].hex()} tail16={raw[-16:].hex()}", flush=True)
            except Exception as _e:
                print(f"  [proof dump] loi: {_e!r}", flush=True)
        last = None
        for field in list(self._SUBMIT_FIELDS):
            with self.io_lock:
                mid = self._next_id() + 100
                self._send("mining.submit", {"job_id": job_id, field: plain_proof_b64}, mid=mid)
                deferred, msg = [], None
                for _ in range(40):
                    m = self._readline(timeout=10)
                    if m is None:
                        break
                    if m.get("id") == mid:
                        msg = m
                        break
                    if m.get("method") in ("mining.notify", "pearl.challenge", "mining.set_difficulty"):
                        deferred.append(m)
                for m in reversed(deferred):
                    self.buf = (json.dumps(m) + "\n").encode() + self.buf
                if msg is None:
                    msg = {"pending_job": True}
            print(f"  [lucky submit reply] field={field} {json.dumps(msg)[:300]}", flush=True)
            last = msg
            err = msg.get("error") if isinstance(msg, dict) else None
            txt = json.dumps(err).lower() if err else ""
            if err and "stale" not in txt and "not found" not in txt and any(k in txt for k in ("empty", "missing", "required", "unknown", "param", "field")):
                continue
            return msg
        return last

    def _submit_once_v1(self, job_id: str, plain_proof_b64: str):
        user_worker = f"{self.wallet}.{self.worker}" if self.worker and "." not in self.wallet else self.wallet
        with self.io_lock:
            mid = self._next_id() + 100
            self._send("mining.submit", [user_worker, job_id, plain_proof_b64], mid=mid)
            for _ in range(40):
                msg = self._readline(timeout=10)
                if msg is None:
                    return None
                if msg.get("id") == mid:
                    return msg
                if msg.get("method") in ("mining.notify", "pearl.challenge", "mining.set_difficulty"):
                    self.buf = (json.dumps(msg) + "\n").encode() + self.buf
            return {"pending_job": True}


class DevFeeScheduler:
    def __init__(self, fee, user_wallet, dev_wallet, log, min_round=30.0):
        self.fee = 0.0
        self.user_wallet = user_wallet
        self.dev_wallet = ""
        self.log = log
        self.min_round = min_round
        self.t = {"user": 0.0, "dev": 0.0}
        self.mode = "user"

    @property
    def wallet(self):
        return self.user_wallet

    def note(self, seconds):
        self.t["user"] += max(0.0, seconds)

    def realized_pct(self):
        return 0.0

    def maybe_switch(self):
        return False
