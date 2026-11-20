import os, re, subprocess, time
from datetime import datetime

LOG_PATH = "/root/pearl_f2pool/safe_lp.log"

def get_gpu():
    out = subprocess.getoutput(
        "nvidia-smi --query-gpu=name,temperature.gpu,power.draw,utilization.gpu,clocks.current.graphics,clocks.current.memory --format=csv,noheader,nounits"
    ).strip()
    if not out:
        return ("CMP 40HX", "0", "0", "0", "0", "0")
    parts = [x.strip() for x in out.split(",")]
    while len(parts) < 6:
        parts.append("0")
    return tuple(parts[:6])

def parse_log(path, max_events=7):
    if not os.path.exists(path):
        return [], 0.0, 0, 0, 0, "waiting..."
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    events = []
    hr = 0.0
    acc = 0
    rej = 0
    hw = 0
    pool_tag = "luckypool-sg1"

    for line in lines[-400:]:
        m_hr = re.search(r"(\d+(?:\.\d+)?)\s*TH/s", line)
        if m_hr:
            hr = float(m_hr.group(1))
        if "SHARE ACCEPTED" in line or "share accepted" in line:
            acc += 1
        if "rejected" in line.lower() or "submit error" in line.lower() or "decode failed" in line.lower():
            rej += 1
        if "WATCHDOG" in line or "RETRY" in line:
            hw += 1
        if "luckypool" in line.lower():
            pool_tag = "luckypool-sg1"
        elif "f2pool" in line.lower():
            pool_tag = "f2pool"

        if any(k in line for k in ("Job ", "job ", "HIT tile", "submitting share", "[POOL]", "SHARE ACCEPTED", "authorized", "WATCHDOG", "WARN", "RETRY", "error", "Error")):
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r"^\s*\d{2}:\d{2}:\d{2}\s*", "", line).strip()
            events.append(f"[{ts}] {clean[:115]}")

    return events[-max_events:], hr, acc, rej, hw, pool_tag

def render():
    name, temp, power, util, gclk, mclk = get_gpu()
    events, hr, acc, rej, hw, pool_tag = parse_log(LOG_PATH)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    acc_pct = f"{(acc / max(1, acc + rej) * 100):.2f}%" if (acc + rej) > 0 else "0.00%"

    buf = ["\033[H\033[J"]
    for ev in events:
        buf.append(ev)

    buf.append(f"[{now}] ----------------- [ Pearl Miner TUI - Statistics ] -----------------")
    buf.append(f"[{now}] -------- [ {pool_tag} ] ------------------------------------------------")
    buf.append(f"[{now}]   ID  Name            Hashrate     Power     Temp    GPU/Mem MHz     A    R    HW")
    buf.append(f"[{now}]   ---------------------------------------------------------------------------------")
    buf.append(f"[{now}]   0   {name:<15} {hr:>7.2f} TH/s {float(power or 0):>6.1f} W  {int(float(temp or 0)):>3d} C  {int(float(gclk or 0)):>4d}/{int(float(mclk or 0)):<4d}   {acc:<4d} {rej:<4d} {hw:<4d}")
    buf.append(f"[{now}]   ---------------------------------------------------------------------------------")
    buf.append(f"[{now}]   Total Hashrate: {hr:>7.2f} TH/s | Power: {float(power or 0):>6.1f} W | Util: {int(float(util or 0)):>2d}%")
    buf.append(f"[{now}]   Share stats [{acc_pct} Accepted | A:{acc} R:{rej} HW:{hw}]")
    print("\n".join(buf), flush=True)

if __name__ == "__main__":
    try:
        while True:
            render()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nExited monitor.")
