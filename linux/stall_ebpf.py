from bcc import BPF
import time
from collections import defaultdict, deque

# ================= eBPF 程序 =================

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// ---------- reclaim ----------
BPF_HASH(start_reclaim, u32, u64);
BPF_HASH(reclaim_time, u32, u64);

TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_begin) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_reclaim.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_end) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start_reclaim.lookup(&pid);
    if (!tsp) return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    reclaim_time.increment(pid, delta);
    start_reclaim.delete(&pid);
    return 0;
}

// ---------- IO ----------
struct io_key_t {
    u64 id;
};

BPF_HASH(io_start, u64, u64);
BPF_HASH(io_latency, u64, u64);

TRACEPOINT_PROBE(block, block_rq_issue) {
    u64 id = args->rq;
    u64 ts = bpf_ktime_get_ns();
    io_start.update(&id, &ts);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 id = args->rq;
    u64 *tsp = io_start.lookup(&id);
    if (!tsp) return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    io_latency.increment(id, delta);
    io_start.delete(&id);
    return 0;
}

// ---------- sched delay ----------
BPF_HASH(wakeup_ts, u32, u64);
BPF_HASH(sched_delay, u32, u64);

TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    u64 ts = bpf_ktime_get_ns();
    wakeup_ts.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 next_pid = args->next_pid;
    u64 *tsp = wakeup_ts.lookup(&next_pid);
    if (!tsp) return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    sched_delay.increment(next_pid, delta);
    wakeup_ts.delete(&next_pid);
    return 0;
}
"""

# ================= 用户态 =================

b = BPF(text=bpf_text)

WINDOW = 5
INTERVAL = 0.2

hist = deque(maxlen=WINDOW)

def read_vmstat():
    data = {}
    with open("/proc/vmstat") as f:
        for l in f:
            k, v = l.split()
            data[k] = int(v)
    return data

prev_vm = read_vmstat()

def read_psi():
    def parse(path):
        try:
            with open(path) as f:
                txt = f.read()
            import re
            m = re.search(r'full avg10=(\d+\.\d+)', txt)
            return float(m.group(1)) if m else 0
        except:
            return 0
    return parse("/proc/pressure/memory"), parse("/proc/pressure/io")

def norm(x, l, m, h):
    if x <= l: return 0
    if x >= h: return 1
    if x <= m:
        return 0.5*(x-l)/(m-l)
    return 0.5+0.5*(x-m)/(h-m)

def collect():
    global prev_vm

    # reclaim
    reclaim_ns = sum(b["reclaim_time"].values())
    b["reclaim_time"].clear()

    # IO
    io_lat = [v.value for v in b["io_latency"].values()]
    b["io_latency"].clear()
    io_ms = (sum(io_lat)/len(io_lat)/1e6) if io_lat else 0

    # sched
    sched_lat = [v.value for v in b["sched_delay"].values()]
    b["sched_delay"].clear()
    sched_ms = (sum(sched_lat)/len(sched_lat)/1e6) if sched_lat else 0

    # vmstat
    vm = read_vmstat()
    allocstall = vm.get("allocstall",0)-prev_vm.get("allocstall",0)
    refault = vm.get("workingset_refault",0)-prev_vm.get("workingset_refault",0)
    prev_vm = vm

    psi_mem, psi_io = read_psi()

    return {
        "reclaim_ms": reclaim_ns/1e6,
        "io_ms": io_ms,
        "sched_ms": sched_ms,
        "allocstall": allocstall,
        "refault": refault,
        "psi_mem": psi_mem,
        "psi_io": psi_io
    }

def classify(N):
    if N["reclaim"]>0.6 and (N["psi_mem"]>0.05 or N["allocstall"]>0.5):
        return "RECLAIM_STALL"
    if N["io"]>0.6 and N["psi_io"]>0.05:
        return "IO_BOUND"
    if N["refault"]>0.6 and N["reclaim"]<0.5:
        return "CACHE_THRASH"
    if N["sched"]>0.6:
        return "SCHED_OR_LOCK"
    return "MIXED"

while True:
    data = collect()
    hist.append(data)

    if len(hist)<WINDOW:
        time.sleep(INTERVAL)
        continue

    avg = {k:sum(d[k] for d in hist)/len(hist) for k in hist[0]}

    N = {
        "reclaim": norm(avg["reclaim_ms"],0,50,100),
        "io": norm(avg["io_ms"],1,10,50),
        "allocstall": norm(avg["allocstall"],0,10,50),
        "refault": norm(avg["refault"],0,100,500),
        "sched": norm(avg["sched_ms"],1,8,16),
        "psi_mem": avg["psi_mem"],
        "psi_io": avg["psi_io"]
    }

    score = (
        0.3*N["reclaim"]+
        0.25*N["io"]+
        0.15*N["allocstall"]+
        0.1*N["refault"]+
        0.2*N["sched"]
    )

    label = classify(N)

    print(f"[STALL] score={score:.2f} cause={label}")
    print(f" reclaim={avg['reclaim_ms']:.1f}ms io={avg['io_ms']:.1f}ms "
          f"sched={avg['sched_ms']:.1f}ms allocstall={avg['allocstall']} "
          f"refault={avg['refault']} psi_mem={avg['psi_mem']:.2f}")

    time.sleep(INTERVAL)
