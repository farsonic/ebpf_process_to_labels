#!/usr/bin/python3

import socket
import struct
import pwd
import time
import json
import redis
import requests
import urllib3
import threading
import argparse
from collections import defaultdict
from bcc import BPF
from requests.structures import CaseInsensitiveDict

# === Command-line Arguments ===
parser = argparse.ArgumentParser(description="Connection tracker and workload label pusher")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

DEBUG = args.debug

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIG ===
TTL_SECONDS = 3600
CONFIG_FILE = "config.json"
SUMMARY_INTERVAL = 5  # seconds

# === Redis & Config ===
r = redis.Redis(host='localhost', port=6379, db=0)
with open(CONFIG_FILE) as f:
    config = json.load(f)
psm_ip = config['psmipaddress']
psm_user = config['psmusername']
psm_pass = config['psmpassword']
local_ip = config.get('hostip', '127.0.0.1')
spec_hostname = config.get('spec_hostname', 'autodiscovered-host')
meta_name = config.get('hostname', 'autodiscovered-host')

# === PSM Auth ===
def get_token():
    url = f"https://{psm_ip}/v1/login"
    creds = {"username": psm_user, "password": psm_pass, "tenant": "default"}
    headers = {"Content-Type": "application/json"}
    res = requests.post(url, headers=headers, data=json.dumps(creds), verify=False, timeout=5)
    if DEBUG:
        print(f"[DEBUG] Token request response: {res.status_code} {res.text}")
    return res.headers.get("Set-Cookie", "")

def construct_headers(token):
    return {
        "Content-Type": "application/json",
        "accept": "application/json; version=1.0",
        "cookie": token
    }

# === BPF PROGRAM ===
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct conn_info_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
    u8 direction;
};

BPF_HASH(sockstore, u32, struct sock *);
BPF_PERF_OUTPUT(events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    sockstore.update(&pid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skpp = sockstore.lookup(&pid);
    if (!skpp) return 0;
    struct sock *sk = *skpp;
    sockstore.delete(&pid);

    struct conn_info_t data = {};
    struct inet_sock *inet = (struct inet_sock *)sk;

    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &inet->inet_sport);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &inet->inet_dport);
    data.pid = pid;
    data.uid = bpf_get_current_uid_gid();
    data.direction = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_accept_return(struct pt_regs *ctx) {
    struct conn_info_t data = {};
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &inet->inet_dport);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &inet->inet_sport);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.direction = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

def inet_ntoa(addr): return socket.inet_ntoa(struct.pack("<I", addr))
def uid_to_user(uid):
    try: return pwd.getpwuid(uid).pw_name
    except KeyError: return str(uid)
def is_loopback(ip): return ip.startswith("127.") or ip == "::1"

# === Workload Pusher ===
def push_summary_to_psm():
    token = get_token()
    headers = construct_headers(token)

    active_keys = r.keys()
    grouped_labels = defaultdict(set)

    for key in active_keys:
        key = key.decode()
        if r.ttl(key) > 0:
            parts = key.split(":")
            if len(parts) == 4:
                direction, user, comm, dport = parts
                grouped_labels[f"{direction}:{user}"].add(f"{comm}:{dport}")

    if not grouped_labels:
        if DEBUG: print("[DEBUG] No active labels to send.")
        return

    summary_labels = {k: " ".join(sorted(v)) for k, v in grouped_labels.items()}

    payload = {
        "kind": "Workload",
        "api-version": "v1",
        "meta": {
            "name": meta_name,
            "tenant": "default",
            "labels": summary_labels
        },
        "spec": {
            "host-name": spec_hostname,
            "interfaces": [{"ip-addresses": [local_ip]}],
            "migration-timeout": "60s"
        }
    }

    url = f"https://{psm_ip}/configs/workload/v1/tenant/default/workloads/{meta_name}"
    res = requests.get(url, headers=headers, verify=False)

    if res.status_code == 200:
        obj = res.json()
        obj["meta"]["labels"] = payload["meta"]["labels"]
        obj["spec"]["interfaces"] = payload["spec"]["interfaces"]
        r2 = requests.put(url, headers=headers, json=obj, verify=False)
        if DEBUG: print(f"[DEBUG] PUT {url}: {r2.status_code} {r2.text}")
    elif res.status_code == 404:
        r2 = requests.post(url.replace(f"/{meta_name}", ""), headers=headers, json=payload, verify=False)
        if DEBUG: print(f"[DEBUG] POST {url}: {r2.status_code} {r2.text}")
    else:
        print(f"[DEBUG] Unexpected status {res.status_code}: {res.text}")

def periodic_push_loop():
    while True:
        time.sleep(SUMMARY_INTERVAL)
        if DEBUG: print("[DEBUG] Sending periodic summary update...")
        push_summary_to_psm()

threading.Thread(target=periodic_push_loop, daemon=True).start()

# === Event Handler ===
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    saddr = inet_ntoa(event.saddr)
    daddr = inet_ntoa(event.daddr)
    if is_loopback(saddr) and is_loopback(daddr): return
    dport = socket.ntohs(event.dport)
    user = uid_to_user(event.uid)
    comm = event.comm.decode(errors="replace").strip()
    direction = "out" if event.direction == 0 else "in"
    key = f"{direction}:{user}:{comm}:{dport}"

    r.setex(key, TTL_SECONDS, int(time.time()))
    if DEBUG:
        print(f"[DEBUG] New connection: {key} from {saddr if direction == 'out' else daddr}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopped.")
