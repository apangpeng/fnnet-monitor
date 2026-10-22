#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netmon - 飞牛 NAS / Linux 专用网络监控面板（网络监控为主界面）
=============================================================
网络监控采集维度：
  A. 每张网卡：状态/载波/MTU/双工/MAC/速率/驱动/固件 + 完整 16 字段计数器
     (rx: bytes packets errs drop fifo frame compressed multicast;
      tx: bytes packets errs drop fifo colls carrier compressed)
     + 实时速率 (B/s) + 包速率 (pkt/s) + 错误/丢包速率
  B. IPv4 / IPv6 地址（ip -o addr，保留 Docker/veth 等虚拟网卡可看）
  C. 全局协议计数器：TCP/UDP/ICMP/ICMPv6（/proc/net/snmp, snmp6），
     含重传率、新建连接、入错包等
  D. TCP/UDP 连接状态分布（LISTEN/ESTAB/TIME_WAIT/CLOSE_WAIT...）
  E. 监听端口：ss -tlnpH + ss -ulnpH（TCP+UDP，带进程名/PID）
  F. 默认网关 / DNS / 路由表
  G. Docker 容器：每容器累计 NetIO + 实时速率
  H. SQLite 历史：每网卡累计字节/速率/丢包/错误，用于今日/本月累计与趋势图

内置「下行带宽消耗器」（原 downstream-consumer 并入 PCDN 业务版块）：
  按设定速度持续消耗下行流量（默认不落盘、不写盘），网页限速/每日目标/
  下载源/启停 + 访问口令保护，API 位于 /api/dc/*，数据存于 <data-dir>/dc/。

用法:
  python3 server.py [--port 8778] [--data-dir ./data] [--interval 2] [--history-interval 60] [--retention-days 7]
无第三方依赖，Python 3.7+。
"""

import argparse
import datetime
import hmac
import ipaddress
import json
import os
import random
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.3.29"

# 虚拟网卡前缀（在"物理网卡"视图里默认过滤，但在"全部网卡"里仍展示）
VIRT_PREFIXES = ("docker", "veth", "br-", "virbr", "vnet", "tun", "tap",
                 "vxlan", "wg", "lxc", "kube", "zt", "tailscale", "ipsec")

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def read_text(path, default=""):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return default


def read_int(path, default=0):
    try:
        with open(path, "r", errors="ignore") as f:
            return int(f.read().strip())
    except Exception:
        return default


def run_cmd(argv, timeout=8):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.returncode
    except Exception:
        return "", -1


def run_cmd3(argv, timeout=8):
    """返回 (stdout, returncode, stderr)，供连接排行诊断用。"""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.returncode, p.stderr or ""
    except subprocess.TimeoutExpired:
        return "", -1, "timeout"
    except Exception as e:
        return "", -1, str(e)


def is_linux():
    return sys.platform.startswith("linux")


# ---------------------------------------------------------------------------
# IP 归属地（离线 ip2region v3 xdb，仅 IPv4；IPv6 暂不收录）
# ---------------------------------------------------------------------------

class XdbSearcher(object):
    """ip2region v3 xdb 查询器（纯 Python，无第三方依赖），支持 IPv4 + IPv6。
    文件结构：Header 256B（实际用 16B）→ Vector 索引 512KiB → 地域信息段 → 二分索引段。
    IPv4 二分索引项 14B：startIP(4) + endIP(4) + dataLen(2) + dataPtr(4)；
    IPv6 二分索引项 38B：startIP(16) + endIP(16) + dataLen(2) + dataPtr(4)；均小端。"""

    V4_FIXED = 14
    V6_FIXED = 38

    def __init__(self, path):
        self._data = open(path, "rb").read()
        self._idx_start = struct.unpack("<I", self._data[8:12])[0]
        self._idx_end = struct.unpack("<I", self._data[12:16])[0]

    def search(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return ""
        if addr.version == 4:
            return self._search_v4(struct.unpack(">I", addr.packed)[0])
        return self._search_v6(addr.packed)

    def _search_v4(self, val):
        # vector 索引按 IP 前两字节（0-65535）定位，每项 8B
        vp = 256 + ((val >> 16) & 0xFFFF) * 8
        start_ptr = struct.unpack("<I", self._data[vp:vp + 4])[0]
        end_ptr = struct.unpack("<I", self._data[vp + 4:vp + 8])[0]
        if end_ptr < start_ptr or end_ptr - start_ptr < self.V4_FIXED:
            return ""
        lo, hi = start_ptr, end_ptr - self.V4_FIXED
        while lo <= hi:
            mid = lo + ((hi - lo) // self.V4_FIXED) * self.V4_FIXED
            s_ip = struct.unpack("<I", self._data[mid:mid + 4])[0]
            e_ip = struct.unpack("<I", self._data[mid + 4:mid + 8])[0]
            if val < s_ip:
                hi = mid - self.V4_FIXED
            elif val > e_ip:
                lo = mid + self.V4_FIXED
            else:
                dlen = struct.unpack("<H", self._data[mid + 8:mid + 10])[0]
                dptr = struct.unpack("<I", self._data[mid + 10:mid + 14])[0]
                try:
                    return self._data[dptr:dptr + dlen].decode("utf-8", "ignore")
                except Exception:
                    return ""
        return ""

    def _search_v6(self, packed):
        # vector 索引按 IPv6 前 16 位（第一个 hextet）定位，每项 8B
        vp = 256 + (int.from_bytes(packed[0:2], "big")) * 8
        start_ptr = struct.unpack("<I", self._data[vp:vp + 4])[0]
        end_ptr = struct.unpack("<I", self._data[vp + 4:vp + 8])[0]
        if end_ptr < start_ptr or end_ptr - start_ptr < self.V6_FIXED:
            return ""
        lo, hi = start_ptr, end_ptr - self.V6_FIXED
        while lo <= hi:
            mid = lo + ((hi - lo) // self.V6_FIXED) * self.V6_FIXED
            s_ip = self._data[mid:mid + 16]
            e_ip = self._data[mid + 16:mid + 32]
            if packed < s_ip:
                hi = mid - self.V6_FIXED
            elif packed > e_ip:
                lo = mid + self.V6_FIXED
            else:
                dlen = struct.unpack("<H", self._data[mid + 32:mid + 34])[0]
                dptr = struct.unpack("<I", self._data[mid + 34:mid + 38])[0]
                try:
                    return self._data[dptr:dptr + dlen].decode("utf-8", "ignore")
                except Exception:
                    return ""
        return ""


_xdb_v4 = None
_xdb_v6 = None
_xdb_region_cache = {}


def get_xdb():
    """加载 IPv4 / IPv6 两个离线库（惰性，失败置 False 避免重复尝试）。"""
    global _xdb_v4, _xdb_v6
    if _xdb_v4 is None:
        try:
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip2region_v4.xdb")
            _xdb_v4 = XdbSearcher(p) if os.path.exists(p) else False
        except Exception:
            _xdb_v4 = False
    if _xdb_v6 is None:
        try:
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip2region_v6.xdb")
            _xdb_v6 = XdbSearcher(p) if os.path.exists(p) else False
        except Exception:
            _xdb_v6 = False
    return _xdb_v4, _xdb_v6


def _norm_region(parts):
    """把 xdb 的 国家|省|市|ISP|国家码（可能 4~5 段，含 0/Reserved 占位）整理成展示文本。"""
    out = []
    for s in parts:
        s = (s or "").strip()
        if not s or s in ("0", "-", "Reserved", "保留地址", "内网IP", "未分配"):
            continue
        # 结尾的国家码（CN/US/AU...）不展示
        if len(s) == 2 and s.isalpha() and s.isupper():
            continue
        if s not in out:
            out.append(s)
    return " ".join(out)


def ip_region(ip):
    """离线查询 IP 归属地（IPv4 + IPv6）。内网 / 失败返回空串。带缓存。"""
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return ""
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ""
    hit = _xdb_region_cache.get(ip)
    if hit is not None:
        return hit
    v4s, v6s = get_xdb()
    searcher = v6s if addr.version == 6 else v4s
    region = ""
    if searcher:
        raw = searcher.search(ip)
        if raw:
            region = _norm_region(raw.split("|"))
    if len(_xdb_region_cache) > 8192:
        _xdb_region_cache.clear()
    _xdb_region_cache[ip] = region
    return region


# 常见进程友好名（仅用于连接排行展示，不影响功能）
PROC_FRIENDLY = {
    "P2PClient": "网心云客户端",
    "trim-qbittorren": "qBittorrent",
    "xunlei-pan-cli": "迅雷云盘",
    "beam.smp": "Erlang 节点",
    "epmd": "Erlang 端口映射",
    "postgres": "PostgreSQL",
    "docs": "飞牛文档",
    "webdav": "WebDAV",
    "minidlnad": "MiniDLNA 媒体",
    "upnp_service": "UPnP 服务",
    "cloud_storage_d": "云存储",
    "baiduNas": "百度网盘",
    "seekbox": "SeekBox",
    "openclaw": "龙虾应用",
    "fntermx": "终端",
    "Xkasmvnc": "VNC 远程桌面",
    "fygo-browser-ga": "浏览器",
    "smbftpd": "SMB/FTP",
    "rpcbind": "RPC 绑定",
    "rpc.statd": "NFS 状态",
    "rpc.mountd": "NFS 挂载",
    "docker-proxy": "Docker 端口代理",
    "wsdd2": "WSDD 发现",
}


def friendly_proc(name):
    if not name:
        return ""
    return PROC_FRIENDLY.get(name, name)


# ---------------------------------------------------------------------------
# 路由出口网卡（连接排行标注"哪个网口出的"，最长前缀匹配）
# ---------------------------------------------------------------------------

_routes_cache = {"ts": 0.0, "routes": []}


def collect_routes_map():
    """读取主路由表（IPv4 + IPv6）→ [(dest, prefixlen, iface)]，30 秒缓存。"""
    now = time.time()
    if now - _routes_cache["ts"] < 30 and _routes_cache["routes"]:
        return _routes_cache["routes"]
    routes = []
    for cmd in (["ip", "route", "show"], ["ip", "-6", "route", "show"]):
        is6 = "-6" in cmd
        out, _ = run_cmd(cmd, timeout=4)
        for line in out.splitlines():
            p = line.split()
            if not p:
                continue
            if p[0] in ("unreachable", "blackhole", "prohibit", "throw", "local"):
                continue
            if p[0] == "default":
                # IPv6 默认路由必须存成 ::/0（IPv4 才是 0.0.0.0/0），否则 IPv6 地址匹配不到
                dest, plen = ("::", 0) if is6 else ("0.0.0.0", 0)
                rest = p[1:]
            elif p[0] == "fe80" or p[0] == "ff00" or "/" in p[0] or ":" not in p[0]:
                # IPv4 或带前缀的 IPv6：dest 在第一列；"fe80::/64" 也可能带 "/"
                dest = p[0]
                if "/" in dest:
                    dest, plen = dest.split("/", 1)
                    plen = int(plen)
                else:
                    plen = 32 if ":" not in dest else 128
                rest = p[1:]
            else:
                # 不带前缀的 IPv6 地址（/128）
                dest, plen, rest = p[0], 128, p[1:]
            if "dev" in rest:
                iface = rest[rest.index("dev") + 1]
            else:
                continue
            routes.append((dest, plen, iface))
    _routes_cache["ts"] = now
    _routes_cache["routes"] = routes
    return routes


def route_iface(ip):
    """远端 IP → 出口网卡名（最长前缀匹配）。查不到返回 ""。"""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return ""
    # 回环地址（127.0.0.0/8、::1、::ffff:127.x）是本机自连，不标注出口网卡
    # 注意：老版本 Python 的 IPv6 is_loopback 只认 ::1，IPv4-mapped 回环需另行判断
    if addr.is_loopback:
        return ""
    if addr.version == 6 and addr.ipv4_mapped is not None and addr.ipv4_mapped.is_loopback:
        return ""
    best = None
    for dest, plen, iface in collect_routes_map():
        try:
            net = ipaddress.ip_network("%s/%d" % (dest, plen), strict=False)
        except Exception:
            continue
        if addr.version == net.version and addr in net:
            if best is None or plen > best[0]:
                best = (plen, iface)
    return best[1] if best else ""


# ---------------------------------------------------------------------------
# A. 网卡信息采集
# ---------------------------------------------------------------------------

def read_net_dev():
    """解析 /proc/net/dev，返回 {iface: {rx_bytes,rx_packets,rx_errs,rx_drop,
    rx_fifo,rx_frame,rx_compressed,rx_multicast,
    tx_bytes,tx_packets,tx_errs,tx_drop,tx_fifo,tx_colls,tx_carrier,tx_compressed}}"""
    out = {}
    for line in read_text("/proc/net/dev").splitlines():
        if ":" not in line:
            continue
        iface, _, rest = line.partition(":")
        iface = iface.strip()
        f = rest.split()
        if len(f) < 16:
            continue
        try:
            out[iface] = {
                "rx_bytes": int(f[0]), "rx_packets": int(f[1]),
                "rx_errs": int(f[2]), "rx_drop": int(f[3]),
                "rx_fifo": int(f[4]), "rx_frame": int(f[5]),
                "rx_compressed": int(f[6]), "rx_multicast": int(f[7]),
                "tx_bytes": int(f[8]), "tx_packets": int(f[9]),
                "tx_errs": int(f[10]), "tx_drop": int(f[11]),
                "tx_fifo": int(f[12]), "tx_colls": int(f[13]),
                "tx_carrier": int(f[14]), "tx_compressed": int(f[15]),
            }
        except Exception:
            pass
    return out


def read_iface_sysfs(iface):
    """读取 /sys/class/net/<iface>/ 下的链路属性。"""
    base = "/sys/class/net/" + iface
    info = {
        "operstate": read_text(base + "/operstate").strip(),
        "carrier": read_int(base + "/carrier", -1),
        "mtu": read_int(base + "/mtu"),
        "speed_mbps": read_int(base + "/speed", 0),
        "duplex": read_text(base + "/duplex").strip(),
        "macaddress": read_text(base + "/address").strip(),
        "iftype": read_text(base + "/type").strip(),
    }
    # speed 在 down 状态下读不到，返回 -EINVAL 导致 read_int 失败 → 0
    # 用 ethtool 兜底
    if info["speed_mbps"] <= 0:
        out, rc = run_cmd(["ethtool", iface], timeout=4)
        if rc == 0:
            m = re.search(r"Speed:\s*([0-9]+)([MG])b/s", out)
            if m:
                v = int(m.group(1))
                info["speed_mbps"] = v * 1000 if m.group(2) == "G" else v
            m = re.search(r"Duplex:\s*(\w+)", out)
            if m and not info["duplex"]:
                info["duplex"] = m.group(1)
    # 驱动 / 固件版本
    drv = ""
    fw = ""
    uevent = read_text(base + "/device/uevent")
    m = re.search(r"DRIVER=(\S+)", uevent)
    if m:
        drv = m.group(1)
    if not drv:
        out, rc = run_cmd(["ethtool", "-i", iface], timeout=4)
        if rc == 0:
            m = re.search(r"driver:\s*(\S+)", out)
            if m:
                drv = m.group(1)
            m = re.search(r"firmware-version:\s*(.+)", out)
            if m:
                fw = m.group(1).strip()
    info["driver"] = drv
    info["firmware"] = fw
    return info


def read_iface_addrs():
    """ip -o addr → {iface: {ipv4:[...], ipv6:[...]}}"""
    out = {}
    txt, rc = run_cmd(["ip", "-o", "addr"], timeout=5)
    if rc == 0:
        for line in txt.splitlines():
            p = line.split()
            if len(p) < 4:
                continue
            try:
                iface = p[1].split("@")[0]
                fam = p[2]
                addr = p[3].split("/")[0]
            except Exception:
                continue
            e = out.setdefault(iface, {"ipv4": [], "ipv6": []})
            if fam == "inet":
                e["ipv4"].append(addr)
            elif fam == "inet6":
                a6 = addr.split("%")[0].lower()
                if a6.startswith("fe80") or a6 in ("::1", "::"):
                    continue
                e["ipv6"].append(a6)
    return out


# ---------------------------------------------------------------------------
# B. 全局协议计数器 /proc/net/snmp
# ---------------------------------------------------------------------------

def parse_snmp():
    """解析 /proc/net/snmp，返回 {'Tcp': {...}, 'Udp': {...}, 'Icmp': {...}}"""
    result = {}
    current = None
    keys = None
    for line in read_text("/proc/net/snmp").splitlines():
        line = line.strip()
        if not line:
            continue
        # 形如: "Tcp: RtoAlgorithm RtoMin ..."
        m = re.match(r"^(\w+):\s*(.*)$", line)
        if not m:
            continue
        name = m.group(1)
        rest = m.group(2).split()
        if keys is None or current != name:
            # 第一次出现该协议：是键名行
            current = name
            keys = rest
            result.setdefault(name, {})
        else:
            # 第二次出现：是值行
            for k, v in zip(keys, rest):
                try:
                    result[name][k] = int(v)
                except Exception:
                    result[name][k] = v
            keys = None
            current = None
    return result


def parse_snmp6():
    """解析 /proc/net/snmp6，返回 {Metric: value}（扁平）"""
    out = {}
    for line in read_text("/proc/net/snmp6").splitlines():
        p = line.split()
        if len(p) >= 2:
            try:
                out[p[0]] = int(p[1])
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------
# C. 连接状态分布 /proc/net/tcp{,6} + udp{,6}
# ---------------------------------------------------------------------------

def parse_proc_sock(path):
    """解析 /proc/net/tcp 等，返回 [{local_addr, local_port, rem_addr, rem_port, st, inode}]"""
    rows = []
    txt = read_text(path)
    if not txt:
        return rows
    lines = txt.splitlines()
    if len(lines) < 2:
        return rows
    for line in lines[1:]:
        p = line.split()
        if len(p) < 4:
            continue
        try:
            local = p[1]
            rem = p[2]
            st = int(p[3], 16)
            lip, lport = local.rsplit(":", 1)
            rip, rport = rem.rsplit(":", 1)
            rows.append({
                "local_port": int(lport, 16),
                "rem_port": int(rport, 16),
                "st": st,
            })
        except Exception:
            pass
    return rows


TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}


def collect_conn_states():
    """统计 TCP/UDP 连接状态分布。"""
    tcp_rows = parse_proc_sock("/proc/net/tcp") + parse_proc_sock("/proc/net/tcp6")
    udp_rows = parse_proc_sock("/proc/net/udp") + parse_proc_sock("/proc/net/udp6")
    dist = {}
    for r in tcp_rows:
        s = TCP_STATES.get(r["st"], "STG%02X" % r["st"])
        dist[s] = dist.get(s, 0) + 1
    return {
        "tcp_total": len(tcp_rows),
        "udp_total": len(udp_rows),
        "tcp_states": dist,
    }


# ---------------------------------------------------------------------------
# D. 监听端口 ss
# ---------------------------------------------------------------------------

# 常见端口用途说明（供前端分组展示，一眼看懂"这是啥"）
PORT_DESC = {
    # 文件共享
    21: ("文件共享", "FTP 文件传输（smbftpd）"),
    139: ("文件共享", "SMB 文件共享（Windows 网络邻居）"),
    445: ("文件共享", "SMB 文件共享（Windows 网络邻居）"),
    111: ("文件共享", "NFS RPC 端口映射"),
    2049: ("文件共享", "NFS 文件共享"),
    9024: ("文件共享", "NFS 挂载服务（rpc.mountd）"),
    42423: ("文件共享", "NFS 状态服务（rpc.statd）"),
    41750: ("文件共享", "NFS 高位配套端口"),
    5005: ("文件共享", "WebDAV 文件服务（HTTP）"),
    5006: ("文件共享", "WebDAV 文件服务（HTTPS）"),
    # 飞牛系统
    80: ("飞牛系统", "飞牛网页管理界面（HTTP）"),
    443: ("飞牛系统", "飞牛网页管理界面（HTTPS）"),
    5666: ("飞牛系统", "飞牛系统 API（HTTP）"),
    5667: ("飞牛系统", "飞牛系统 API（HTTPS）"),
    3702: ("飞牛系统", "局域网设备发现（wsdd2）"),
    49152: ("飞牛系统", "UPnP 设备发现 / 端口映射"),
    10500: ("飞牛系统", "飞牛文档服务"),
    10501: ("飞牛系统", "飞牛文档服务"),
    15244: ("飞牛系统", "飞牛云存储同步"),
    5432: ("飞牛系统", "PostgreSQL 数据库（系统后台）"),
    5672: ("飞牛系统", "RabbitMQ 消息队列"),
    25672: ("飞牛系统", "RabbitMQ 集群端口"),
    4369: ("飞牛系统", "Erlang 端口映射（RabbitMQ 辅助）"),
    5122: ("飞牛系统", "飞牛 Web 终端（fntermx）：浏览器里远程开命令行"),
    7475: ("飞牛系统", "飞牛远程访问 P2P 客户端（仅本机内部通道）"),
    10001: ("飞牛系统", "飞牛远程访问 P2P 通道（对外监听，异地访问 NAS 用）"),
    # 远程与虚拟机
    16000: ("远程与虚拟机", "虚拟机 VNC 远程桌面"),
    # 应用服务
    16002: ("应用服务", "飞牛浏览器服务"),
    21603: ("应用服务", "迅雷网盘客户端"),
    40633: ("应用服务", "迅雷网盘客户端（本机）"),
    46767: ("应用服务", "迅雷网盘客户端"),
    5700: ("应用服务", "Docker 容器映射端口"),
    8005: ("应用服务", "飞牛影视媒体服务（trim-media）：刮削与播放"),
    8200: ("应用服务", "DLNA 媒体共享（minidlnad）：电视/播放器直接播 NAS 里的视频"),
    10000: ("应用服务", "百度网盘客户端（baiduNas）"),
    18888: ("应用服务", "迅雷寻宝客户端组件（seekbox，迅雷系）"),
    32775: ("应用服务", "qBittorrent BT 下载器（飞牛版，IPv6 网桥口）"),
    41135: ("应用服务", "qBittorrent BT 下载器（飞牛版，内网网桥口）"),
    42165: ("应用服务", "qBittorrent BT 下载器（飞牛版，IPv6 网桥口）"),
    44381: ("应用服务", "qBittorrent BT 下载器（飞牛版，内网网桥口）"),
    32902: ("应用服务", "飞牛官方「龙虾」应用（OpenClaw）"),
    32904: ("应用服务", "飞牛官方「龙虾」应用（OpenClaw）"),
    # 本应用
    8778: ("本应用", "网络监控网页"),
}

PORT_GROUP_ORDER = ["文件共享", "飞牛系统", "远程与虚拟机", "应用服务", "本应用", "其他"]

# 进程名兜底说明：端口号不在上面表里时，按进程名归组并给说明
# （qBittorrent、迅雷、Docker 容器映射等应用的监听端口是动态高位端口，逐端口维护追不完）
PROCESS_DESC = {
    "trim-qbittorren": ("应用服务", "qBittorrent BT 下载器（飞牛版）"),
    "xunlei-pan-cli": ("应用服务", "迅雷网盘客户端"),
    "trim-media": ("应用服务", "飞牛影视媒体服务（trim-media）"),
    "minidlnad": ("应用服务", "DLNA 媒体共享（minidlnad）：电视/播放器直接播 NAS 里的视频"),
    "openclaw": ("应用服务", "飞牛官方「龙虾」应用（OpenClaw）"),
    "baiduNas": ("应用服务", "百度网盘客户端（baiduNas）"),
    "seekbox": ("应用服务", "迅雷寻宝客户端组件（seekbox，迅雷系）"),
    "docker-proxy": ("应用服务", "Docker 容器映射端口（去 Docker 容器流量看是哪个容器）"),
    "fntermx": ("飞牛系统", "飞牛 Web 终端（fntermx）：浏览器里远程开命令行"),
    "P2PClient": ("飞牛系统", "飞牛远程访问 P2P 客户端"),
    "smbftpd": ("文件共享", "FTP 文件传输（smbftpd）"),
}


def ss_listeners():
    """ss -tlnpH + ss -ulnpH → [{proto, addr, port, process, pid, group, desc}]"""
    rows = []
    for proto, flag in (("tcp", "-tlnpH"), ("udp", "-ulnpH")):
        out, rc = run_cmd(["ss", flag], timeout=6)
        if rc != 0 or not out.strip():
            continue
        for line in out.splitlines():
            p = line.split()
            if not p:
                continue
            if proto == "tcp":
                if p[0] != "LISTEN" or len(p) < 5:
                    continue
                addr = p[3]
                proc = p[5] if len(p) >= 6 else ""
            else:
                # udp 行没有 State 列：Recv-Q Send-Q Local Peer
                if len(p) < 5:
                    continue
                addr = p[4]
                proc = p[5] if len(p) >= 6 else ""
            if ":" not in addr:
                continue
            host, port_s = addr.rsplit(":", 1)
            try:
                port = int(port_s)
            except Exception:
                continue
            pname, pid = "", ""
            m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc)
            if m:
                pname, pid = m.group(1), m.group(2)
            if port in PORT_DESC:
                grp, desc = PORT_DESC[port]
            else:
                # 端口表未收录：按进程名兜底（覆盖动态高位端口），再无则归"其他"
                grp, desc = PROCESS_DESC.get(pname, ("其他", ""))
            rows.append({"proto": proto, "addr": host, "port": port,
                         "process": pname, "pid": pid, "group": grp, "desc": desc})
    # 去重
    seen = set()
    dedup = []
    for r in sorted(rows, key=lambda x: (x["proto"], x["port"], x["addr"])):
        k = (r["proto"], r["addr"], r["port"], r["process"], r["pid"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(r)
    return dedup


# ---------------------------------------------------------------------------
# D2. 连接流量排行：ss -tinp 每连接累计字节 → 两次采样差值得实时速率
# ---------------------------------------------------------------------------

def norm_ip(ip):
    """规范化 IP（IPv6 压缩形式），便于与 conntrack 文本匹配。"""
    if ":" in ip:
        try:
            return ipaddress.IPv6Address(ip).compressed
        except Exception:
            return ip
    return ip


def collect_local_ips(addrs):
    """从 ip -o addr 结果收集本机 IP 集合（规范化）。"""
    ips = set()
    for a in addrs.values():
        for ip in a.get("ipv4", []):
            ips.add(norm_ip(ip))
        for ip in a.get("ipv6", []):
            ips.add(norm_ip(ip))
    return ips


def _remote_host(remote):
    """从 ss 的远端地址 "1.2.3.4:443" / "[::1]:443" / "[fe80::1%eth0]:123" 提取主机部分。"""
    if remote.startswith("["):
        host, _, _ = remote[1:].partition("]")
    else:
        host, _, _ = remote.rpartition(":")
    if "%" in host:
        host = host.split("%", 1)[0]
    return host


def parse_ss_conn_top():
    """ss -tinp → (rows, diag)。
    不依赖 state established 过滤器（兼容各版本 ss），解析时只认 ESTAB 行。
    rows: [{ip, proc, pid, rx, tx, conns}]；rx=本端收到（下行）、tx=本端发出（上行）。
    diag: {"rc", "lines", "err", "head"}；head=ss 原始输出前 800 字符（供排障）。"""
    rows = []
    diag = {"rc": -1, "lines": 0, "err": "", "head": ""}
    if not is_linux():
        diag["err"] = "非 Linux 环境"
        return rows, diag
    txt, rc, err = run_cmd3(["ss", "-tinp"], timeout=15)
    diag["rc"] = rc
    diag["lines"] = len(txt.splitlines()) if txt else 0
    diag["err"] = (err or "")[:200]
    diag["head"] = txt[:800] if txt else ""
    if rc != 0 or not txt:
        return rows, diag
    conns = []
    cur = None
    for line in txt.splitlines():
        s = line.strip()
        if not s:
            if cur is not None:
                conns.append(cur)
                cur = None
            continue
        if s.startswith("ESTAB"):
            if cur is not None:
                conns.append(cur)
            p = s.split()
            cur = None
            if len(p) >= 5:
                cur = {"remote": p[4], "proc": "?", "pid": 0, "rx": 0, "tx": 0}
            continue
        if cur is None:
            continue
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', s)
        if m:
            cur["proc"] = m.group(1)
            cur["pid"] = int(m.group(2))
        m = re.search(r"bytes_acked:(\d+)", s)
        if m:
            cur["tx"] = int(m.group(1))
        else:
            m = re.search(r"bytes_sent:(\d+)", s)
            if m:
                cur["tx"] = int(m.group(1))
        m = re.search(r"bytes_received:(\d+)", s)
        if m:
            cur["rx"] = int(m.group(1))
        else:
            m = re.search(r"bytes_recv:(\d+)", s)
            if m:
                cur["rx"] = int(m.group(1))
    if cur is not None:
        conns.append(cur)
    # 按 远端IP + 进程 聚合
    agg = {}
    for c in conns:
        ip = _remote_host(c["remote"])
        if not ip or ip == "*":
            continue
        key = (ip, c["proc"], c["pid"])
        e = agg.get(key)
        if e is None:
            e = {"ip": ip, "proc": c["proc"], "pid": c["pid"], "rx": 0, "tx": 0, "conns": 0}
            agg[key] = e
        e["rx"] += c["rx"]
        e["tx"] += c["tx"]
        e["conns"] += 1
    return list(agg.values()), diag


def parse_conntrack(local_ips):
    """/proc/net/nf_conntrack 的 TCP+UDP 条目按远端 IP 聚合字节（无进程名）。
    local_ips: 本机 IP 规范化集合。返回 (tcp_rows, udp_rows, readable)。
    两端都非本机 IP 的行（如 NAT 中间态）无法判断方向，跳过。"""
    tcp_rows, udp_rows = [], []
    if not is_linux():
        return tcp_rows, udp_rows, False
    txt = read_text("/proc/net/nf_conntrack")
    if not txt:
        return tcp_rows, udp_rows, False
    agg_t, agg_u = {}, {}
    for line in txt.splitlines():
        if " tcp " not in line and " udp " not in line:
            continue
        is_udp = " udp " in line
        blocks = []
        cur = {}
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                if k in ("src", "dst", "sport", "dport", "packets", "bytes"):
                    cur[k] = v
                    continue
            if "src" in cur and "bytes" in cur:
                blocks.append(cur)
            cur = {}
        if "src" in cur and "bytes" in cur:
            blocks.append(cur)
        if not blocks:
            continue
        rx = tx = 0
        remote = None
        for b in blocks:
            src = norm_ip(b.get("src", ""))
            dst = norm_ip(b.get("dst", ""))
            try:
                bts = int(b.get("bytes", 0) or 0)
            except Exception:
                bts = 0
            if src in local_ips:
                tx += bts
                remote = dst or remote
            elif dst in local_ips:
                rx += bts
                remote = src or remote
        if remote is None:
            continue
        agg = agg_u if is_udp else agg_t
        e = agg.get(remote)
        if e is None:
            e = {"ip": remote, "rx": 0, "tx": 0, "conns": 0}
            agg[remote] = e
        e["rx"] += rx
        e["tx"] += tx
        e["conns"] += 1
    return list(agg_t.values()), list(agg_u.values()), True


# ---------------------------------------------------------------------------
# E. 路由 / DNS
# ---------------------------------------------------------------------------

def collect_routes():
    """默认网关 + DNS。"""
    gw = ""
    out, rc = run_cmd(["ip", "route"], timeout=4)
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("default"):
                m = re.search(r"via\s+(\S+)", line)
                if m:
                    gw = m.group(1)
                break
    dns = []
    for line in read_text("/etc/resolv.conf").splitlines():
        if line.startswith("nameserver"):
            p = line.split()
            if len(p) >= 2:
                dns.append(p[1])
    return {"gateway": gw, "dns": dns}


# ---------------------------------------------------------------------------
# F. Docker 容器网络
# ---------------------------------------------------------------------------

def parse_human_bytes(s):
    """'1.23GB' → int bytes。"""
    if not s:
        return 0
    s = s.strip()
    units = {"B": 1, "KB": 1024, "MB": 1048576, "GB": 1073741824,
             "TB": 1099511627776}
    for u in sorted(units, key=len, reverse=True):
        if s.endswith(u):
            try:
                return int(float(s[:-len(u)].strip()) * units[u])
            except Exception:
                return 0
    try:
        return int(float(s))
    except Exception:
        return 0


def collect_docker(prev_stats=None):
    """返回容器列表，含累计 NetIO 与实时速率（B/s）。
    prev_stats: 上一次 {cid: (rx, tx, ts)}。"""
    result = {"available": False, "containers": []}
    out, rc = run_cmd(["docker", "ps", "--format", "{{json .}}"], timeout=15)
    if rc != 0 or not out.strip():
        return result
    result["available"] = True
    containers = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            c = json.loads(line)
        except Exception:
            continue
        containers.append({
            "id": (c.get("ID") or "")[:12],
            "name": (c.get("Names") or "").lstrip("/"),
            "image": c.get("Image") or "",
            "state": c.get("State") or "",
            "status": c.get("Status") or "",
            "ports": c.get("Ports") or "",
            "net_in": 0, "net_out": 0,
            "rx_rate": 0.0, "tx_rate": 0.0,
        })
    # stats
    sout, src = run_cmd(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=30)
    now = time.time()
    if src == 0:
        smap = {}
        for line in sout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                s = json.loads(line)
                smap[(s.get("ID") or "")[:12]] = s
            except Exception:
                continue
        for c in containers:
            s = smap.get(c["id"])
            if not s:
                continue
            netio = s.get("NetIO", "")
            if "/" in netio:
                a, b = netio.split("/", 1)
                rx = parse_human_bytes(a)
                tx = parse_human_bytes(b)
            else:
                rx = tx = 0
            c["net_in"] = rx
            c["net_out"] = tx
            # 实时速率
            if prev_stats and c["id"] in prev_stats:
                prx, ptx, pts = prev_stats[c["id"]]
                dt = now - pts
                if dt > 0:
                    c["rx_rate"] = round(max(0, rx - prx) / dt, 1)
                    c["tx_rate"] = round(max(0, tx - ptx) / dt, 1)
    result["containers"] = containers
    result["_prev"] = {c["id"]: (c["net_in"], c["net_out"], now) for c in containers}
    return result


# ---------------------------------------------------------------------------
# H0. 配置读写（config.json，存 data_dir 下）
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "interval": 2,
    "retention_days": 7,
    "upstream_mbps": 0,          # 套餐上行带宽 Mbps，0=未设置
    "downstream_mbps": 0,        # 套餐下行带宽 Mbps，0=未设置
    "monthly_quota_gb": 0,       # 每月上行流量配额 GB，0=未设置
    "aliases": {},               # {"vnet3": "网心云", "docker0": "Docker 网桥"}
}


def load_config(data_dir):
    path = os.path.join(data_dir, "config.json")
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path, "r", errors="ignore") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            for k, v in saved.items():
                cfg[k] = v
    except Exception:
        pass
    if not isinstance(cfg.get("aliases"), dict):
        cfg["aliases"] = {}
    return cfg


def save_config(data_dir, cfg):
    path = os.path.join(data_dir, "config.json")
    merged = dict(DEFAULT_CONFIG)
    for k in merged:
        if k in cfg:
            merged[k] = cfg[k]
    with open(path, "w") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    return merged


# ---------------------------------------------------------------------------
# H1. 虚拟机识别（KVM / libvirt：把 vnetX 映射到虚拟机名）
# ---------------------------------------------------------------------------

_VNET_CACHE = {"map": {}, "ts": 0}


def detect_vms():
    """返回 {vnetX: 虚拟机名}。60 秒缓存。失败返回空 dict。"""
    now = time.time()
    if _VNET_CACHE["map"] and now - _VNET_CACHE["ts"] < 60:
        return _VNET_CACHE["map"]
    result = {}
    if not is_linux():
        _VNET_CACHE.update(map=result, ts=now)
        return result
    names, rc = run_cmd(["virsh", "list", "--name"], timeout=5)
    if rc != 0:
        _VNET_CACHE.update(map=result, ts=now)
        return result
    for line in names.splitlines():
        vm = line.strip()
        if not vm:
            continue
        out, _ = run_cmd(["virsh", "domiflist", vm], timeout=5)
        for row in out.splitlines():
            # 表头: Interface   Type      Source    Model
            p = row.split()
            if len(p) >= 1 and p[0].startswith("vnet"):
                result[p[0]] = vm
    _VNET_CACHE.update(map=result, ts=now)
    return result


# ---------------------------------------------------------------------------
# G. 历史数据库
# ---------------------------------------------------------------------------

class DB:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS metrics (
            ts REAL NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL)""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_metric_ts ON metrics(metric, ts)")

    def write(self, rows):
        if not rows:
            return
        with self.lock:
            try:
                self.conn.executemany(
                    "INSERT INTO metrics(ts, metric, value) VALUES(?,?,?)", rows)
            except Exception:
                pass

    def query_prefix(self, prefix, seconds):
        """返回 [(ts, metric, value), ...]，按时间升序。seconds=0 表示全部。"""
        sql = "SELECT ts, metric, value FROM metrics WHERE metric LIKE ?"
        args = [prefix + "%"]
        if seconds and seconds > 0:
            sql += " AND ts >= ?"
            args.append(time.time() - seconds)
        sql += " ORDER BY ts ASC"
        with self.lock:
            try:
                cur = self.conn.execute(sql, args)
                return cur.fetchall()
            except Exception:
                return []

    def cleanup(self, retention_days):
        cutoff = time.time() - retention_days * 86400
        with self.lock:
            try:
                self.conn.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
            except Exception:
                pass

    def reset_traffic(self):
        """清零流量累计统计：删除 rx_bytes:/tx_bytes:/drop:/err: 历史记录。
        实时速率（rx_rate:/tx_rate:）和趋势图保留，今日/本月累计从 0 重新开始。"""
        with self.lock:
            try:
                self.conn.execute(
                    "DELETE FROM metrics WHERE metric LIKE 'rx_bytes:%' "
                    "OR metric LIKE 'tx_bytes:%' OR metric LIKE 'drop:%' "
                    "OR metric LIKE 'err:%'")
                return self.conn.total_changes
            except Exception:
                return 0

    def size(self):
        try:
            return os.path.getsize(self.path)
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# H. 采集器（后台线程）
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self, db, data_dir=".", interval=2, history_interval=60, retention_days=7):
        self.db = db
        self.data_dir = data_dir
        self.interval = interval
        self.history_interval = history_interval
        self.retention_days = retention_days
        self.config = load_config(data_dir)
        self._stop = threading.Event()
        self._prev_dev = None
        self._prev_ts = 0
        self._prev_docker = None
        self._prev_snmp = None
        self._last_hist_ts = 0
        self._last_cleanup_ts = 0
        self._last_vnet_ts = 0
        self._conn_prev = {}          # (kind, ...) -> (ts, rx, tx)，连接排行速率采样
        self.vnet_map = {}
        self.conn_top = {"available": False, "top": [], "udp": [], "ts": 0,
                         "debug": {"ss_rc": -1, "ss_lines": 0, "ss_err": "", "ss_head": "",
                                   "conntrack": False, "fallback": "", "error": ""}}
        self.snapshot = {
            "ifaces": [], "snmp": {}, "snmp6": {}, "conn": {},
            "routes": {}, "docker": {"available": False, "containers": []},
            "vnet_map": {}, "conn_top": self.conn_top, "ts": 0,
        }

    def reload_config(self):
        self.config = load_config(self.data_dir)

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                sys.stderr.write("[netmon] tick error: %s\n" % e)
            self._stop.wait(self.interval)

    def _tick(self):
        now = time.time()
        cur = read_net_dev()
        addrs = read_iface_addrs()

        # 计算速率
        ifaces = []
        for name, c in cur.items():
            entry = {"iface": name, "virtual": name.startswith(VIRT_PREFIXES)}
            entry.update(c)
            # 速率
            rx_rate = tx_rate = rx_pkt = tx_pkt = 0.0
            if self._prev_dev and name in self._prev_dev and self._prev_ts:
                dt = now - self._prev_ts
                if dt > 0:
                    rx_rate = max(0, c["rx_bytes"] - self._prev_dev[name]["rx_bytes"]) / dt
                    tx_rate = max(0, c["tx_bytes"] - self._prev_dev[name]["tx_bytes"]) / dt
                    rx_pkt = max(0, c["rx_packets"] - self._prev_dev[name]["rx_packets"]) / dt
                    tx_pkt = max(0, c["tx_packets"] - self._prev_dev[name]["tx_packets"]) / dt
            entry["rx_rate"] = round(rx_rate, 1)
            entry["tx_rate"] = round(tx_rate, 1)
            entry["rx_pkt_rate"] = round(rx_pkt, 1)
            entry["tx_pkt_rate"] = round(tx_pkt, 1)
            # 链路属性
            if is_linux():
                entry.update(read_iface_sysfs(name))
            # 地址
            a = addrs.get(name, {"ipv4": [], "ipv6": []})
            entry["ipv4"] = a["ipv4"]
            entry["ipv6"] = a["ipv6"]
            ifaces.append(entry)

        # 排序：物理网卡在前，组内按网卡名固定排列（避免按流量排序导致卡片来回换位）
        ifaces.sort(key=lambda x: (x["virtual"], x["iface"]))

        # vnet 映射（每 30 秒刷新一次）
        if now - self._last_vnet_ts > 30:
            self._last_vnet_ts = now
            self.vnet_map = detect_vms()
        aliases = self.config.get("aliases", {})
        for it in ifaces:
            n = it["iface"]
            # 显示名：用户别名 > 虚拟机名 > 网卡名
            if n in aliases:
                it["label"] = aliases[n]
                it["label_kind"] = "alias"
            elif n in self.vnet_map:
                it["label"] = self.vnet_map[n]
                it["label_kind"] = "vm"
            else:
                it["label"] = n
                it["label_kind"] = "iface"

        snmp = parse_snmp()
        snmp6 = parse_snmp6()
        conn = collect_conn_states()
        routes = collect_routes()
        docker = collect_docker(self._prev_docker)
        self._prev_docker = docker.pop("_prev", None)
        self.conn_top = self._collect_conn_top(now, addrs)

        self.snapshot = {
            "ifaces": ifaces,
            "snmp": snmp,
            "snmp6": snmp6,
            "conn": conn,
            "routes": routes,
            "docker": docker,
            "vnet_map": self.vnet_map,
            "conn_top": self.conn_top,
            "ts": now,
        }

        # 历史写入
        if now - self._last_hist_ts >= self.history_interval:
            self._last_hist_ts = now
            rows = []
            for it in ifaces:
                n = it["iface"]
                rows.append((now, "rx_bytes:" + n, float(it["rx_bytes"])))
                rows.append((now, "tx_bytes:" + n, float(it["tx_bytes"])))
                rows.append((now, "rx_rate:" + n, float(it["rx_rate"])))
                rows.append((now, "tx_rate:" + n, float(it["tx_rate"])))
                rows.append((now, "drop:" + n, float(it["rx_drop"] + it["tx_drop"])))
                rows.append((now, "err:" + n, float(it["rx_errs"] + it["tx_errs"])))
            tcp = snmp.get("Tcp", {})
            if tcp:
                rows.append((now, "tcp_estab", float(tcp.get("CurrEstab", 0))))
                rows.append((now, "tcp_retrans", float(tcp.get("RetransSegs", 0))))
            self.db.write(rows)

        # 清理（每小时一次）
        if now - self._last_cleanup_ts > 3600:
            self._last_cleanup_ts = now
            self.db.cleanup(self.retention_days)

        self._prev_dev = cur
        self._prev_ts = now

    def _collect_conn_top(self, now, addrs):
        """连接流量排行：TCP（ss 每连接累计字节）+ UDP（conntrack），
        两次采样差值得实时速率；按远端 IP + 进程聚合。
        返回 {available, top, udp, ts, debug}；debug 含诊断信息（ss 返回码/行数/错误），
        采集异常被隔离并写入 debug.error，避免整轮 tick 中断。"""
        diag = {"ss_rc": -1, "ss_lines": 0, "ss_err": "", "ss_head": "", "conntrack": False,
                "fallback": "", "error": ""}
        try:
            tcp, sdiag = parse_ss_conn_top()
            diag["ss_rc"], diag["ss_lines"], diag["ss_err"], diag["ss_head"] = \
                sdiag["rc"], sdiag["lines"], sdiag["err"], sdiag["head"]
            ct_tcp, ct_udp, ct_ok = parse_conntrack(collect_local_ips(addrs))
            diag["conntrack"] = ct_ok
            # 合并 ss + conntrack：ss 行带进程名优先；conntrack 补充 ss 未覆盖的远端 IP
            # （无进程名，标记 ct=True）。两者都显示，宿主进程流量和虚拟机流量互不遗漏。
            ss_ips = set(e["ip"] for e in tcp)
            merged = list(tcp)
            if ct_tcp:
                for e in ct_tcp:
                    e.setdefault("proc", "")
                    e.setdefault("pid", 0)
                    e["ct"] = True
                    if e["ip"] not in ss_ips:
                        merged.append(e)
                diag["fallback"] = "conntrack-tcp" if not tcp else "merged"
            tcp = merged
            udp = ct_udp
            for e in udp:
                e["ct"] = True
            prev = self._conn_prev
            out_tcp, out_udp = [], []
            aliases = self.config.get("aliases", {}) if hasattr(self, "config") else {}
            vnet_map = getattr(self, "vnet_map", {}) or {}
            for e in tcp:
                key = ("t", e["ip"], e["proc"], e["pid"])
                p = prev.get(key)
                rx_rate = tx_rate = 0.0
                if p and now > p[0]:
                    dt = now - p[0]
                    if dt > 0:
                        rx_rate = max(0, e["rx"] - p[1]) / dt
                        tx_rate = max(0, e["tx"] - p[2]) / dt
                iface = route_iface(e["ip"])
                iface_lbl = aliases.get(iface) or vnet_map.get(iface) or iface
                out_tcp.append(dict(e, rx_rate=round(rx_rate, 1), tx_rate=round(tx_rate, 1),
                                    region=ip_region(e["ip"]),
                                    proc=friendly_proc(e.get("proc", "")),
                                    iface=iface, iface_lbl=iface_lbl))
            for e in udp:
                key = ("u", e["ip"])
                p = prev.get(key)
                rx_rate = tx_rate = 0.0
                if p and now > p[0]:
                    dt = now - p[0]
                    if dt > 0:
                        rx_rate = max(0, e["rx"] - p[1]) / dt
                        tx_rate = max(0, e["tx"] - p[2]) / dt
                iface = route_iface(e["ip"])
                iface_lbl = aliases.get(iface) or vnet_map.get(iface) or iface
                out_udp.append(dict(e, rx_rate=round(rx_rate, 1), tx_rate=round(tx_rate, 1),
                                    region=ip_region(e["ip"]),
                                    iface=iface, iface_lbl=iface_lbl))
            # 更新采样基准（限制规模，防连接频繁变动导致内存膨胀）
            new_prev = {}
            for e in tcp:
                new_prev[("t", e["ip"], e["proc"], e["pid"])] = (now, e["rx"], e["tx"])
            for e in udp:
                new_prev[("u", e["ip"])] = (now, e["rx"], e["tx"])
            if len(new_prev) < 2000:
                for k, v in prev.items():
                    if k not in new_prev:
                        new_prev[k] = v
                        if len(new_prev) >= 2000:
                            break
            self._conn_prev = new_prev
            out_tcp.sort(key=lambda x: x["rx_rate"] + x["tx_rate"], reverse=True)
            out_udp.sort(key=lambda x: x["rx_rate"] + x["tx_rate"], reverse=True)
            # 数据源任一可用即算功能可用
            usable = diag["ss_rc"] == 0 or ct_ok
            return {
                "available": is_linux() and usable,
                "top": out_tcp[:20],
                "udp": out_udp[:10],
                "ts": now,
                "debug": diag,
            }
        except Exception as e:
            diag["error"] = str(e)[:300]
            return {"available": False, "top": [], "udp": [], "ts": now, "debug": diag}


# ---------------------------------------------------------------------------
# I. HTTP 接口
# ---------------------------------------------------------------------------

STATIC_DIR = os.path.dirname(os.path.abspath(__file__))


class Handler(BaseHTTPRequestHandler):
    server_version = "netmon/" + VERSION

    def log_message(self, fmt, *args):
        pass  # 静默

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except Exception:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path in ("/", "/index.html"):
            return self._send_file(os.path.join(STATIC_DIR, "index.html"),
                                   "text/html; charset=utf-8")

        if path == "/api/net":
            s = self.server.collector.snapshot
            # 虚拟网卡方向修正：vnet/tap/veth 是宿主侧的成对虚拟网线（一端宿主、一端虚拟机/容器）。
            # 宿主侧 RX=从对端收到的流量=客户机的上行；宿主侧 TX=发给对端的流量=客户机的下行。
            # 显示层把这类设备的 RX/TX 互换，让"上行/下行"符合虚拟机/容器视角；
            # 物理网卡与网桥（docker0/br-*）方向语义不变，内部快照与历史数据也不受影响。
            ifaces = [dict(it) for it in s["ifaces"]]
            for it in ifaces:
                if it["iface"].startswith(("vnet", "veth", "tap")):
                    it["rx_bytes"], it["tx_bytes"] = it["tx_bytes"], it["rx_bytes"]
                    it["rx_rate"], it["tx_rate"] = it["tx_rate"], it["rx_rate"]
                    it["rx_packets"], it["tx_packets"] = it["tx_packets"], it["rx_packets"]
                    it["rx_pkt_rate"], it["tx_pkt_rate"] = it["tx_pkt_rate"], it["rx_pkt_rate"]
            return self._send_json({**s, "ifaces": ifaces})

        if path == "/api/ports":
            return self._send_json({"listeners": ss_listeners(), "ts": time.time()})

        if path == "/api/conn_top":
            return self._send_json(self.server.collector.conn_top)

        if path == "/api/traffic":
            return self._send_traffic(qs)

        if path == "/api/history":
            return self._send_history(qs)

        if path == "/api/info":
            return self._send_json({
                "version": VERSION,
                "ts": time.time(),
                "host": socket.gethostname(),
                "db_size": self.server.collector.db.size(),
                "interval": self.server.collector.interval,
                "history_interval": self.server.collector.history_interval,
            })

        if path == "/api/config":
            return self._send_json(self.server.collector.config)

        if path.startswith("/api/dc/"):
            return self._dc_get(path)

        self.send_error(404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path.startswith("/api/dc/"):
            return self._dc_post(u.path)
        if u.path == "/api/config":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = self.rfile.read(length).decode("utf-8")
                data = json.loads(body)
            except Exception:
                return self._send_json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
            # 只允许更新白名单字段
            allowed = ("upstream_mbps", "downstream_mbps", "monthly_quota_gb",
                       "aliases", "interval", "retention_days")
            patch = {}
            for k in allowed:
                if k in data:
                    patch[k] = data[k]
            saved = save_config(self.server.collector.data_dir, patch)
            self.server.collector.reload_config()
            return self._send_json({"ok": True, "config": saved})
        if u.path == "/api/reset_traffic":
            n = self.server.collector.db.reset_traffic()
            return self._send_json({"ok": True, "deleted_rows": n})
        self.send_error(404)

    def _send_traffic(self, qs):
        """今日/本月/开机累计上下行字节（由历史累计字节差值算）。"""
        s = self.server.collector.snapshot
        now = time.time()
        import datetime
        d = datetime.datetime.now()
        today_start = datetime.datetime(d.year, d.month, d.day).timestamp()
        month_start = datetime.datetime(d.year, d.month, 1).timestamp()

        def period_totals(seconds):
            rows = self.server.collector.db.query_prefix("rx_bytes:", seconds)
            rows += self.server.collector.db.query_prefix("tx_bytes:", seconds)
            rx_by_if = {}
            tx_by_if = {}
            for ts, metric, v in rows:
                iface = metric.split(":", 1)[1]
                if metric.startswith("rx_bytes:"):
                    rx_by_if.setdefault(iface, []).append((ts, v))
                else:
                    tx_by_if.setdefault(iface, []).append((ts, v))
            # 只统计物理网卡：过滤 lo 和虚拟网卡（docker/veth/vnet/br-/tun 等），
            # 这些网卡的 rx≈tx 会把 PCDN 真实的"上行远大于下行"比例平均掉。
            def _is_physical(n):
                if n == "lo":
                    return False
                return not n.startswith(VIRT_PREFIXES)
            rx = tx = 0
            for iface, pts in rx_by_if.items():
                if not _is_physical(iface):
                    continue
                pts.sort()
                rx += max(0, pts[-1][1] - pts[0][1])
            for iface, pts in tx_by_if.items():
                if not _is_physical(iface):
                    continue
                pts.sort()
                tx += max(0, pts[-1][1] - pts[0][1])
            return rx, tx

        today_rx, today_tx = period_totals(now - today_start)
        month_rx, month_tx = period_totals(now - month_start)
        # 开机累计：直接读 /proc/net/dev 当前值
        boot_rx = boot_tx = 0
        for it in s["ifaces"]:
            if it["iface"] == "lo" or it.get("virtual"):
                continue
            boot_rx += it["rx_bytes"]
            boot_tx += it["tx_bytes"]

        # ---- PCDN 辅助计算 ----
        cfg = self.server.collector.config
        upstream_mbps = float(cfg.get("upstream_mbps", 0) or 0)
        monthly_quota_gb = float(cfg.get("monthly_quota_gb", 0) or 0)
        # 实时上行速率（B/s）→ Mbps
        real_tx_bps = sum(it["tx_rate"] for it in s["ifaces"] if not it.get("virtual"))
        real_tx_mbps = real_tx_bps * 8 / 1_000_000.0
        upstream_util = round(real_tx_mbps / upstream_mbps * 100, 1) if upstream_mbps > 0 else None
        # 上下行比（PCDN 正常应 >1，越大表示上传越多）
        real_rx_bps = sum(it["rx_rate"] for it in s["ifaces"] if not it.get("virtual"))
        ratio = round(real_tx_bps / real_rx_bps, 2) if real_rx_bps > 1024 else None
        # 本月上行配额进度
        month_tx_gb = month_tx / 1_073_741_824.0
        quota_pct = round(month_tx_gb / monthly_quota_gb * 100, 1) if monthly_quota_gb > 0 else None

        return self._send_json({
            "realtime": {
                "rx_rate": round(real_rx_bps, 1),
                "tx_rate": round(real_tx_bps, 1),
                "tx_mbps": round(real_tx_mbps, 2),
            },
            "boot": {"rx": boot_rx, "tx": boot_tx},
            "today": {"rx": today_rx, "tx": today_tx},
            "month": {"rx": month_rx, "tx": month_tx},
            "pcdn": {
                "upstream_mbps_cfg": upstream_mbps,
                "upstream_util_pct": upstream_util,
                "tx_rx_ratio": ratio,
                "month_tx_gb": round(month_tx_gb, 2),
                "monthly_quota_gb": monthly_quota_gb,
                "quota_pct": quota_pct,
            },
        })

    def _send_history(self, qs):
        rng = qs.get("range", ["1h"])[0]
        seconds = {"10m": 600, "1h": 3600, "6h": 21600,
                   "24h": 86400, "7d": 604800, "all": 0}.get(rng, 3600)
        rx_rows = self.server.collector.db.query_prefix("rx_rate:", seconds)
        tx_rows = self.server.collector.db.query_prefix("tx_rate:", seconds)
        rx_map = {}
        tx_map = {}
        for ts, metric, v in rx_rows:
            iface = metric.split(":", 1)[1]
            if iface.startswith(VIRT_PREFIXES):
                continue
            rx_map[ts] = rx_map.get(ts, 0) + v
        for ts, metric, v in tx_rows:
            iface = metric.split(":", 1)[1]
            if iface.startswith(VIRT_PREFIXES):
                continue
            tx_map[ts] = tx_map.get(ts, 0) + v
        all_ts = sorted(set(rx_map) | set(tx_map))
        step = max(1, len(all_ts) // 720)
        sampled = all_ts[::step]
        return self._send_json({
            "range": rng,
            "rx": [[t, round(rx_map.get(t, 0), 1)] for t in sampled],
            "tx": [[t, round(tx_map.get(t, 0), 1)] for t in sampled],
        })

    # ------------------------------------------------------------------
    # 下行带宽消耗器接口（/api/dc/*，访问口令保护）
    # ------------------------------------------------------------------

    def _dc_deny(self):
        self._send_json({"ok": False, "auth": False, "error": "需要访问口令"}, 401)

    def _dc_authed(self):
        return dc_authorized(self.server.collector.data_dir, self.headers)

    def _dc_get(self, path):
        data_dir = self.server.collector.data_dir
        dl = dc_downloader
        if path == "/api/dc/status":
            tok = dc_read_token(data_dir)
            if not tok:
                # 尚未设置访问口令：前端据此进入"设置口令"流程
                return self._send_json({"ok": True, "auth": False, "setup": True})
            if not self._dc_authed():
                return self._dc_deny()
            st = dc_status(data_dir, dl)
            st['auth'] = True
            return self._send_json(st)
        if path == "/api/dc/config":
            if not self._dc_authed():
                return self._dc_deny()
            cfg = dc_read_cfg(data_dir)
            return self._send_json({"ok": True, "speed_mbps": cfg['speed'],
                                    "daily_gb": cfg['daily_gb'],
                                    "check_minutes": cfg['check_minutes'],
                                    "download_mode": cfg['mode']})
        if path == "/api/dc/urls":
            if not self._dc_authed():
                return self._dc_deny()
            try:
                with open(dc_paths(data_dir)["urls"], encoding="utf-8") as f:
                    content = f.read()
                return self._send_json({"ok": True, "urls": content})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        self.send_error(404)

    def _dc_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                return self.rfile.read(length).decode("utf-8")
        except Exception:
            pass
        return '{}'

    def _dc_post(self, path):
        data_dir = self.server.collector.data_dir
        dl = dc_downloader
        if path == "/api/dc/setup":
            # 首次设置口令；已设置后需带旧口令，用于修改口令
            try:
                data = json.loads(self._dc_body())
                nt = str(data.get('token') or '').strip()
                if len(nt) < 8:
                    return self._send_json({"ok": False, "error": "访问口令至少需要 8 位"})
                cur = dc_read_token(data_dir)
                if cur and not self._dc_authed():
                    return self._dc_deny()
                dc_write_token(data_dir, nt)
                return self._send_json({"ok": True})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        if not self._dc_authed():
            return self._dc_deny()
        if path == "/api/dc/config":
            try:
                data = json.loads(self._dc_body())
                speed = dc_num(data.get('speed_mbps'), 0)
                daily = dc_num(data.get('daily_gb'), 0)
                if not (0 <= speed <= 99999) or not (0 <= daily <= 9999999):
                    raise ValueError('数值超出允许范围（0=不限）')
                if speed > 0 and daily > 0:
                    # 理论最大日消耗 = 限速 × 86400 秒；留 5% 余量（TCP 开销/源站波动）
                    daily_max = int(speed * 86400 / 1024 * 0.95)
                    if daily > daily_max:
                        need_speed = int(daily * 1024 / (86400 * 0.95)) + 1
                        raise ValueError('按限速 %d MB/s 连续下载 24 小时最多约 %d GB，目标 %d GB 当天无法完成：请把每日目标调低到 %d GB 以内，或把下行限速提高到 %d MB/s 以上（目标填 0 可不限量）' % (speed, daily_max, daily, daily_max, need_speed))
                mode = 'none'  # 下载方式固定为不落盘
                cm = data.get('check_minutes')
                if cm is None:
                    cm = dc_read_cfg(data_dir)['check_minutes']  # 兼容旧前端：不传则保留原值
                else:
                    try:
                        cm = int(cm)
                    except Exception:
                        raise ValueError('达成后复查间隔需填 0~1440 分钟（0=达成后彻底暂停等明天）')
                    if not (0 <= cm <= 1440):
                        raise ValueError('达成后复查间隔需填 0~1440 分钟（0=达成后彻底暂停等明天）')
                with open(dc_paths(data_dir)["config"], 'w', encoding='utf-8') as f:
                    f.write('SPEED_MBPS=%d\nDAILY_GB=%d\nCHECK_MINUTES=%d\nDOWNLOAD_MODE=%s\n' % (speed, daily, cm, mode))
                dc_log(data_dir, '配置已更新：限速 %d MB/s（0=不限速），每日目标 %d GB（0=不限流量），达成后每 %d 分钟复查（0=达成后暂停等明天），下载方式不落盘' % (speed, daily, cm))
                return self._send_json({"ok": True})
            except Exception as e:
                return self._send_json({"ok": False, "error": '参数不合法：%s' % e})
        if path == "/api/dc/urls":
            try:
                data = json.loads(self._dc_body())
                raw = data.get('urls', '')
                if isinstance(raw, list):
                    raw = '\n'.join(str(x) for x in raw)
                with open(dc_paths(data_dir)["urls"], 'w', encoding='utf-8') as f:
                    f.write(str(raw))
                count = len([x for x in str(raw).splitlines() if x.strip() and not x.strip().startswith('#')])
                dc_log(data_dir, '下载源已更新（%d 条有效链接）' % count)
                return self._send_json({"ok": True})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        if path == "/api/dc/action":
            try:
                data = json.loads(self._dc_body())
                act = data.get('action')
                if act == 'start':
                    started = dl.start_loop()
                    return self._send_json({"ok": True, "started": started})
                elif act == 'stop':
                    dl.stop_loop()
                    return self._send_json({"ok": True})
                else:
                    return self._send_json({"ok": False, "error": '未知操作'})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        self.send_error(404)


# ---------------------------------------------------------------------------
# 下行带宽消耗器（原 downstream-consumer 并入，PCDN 业务子模块）
# 数据全部存放在 <data-dir>/dc/ 下，API 前缀 /api/dc/*，访问口令保护
# ---------------------------------------------------------------------------

DC_DEFAULT_URLS = [
    # Ubuntu 24.04.5.1 desktop ISO（约 6.5GB）—— 5 个镜像站
    'https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.5.1-desktop-amd64.iso',
    'https://mirrors.ustc.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.5.1-desktop-amd64.iso',
    'https://mirrors.huaweicloud.com/ubuntu-releases/24.04/ubuntu-24.04.5.1-desktop-amd64.iso',
    'https://mirror.sjtu.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.5.1-desktop-amd64.iso',
    'https://mirror.nju.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.5.1-desktop-amd64.iso',
    # Debian 13.7.0 DVD-1（约 4GB）—— 3 个镜像站
    'https://mirrors.tuna.tsinghua.edu.cn/debian-cd/current/amd64/iso-dvd/debian-13.7.0-amd64-DVD-1.iso',
    'https://mirror.sjtu.edu.cn/debian-cd/current/amd64/iso-dvd/debian-13.7.0-amd64-DVD-1.iso',
    'https://mirror.nju.edu.cn/debian-cd/current/amd64/iso-dvd/debian-13.7.0-amd64-DVD-1.iso',
    # openSUSE Tumbleweed DVD（约 5GB）
    'https://mirrors.tuna.tsinghua.edu.cn/opensuse/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso',
    # Arch Linux 最新 ISO（约 1.6GB）—— 4 个镜像站
    'https://mirrors.tuna.tsinghua.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso',
    'https://mirrors.ustc.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso',
    'https://mirrors.huaweicloud.com/archlinux/iso/latest/archlinux-x86_64.iso',
    'https://mirror.sjtu.edu.cn/archlinux/iso/latest/archlinux-x86_64.iso',
    # OVH 官方测速文件（专为反复下载设计，最安全）
    'https://proof.ovh.net/files/10Gb.dat',
    'https://proof.ovh.net/files/1Gb.dat',
    'https://proof.ovh.net/files/100Mb.dat',
    # Hetzner / Tele2 官方测速文件
    'https://speed.hetzner.de/1GB.bin',
    'https://speed.hetzner.de/100MB.bin',
    'https://speedtest.tele2.net/1GB.zip',
    'https://speedtest.tele2.net/100MB.zip',
]

# 测速文件源（设计给反复下载，长期使用不会被限速）
DC_SPEED_URLS = [u for u in DC_DEFAULT_URLS
                 if 'proof.ovh.net' in u or 'speed.hetzner' in u or 'speedtest.tele2' in u]
# 系统镜像 ISO 源（镜像站有滥用防护，适合少量轮换，不宜长期盯同一个）
DC_MIRROR_URLS = [u for u in DC_DEFAULT_URLS if u not in DC_SPEED_URLS]

_dc_lock = threading.Lock()


def dc_paths(data_dir):
    d = os.path.join(data_dir, "dc")
    return {
        "dir": d,
        "config": os.path.join(d, "config.txt"),
        "urls": os.path.join(d, "urls.txt"),
        "runlog": os.path.join(d, "run.log"),
        "daystate": os.path.join(d, "day_state"),
        "dldir": os.path.join(d, "dl"),
        "token": os.path.join(d, "access_token"),
    }


def dc_log(data_dir, msg):
    try:
        with _dc_lock:
            with open(dc_paths(data_dir)["runlog"], "a", encoding="utf-8") as f:
                f.write('%s %s\n' % (datetime.datetime.now().strftime('%F %T'), msg))
    except Exception:
        pass


def dc_read_token(data_dir):
    try:
        t = open(dc_paths(data_dir)["token"], encoding="utf-8").read().strip()
        return t or None
    except Exception:
        return None


def dc_write_token(data_dir, t):
    with open(dc_paths(data_dir)["token"], "w", encoding="utf-8") as f:
        f.write(t)
    dc_log(data_dir, '访问口令已设置')


def dc_authorized(data_dir, headers):
    tok = dc_read_token(data_dir)
    if not tok:
        return False
    got = headers.get('X-Auth-Token') or ''
    if not got:
        return False
    return hmac.compare_digest(got.encode('utf-8'), tok.encode('utf-8'))


def dc_ensure_files(data_dir):
    p = dc_paths(data_dir)
    os.makedirs(p["dir"], exist_ok=True)
    os.makedirs(p["dldir"], exist_ok=True)
    if not os.path.exists(p["config"]):
        with open(p["config"], "w", encoding="utf-8") as f:
            f.write('SPEED_MBPS=100\nDAILY_GB=5000\nCHECK_MINUTES=5\nDOWNLOAD_MODE=none\n')
    if not os.path.exists(p["urls"]):
        with open(p["urls"], "w", encoding="utf-8") as f:
            f.write('\n'.join(DC_DEFAULT_URLS) + '\n')


def dc_num(v, default):
    s = str(v or '').strip()
    return default if not s.isdigit() else int(s)


def dc_read_cfg(data_dir):
    cfg = {'SPEED_MBPS': '100', 'DAILY_GB': '5000', 'CHECK_MINUTES': '5', 'DOWNLOAD_MODE': 'none'}
    try:
        with open(dc_paths(data_dir)["config"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    cfg[k.strip()] = v.strip()
    except Exception:
        pass
    mode = 'none'  # 下载方式固定为不落盘（数据直接丢弃、仅统计流量，不写盘不磨损硬盘）
    return {'speed': dc_num(cfg.get('SPEED_MBPS'), 100),
            'daily_gb': dc_num(cfg.get('DAILY_GB'), 5000),
            'check_minutes': dc_num(cfg.get('CHECK_MINUTES'), 5),
            'mode': mode}


def dc_read_urls(data_dir):
    """读取实际使用的下载源。

    - 用户手动编辑过 urls.txt（内容与内置默认池不一致）：原样使用用户的列表；
    - 仍是内置默认池（或为空）：按日期做种子自动轮换——
      每次取 2 个测速文件源 + 2 个镜像源，同一天内组合稳定、跨天自动更换。
    """
    urls = []
    try:
        with open(dc_paths(data_dir)["urls"], encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    urls.append(s)
    except Exception:
        pass
    if set(urls) != set(DC_DEFAULT_URLS):
        return urls
    # 纯默认池：按日期做种子，每天自动轮换（同一天内多次调用结果一致）
    rng = random.Random(datetime.date.today().isoformat())
    picked = list(rng.sample(DC_SPEED_URLS, min(2, len(DC_SPEED_URLS))))
    if DC_MIRROR_URLS:
        picked += list(rng.sample(DC_MIRROR_URLS, min(2, len(DC_MIRROR_URLS))))
    return picked


def dc_read_day_state(data_dir):
    try:
        with open(dc_paths(data_dir)["daystate"], encoding="utf-8") as f:
            parts = f.read().split()
            if len(parts) >= 2:
                return parts[0], int(parts[1])
    except Exception:
        pass
    return None, 0


def dc_write_day_state(data_dir, d, used):
    try:
        with open(dc_paths(data_dir)["daystate"], "w", encoding="utf-8") as f:
            f.write('%s %d\n' % (d, used))
    except Exception:
        pass


def dc_dir_bytes(path):
    total = 0
    try:
        for name in os.listdir(path):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                total += os.path.getsize(p)
    except Exception:
        pass
    return total


def dc_tail(path, n):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        return ''.join(lines[-n:])
    except Exception:
        return ''


class DCDownloader:
    """下行带宽消耗器下载循环管理器：每次启动新建线程，可反复开始/停止。"""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.stop_event = threading.Event()
        self.thread = None
        self.live_bytes = 0
        self.live_lock = threading.Lock()

    def _dldir(self):
        return dc_paths(self.data_dir)["dldir"]

    def start_loop(self):
        if self.is_alive():
            # 旧线程可能仍在收尾：最多等 5 秒让其退出，避免竞态
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                return False
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def stop_loop(self):
        self.stop_event.set()
        # 把已下载但尚未记账的部分计入当日（含不落盘模式的实时字节），并清掉残留
        try:
            batch = dc_dir_bytes(self._dldir())
            with self.live_lock:
                batch += self.live_bytes
                self.live_bytes = 0
            if batch:
                d = datetime.date.today().isoformat()
                pd, pu = dc_read_day_state(self.data_dir)
                if pd != d:
                    pu = 0
                dc_write_day_state(self.data_dir, d, pu + batch)
            for f in os.listdir(self._dldir()):
                try:
                    os.remove(os.path.join(self._dldir(), f))
                except Exception:
                    pass
        except Exception:
            pass

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def _dl_url(self, u, out_path, rate_bytes, mode, done_event):
        """单路下载线程：流式读取，每 256KB 立即计入 live_bytes（进度实时刷新），
        并按下个数据块的到达时间间隔硬限速，总速率严格不超过设定值。"""
        headers = {'User-Agent': 'curl/8.0.1'}
        for attempt in range(3):
            if self.stop_event.is_set() or done_event.is_set():
                return
            try:
                req = urllib.request.Request(u, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as r:
                    f = open(out_path, 'wb') if mode == 'disk' else None
                    try:
                        while not self.stop_event.is_set() and not done_event.is_set():
                            chunk = r.read(262144)
                            if not chunk:
                                break
                            if f is not None:
                                f.write(chunk)
                            if mode == 'none':
                                with self.live_lock:
                                    self.live_bytes += len(chunk)
                            if rate_bytes > 0:
                                time.sleep(len(chunk) / rate_bytes)
                    finally:
                        if f is not None:
                            f.close()
                return
            except Exception as e:
                if attempt == 2:
                    dc_log(self.data_dir, '下载失败 %s: %s' % (u, e))
                else:
                    time.sleep(2)

    def _run(self):
        dc_log(self.data_dir, '下载循环已启动')
        try:
            while not self.stop_event.is_set():
                d = datetime.date.today().isoformat()
                pd, pu = dc_read_day_state(self.data_dir)
                if pd != d:
                    pu = 0
                cfg = dc_read_cfg(self.data_dir)
                speed = cfg['speed']
                daily_gb = cfg['daily_gb']
                target = daily_gb * 1000000000
                # daily_gb=0 表示不限流量：跳过每日目标判断，持续下载
                if daily_gb > 0 and pu >= target:
                    cm = cfg['check_minutes']
                    if cm > 0:
                        dc_log(self.data_dir, '今日目标已达（%d GB），暂停下载（每 %d 分钟复查，改大目标即可继续）' % (daily_gb, cm))
                        if not self._sleep(cm * 60):
                            break
                    else:
                        # 0 = 达成后彻底暂停：不周期复查，轻量等待跨天自动恢复
                        dc_log(self.data_dir, '今日目标已达（%d GB），暂停下载等待明天（复查间隔=0，不复查，跨天自动恢复）' % daily_gb)
                        while not self.stop_event.is_set():
                            if datetime.date.today().isoformat() != d:
                                break
                            if not self._sleep(60):
                                break
                        if self.stop_event.is_set():
                            break
                    continue
                urls = dc_read_urls(self.data_dir)
                if not urls:
                    dc_log(self.data_dir, 'urls.txt 没有有效链接，等待 10 分钟后重试')
                    if not self._sleep(600):
                        break
                    continue

                for f in os.listdir(self._dldir()):
                    try:
                        os.remove(os.path.join(self._dldir(), f))
                    except Exception:
                        pass

                # 限速：所有下载源线程均分总限速额度，总速率严格不超过填写值（MB/s）
                n = max(1, len(urls))
                rate_bytes = int(speed * 1000000 // n) if speed > 0 else 0
                mode = cfg['mode']
                done_event = threading.Event()
                threads = []
                for i, u in enumerate(urls, 1):
                    out = os.path.join(self._dldir(), 'f%d.dat' % i)
                    t = threading.Thread(target=self._dl_url,
                                         args=(u, out, rate_bytes, mode, done_event), daemon=True)
                    t.start()
                    threads.append(t)
                # 轮内实时检查每日目标：累计达到即提前停止本轮下载，避免目标完成后继续超跑
                while any(t.is_alive() for t in threads):
                    if self.stop_event.is_set():
                        break
                    with self.live_lock:
                        cur = self.live_bytes if mode == 'none' else dc_dir_bytes(self._dldir())
                    if daily_gb > 0 and pu + cur >= target:
                        dc_log(self.data_dir, '今日目标已达（%d GB），提前结束本轮下载' % daily_gb)
                        done_event.set()
                        break
                    time.sleep(1)
                for t in threads:
                    t.join()

                if self.stop_event.is_set():
                    dc_log(self.data_dir, '收到停止指令，退出下载循环')
                    break

                if mode == 'none':
                    with self.live_lock:
                        batch = self.live_bytes
                        self.live_bytes = 0
                else:
                    batch = dc_dir_bytes(self._dldir())
                pu += batch
                dc_write_day_state(self.data_dir, d, pu)
                dc_log(self.data_dir, '本轮完成：+%d GB，今日累计 %d GB / %d GB'
                       % (batch // 1000000000, pu // 1000000000, daily_gb))
                if mode != 'none':
                    for f in os.listdir(self._dldir()):
                        try:
                            os.remove(os.path.join(self._dldir(), f))
                        except Exception:
                            pass
                if not self._sleep(5):
                    break
        finally:
            dc_log(self.data_dir, '下载循环已停止')

    def _sleep(self, sec):
        end = time.time() + sec
        while time.time() < end and not self.stop_event.is_set():
            time.sleep(0.5)
        return not self.stop_event.is_set()


def dc_status(data_dir, downloader):
    cfg = dc_read_cfg(data_dir)
    d, pu = dc_read_day_state(data_dir)
    today = datetime.date.today().isoformat()
    if d != today:
        pu = 0
    running = downloader.is_alive()
    if cfg['mode'] == 'disk':
        live = dc_dir_bytes(dc_paths(data_dir)["dldir"]) if running else 0
    else:
        with downloader.live_lock:
            live = downloader.live_bytes if running else 0
    return {
        'running': running,
        'today_gb': (pu + live) // 1000000000,
        'today_bytes': pu + live,
        'target_gb': cfg['daily_gb'],
        'speed_mbps': cfg['speed'],
        'mode': cfg['mode'],
        'date': today,
        'urls_count': len(dc_read_urls(data_dir)),
        'log': dc_tail(dc_paths(data_dir)["runlog"], 40),
    }


dc_downloader = None  # main() 中初始化


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8778)
    ap.add_argument("--host", default="::",
                    help="监听地址，默认 :: 同时监听 IPv4+IPv6 双栈；纯 IPv4 环境自动降级")
    ap.add_argument("--data-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    ap.add_argument("--interval", type=int, default=2, help="实时采样间隔秒")
    ap.add_argument("--history-interval", type=int, default=60, help="历史写库间隔秒")
    ap.add_argument("--retention-days", type=int, default=7)
    args = ap.parse_args()

    os.makedirs(args.data_dir, exist_ok=True)
    db = DB(os.path.join(args.data_dir, "netmon.db"))
    collector = Collector(db, data_dir=args.data_dir, interval=args.interval,
                          history_interval=args.history_interval,
                          retention_days=args.retention_days)
    t = threading.Thread(target=collector.run, daemon=True)
    t.start()

    # 下行带宽消耗器（PCDN 业务子模块）初始化
    dc_ensure_files(args.data_dir)
    global dc_downloader
    dc_downloader = DCDownloader(args.data_dir)
    dc_log(args.data_dir, '下行带宽消耗器就绪（随网络监控 Web 服务运行）')

    # 双栈监听：默认绑 ::（Linux 默认 v6only=0，同时接受 IPv4 和 IPv6）
    # 失败（无 IPv6 / 权限问题）自动降级到 0.0.0.0
    class DualStackServer(ThreadingHTTPServer):
        address_family = socket.AF_INET6
        allow_reuse_address = True

    httpd = None
    listen_desc = args.host
    if args.host == "::":
        try:
            httpd = DualStackServer(("::", args.port), Handler)
        except Exception as e:
            print("[netmon] IPv6 双栈监听失败 (%s)，降级到 IPv4 0.0.0.0" % e)
            httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
            listen_desc = "0.0.0.0"
    else:
        if ":" in args.host:
            httpd = DualStackServer((args.host, args.port), Handler)
        else:
            httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.collector = collector
    print("netmon %s listening on http://%s:%d  (data=%s)" %
          (VERSION, listen_desc, args.port, args.data_dir))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        collector.stop()
        print("\nstopped")


if __name__ == "__main__":
    main()
