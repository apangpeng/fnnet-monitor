# -*- coding: utf-8 -*-
"""合并版 server.py 冒烟测试：验证 netmon 与下行带宽消耗器 API。"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8899"
TOKEN = "testtoken123"
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smoke-data")

passed = []
failed = []


def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print("[PASS] %s %s" % (name, detail))
    else:
        failed.append(name)
        print("[FAIL] %s %s" % (name, detail))


def req(method, path, body=None, token=None, expect401=False):
    url = BASE + path
    headers = {}
    if token:
        headers["X-Auth-Token"] = token
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if expect401 and e.code == 401:
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            except Exception:
                return e.code, {}
        return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def main():
    server_script = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Administrator\Downloads\new-chat-4\new-chat-4\netmon-merged\app\server.py"
    if os.path.isdir(DATA):
        shutil.rmtree(DATA, ignore_errors=True)
    server = subprocess.Popen(
        [sys.executable, server_script,
         "--port", "8899", "--host", "127.0.0.1", "--data-dir", DATA,
         "--interval", "1", "--history-interval", "3600", "--retention-days", "1"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # 等待服务就绪
        ready = False
        for _ in range(40):
            st, j = req("GET", "/api/info")
            if st == 200 and "version" in j:
                ready = True
                break
            time.sleep(0.5)
        check("server up", ready)
        if not ready:
            print("---- server output ----")
            print(server.stdout.read(2000))
            return 1

        check("version", st == 200 and j.get("version") == "1.3.32", str(j.get("version")))

        # DC: 未设口令 → setup 流程
        st, j = req("GET", "/api/dc/status")
        check("dc status setup flag", st == 200 and j.get("setup") is True and j.get("auth") is False, str(j))

        # DC: 设置口令
        st, j = req("POST", "/api/dc/setup", {"token": TOKEN})
        check("dc setup token", st == 200 and j.get("ok") is True, str(j))

        # DC: 无口令 → 401
        st, j = req("GET", "/api/dc/status", expect401=True)
        check("dc status 401 without token", st == 401 and j.get("auth") is False, str(j))

        # DC: 带口令 status
        st, j = req("GET", "/api/dc/status", token=TOKEN)
        check("dc status authed",
              st == 200 and j.get("auth") is True and j.get("target_gb") == 5000
              and j.get("speed_mbps") == 100 and j.get("mode") == "none",
              "today=%s target=%s speed=%s" % (j.get("today_gb"), j.get("target_gb"), j.get("speed_mbps")))

        # DC: 修改配置
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 5, "daily_gb": 10, "download_mode": "none"}, token=TOKEN)
        check("dc config save", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/config", token=TOKEN)
        check("dc config read", st == 200 and j.get("speed_mbps") == 5 and j.get("daily_gb") == 10
              and j.get("check_minutes") == 5, str(j))

        # DC: 达成后复查间隔自定义（30 分钟）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 5, "daily_gb": 10, "check_minutes": 30}, token=TOKEN)
        check("dc config check save", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/config", token=TOKEN)
        check("dc config check read", st == 200 and j.get("check_minutes") == 30, str(j))

        # DC: 复查间隔填 0 = 达成后彻底暂停（合法）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 5, "daily_gb": 10, "check_minutes": 0}, token=TOKEN)
        check("dc config check zero ok", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/config", token=TOKEN)
        check("dc config check zero read", st == 200 and j.get("check_minutes") == 0, str(j))

        # DC: 复查间隔超上限被拒绝
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 5, "daily_gb": 10, "check_minutes": 2000}, token=TOKEN)
        check("dc config reject check", st == 200 and j.get("ok") is False, str(j))

        # DC: 填 0 = 不限速 / 不限流量（合法）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 0, "daily_gb": 0}, token=TOKEN)
        check("dc config zero ok", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/config", token=TOKEN)
        check("dc config zero read", st == 200 and j.get("speed_mbps") == 0 and j.get("daily_gb") == 0, str(j))

        # DC: 非法参数被拒绝（超上限）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 100000, "daily_gb": 10}, token=TOKEN)
        check("dc config reject bad", st == 200 and j.get("ok") is False, str(j))

        # DC: 目标当天不可达被拒绝（10 MB/s × 24h ≈ 843 GB < 1000 GB）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 10, "daily_gb": 1000}, token=TOKEN)
        check("dc config reject unreachable target", st == 200 and j.get("ok") is False and "无法完成" in j.get("error", ""), str(j))

        # DC: 可达组合被接受（10 MB/s × 24h 足够 800 GB）
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 10, "daily_gb": 800}, token=TOKEN)
        check("dc config accept reachable target", st == 200 and j.get("ok") is True, str(j))

        # DC: 恢复低速配置，避免后续启停测试以不限速真实拉满带宽
        st, j = req("POST", "/api/dc/config", {"speed_mbps": 5, "daily_gb": 10}, token=TOKEN)
        check("dc config restore", st == 200 and j.get("ok") is True, str(j))

        # DC: urls 默认列表
        st, j = req("GET", "/api/dc/urls", token=TOKEN)
        check("dc urls default", st == 200 and j.get("ok") is True and len(j.get("urls", "").splitlines()) == 20, str(len(j.get("urls", "").splitlines())))

        # DC: 更新 urls
        st, j = req("POST", "/api/dc/urls", {"urls": "# test\nhttps://proof.ovh.net/files/1Gb.dat"}, token=TOKEN)
        check("dc urls update", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/urls", token=TOKEN)
        check("dc urls updated", st == 200 and "1Gb.dat" in j.get("urls", ""), str(j))

        # DC: 启停（立即停止，不做真实下载）
        st, j = req("POST", "/api/dc/action", {"action": "start"}, token=TOKEN)
        check("dc action start", st == 200 and j.get("ok") is True, str(j))
        st, j = req("POST", "/api/dc/action", {"action": "stop"}, token=TOKEN)
        check("dc action stop", st == 200 and j.get("ok") is True, str(j))
        # 停止是异步的：轮询等待下载线程退出（最多 20 秒）
        stopped = False
        for _ in range(40):
            st, j = req("GET", "/api/dc/status", token=TOKEN)
            if st == 200 and j.get("running") is False:
                stopped = True
                break
            time.sleep(0.5)
        check("dc status after stop", stopped, str(j.get("running")))

        # 修改口令需旧口令
        st, j = req("POST", "/api/dc/setup", {"token": "newtoken4567"})
        check("dc change token without old denied", st == 401, str(st))
        st, j = req("POST", "/api/dc/setup", {"token": "newtoken4567"}, token=TOKEN)
        check("dc change token with old ok", st == 200 and j.get("ok") is True, str(j))
        st, j = req("GET", "/api/dc/status", token="newtoken4567")
        check("dc new token works", st == 200 and j.get("auth") is True, str(j))

        # 主监控 API
        st, j = req("GET", "/api/net")
        check("api net", st == 200 and isinstance(j.get("ifaces"), list), str(st))
        st, j = req("GET", "/api/traffic")
        check("api traffic", st == 200 and "today" in j and "pcdn" in j, str(st))
        st, j = req("GET", "/api/history?range=1h")
        check("api history", st == 200 and "rx" in j, str(st))
        st, j = req("GET", "/api/ports")
        check("api ports", st == 200, str(st))
        # 端口条目带用途分组与说明
        pl = j.get("listeners") or []
        check("ports have group/desc",
              len(pl) == 0 or all(("group" in p and "desc" in p) for p in pl),
              "listeners=%d" % len(pl))
        # 连接流量排行（v1.3.16+）：结构存在，非 Linux 下 available=False 且 top/udp 为列表
        st, j = req("GET", "/api/conn_top")
        check("api conn_top", st == 200 and "available" in j and "top" in j and "udp" in j
              and isinstance(j.get("top"), list) and isinstance(j.get("udp"), list), str(st))
        check("conn_top structure", j.get("available") is False and j.get("top") == [] and j.get("udp") == []
              and "debug" in j and "ss_rc" in (j.get("debug") or {}),
              "available=%s top=%d udp=%d debug=%s" % (
                  j.get("available"), len(j.get("top", [])), len(j.get("udp", [])),
                  json.dumps(j.get("debug", {}), ensure_ascii=False)[:80]))
        # index: 直接读字节确认新面板存在
        import urllib.request as u2
        try:
            html = u2.urlopen(BASE + "/", timeout=10).read().decode("utf-8")
            check("index has dc panel", "下行带宽消耗器" in html and "dc-auth-overlay" in html and "PCDN" in html)
            check("index has conn top", "连接流量排行" in html and "conn-top-list" in html)
        except Exception as e:
            check("index read", False, str(e))

        # 双栈监听降级日志路径不报错
        print("---- summary ----")
        print("passed=%d failed=%d" % (len(passed), len(failed)))
        if failed:
            return 1
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except Exception:
            server.kill()
        if os.path.isdir(DATA):
            shutil.rmtree(DATA, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
