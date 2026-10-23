# -*- coding: utf-8 -*-
"""用标准 tar.gz 复现 fnpack 的 FPK 打包。

结构：fpk = tar.gz { manifest, app.tgz, cmd/, config/, wizard/, ui/, ICON.PNG, ICON_256.PNG }
      app.tgz = tar.gz { app/ 载荷（tar 内无 app/ 前缀）}
"""
import io
import os
import tarfile

ROOT = r"C:\Users\Administrator\Downloads\new-chat-4\new-chat-4\netmon-merged"
OUT = r"C:\Users\Administrator\Downloads\new-chat-4\new-chat-4\网络监控-1.3.31-内置下行带宽消耗器.fpk"


def add_tree(tf, src_dir, arc_prefix=""):
    for name in sorted(os.listdir(src_dir)):
        p = os.path.join(src_dir, name)
        arc = os.path.join(arc_prefix, name) if arc_prefix else name
        if os.path.isdir(p):
            add_tree(tf, p, arc)
        else:
            tf.add(p, arcname=arc)


# 1) app.tgz：app/ 载荷
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as at:
    add_tree(at, os.path.join(ROOT, "app"))
app_tgz = buf.getvalue()

# 2) fpk：顶层
with tarfile.open(OUT, "w:gz") as fpk:
    info = tarfile.TarInfo("app.tgz")
    info.size = len(app_tgz)
    fpk.addfile(info, io.BytesIO(app_tgz))
    for name in ("manifest", "cmd", "config", "wizard", "ICON.PNG", "ICON_256.PNG"):
        p = os.path.join(ROOT, name)
        if os.path.isdir(p):
            add_tree(fpk, p, name)
        elif os.path.isfile(p):
            fpk.add(p, arcname=name)

print("OK %s (%d bytes)" % (OUT, os.path.getsize(OUT)))
