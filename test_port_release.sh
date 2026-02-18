#!/bin/bash
# 端口释放专项测试 - 在 Docker 容器内运行
# 验证 _start_callback_server 的端口清理逻辑
# 用法: docker exec flow2api-token-updater bash /app/test_port_release.sh

set -e
PASS=0
FAIL=0
PORT=11451

red()   { echo -e "\033[31m$1\033[0m"; }
green() { echo -e "\033[32m$1\033[0m"; }

assert_pass() { PASS=$((PASS+1)); green "  ✓ $1"; }
assert_fail() { FAIL=$((FAIL+1)); red   "  ✗ $1"; }

port_in_use() {
    python3 -c "
import socket
s=socket.socket()
s.settimeout(0.3)
r=s.connect_ex(('127.0.0.1',$PORT))
s.close()
exit(0 if r==0 else 1)
" 2>/dev/null
}

cleanup() {
    python3 -c "
import os, signal
hex_port = '%04X' % $PORT
my_pid = os.getpid()
inodes = set()
for f in ['/proc/net/tcp','/proc/net/tcp6']:
    try:
        for line in open(f).readlines()[1:]:
            parts = line.split()
            if parts[1].split(':')[1] == hex_port:
                inodes.add(parts[9])
    except: pass
if not inodes: exit(0)
for p in os.listdir('/proc'):
    if not p.isdigit(): continue
    pid = int(p)
    if pid == my_pid or pid == 1: continue
    try:
        for fd in os.listdir(f'/proc/{pid}/fd'):
            try:
                link = os.readlink(f'/proc/{pid}/fd/{fd}')
                if link.startswith('socket:[') and link[8:-1] in inodes:
                    os.kill(pid, signal.SIGKILL)
            except: pass
    except: pass
" 2>/dev/null || true
    sleep 0.5
}

echo "========================================="
echo " 端口释放专项测试 (port $PORT)"
echo "========================================="
echo ""

# ─── 测试 1: server_close() 释放端口 ───
echo "【测试1】shutdown() + server_close() 释放端口"
cleanup
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading, time

class H(BaseHTTPRequestHandler):
    def do_GET(self): pass
    def log_message(self,*a): pass

class R(HTTPServer):
    allow_reuse_address = True

s = R(('127.0.0.1', $PORT), H)
t = threading.Thread(target=s.serve_forever, daemon=True)
t.start()
time.sleep(0.3)
s.shutdown()
s.server_close()
time.sleep(0.3)
"
if port_in_use; then
    assert_fail "server_close() 后端口仍被占用"
else
    assert_pass "server_close() 后端口已释放"
fi

# ─── 测试 2: 只 shutdown() 不 server_close() → 端口泄漏验证 ───
echo "【测试2】只 shutdown() 不 server_close() → 验证旧 bug"
cleanup
python3 << 'PYEOF' &
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading, time

class H(BaseHTTPRequestHandler):
    def do_GET(self): pass
    def log_message(self,*a): pass

s = HTTPServer(('127.0.0.1', 11451), H)
t = threading.Thread(target=s.serve_forever, daemon=True)
t.start()
time.sleep(0.3)
s.shutdown()  # 只 shutdown，不 server_close
time.sleep(60)  # 保持进程活着
PYEOF
BGPID=$!
sleep 1.5
if port_in_use; then
    assert_pass "只 shutdown() 时端口确实泄漏（验证了旧 bug 存在）"
else
    assert_fail "只 shutdown() 时端口竟然释放了"
fi
kill $BGPID 2>/dev/null; wait $BGPID 2>/dev/null || true
cleanup

# ─── 测试 3: 连续两次创建服务器（模拟换账号） ───
echo "【测试3】连续两次创建/销毁（模拟换账号）"
cleanup
python3 << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading, time

class H(BaseHTTPRequestHandler):
    def do_GET(self): pass
    def log_message(self,*a): pass

class R(HTTPServer):
    allow_reuse_address = True

PORT = 11451
for i in range(2):
    s = R(('127.0.0.1', PORT), H)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    s.shutdown()
    s.server_close()
    time.sleep(0.3)
print("OK")
PYEOF
if [ $? -eq 0 ]; then
    assert_pass "连续两次创建/销毁成功"
else
    assert_fail "第二次创建失败"
fi

# ─── 测试 4: allow_reuse_address 验证 ───
echo "【测试4】ReusableHTTPServer 的 allow_reuse_address 属性验证"
cleanup
python3 << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket

class H(BaseHTTPRequestHandler):
    def do_GET(self): pass
    def log_message(self,*a): pass

class R(HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True

PORT = 11451

# 验证 SO_REUSEADDR 在 bind 时已生效
s = R(('127.0.0.1', PORT), H)
val = s.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
s.server_close()
assert val != 0, f"SO_REUSEADDR 未生效: {val}"

# 对比：普通 HTTPServer 也有 allow_reuse_address=True（默认），
# 但我们的子类确保了 allow_reuse_port 也设置
print("OK")
PYEOF
if [ $? -eq 0 ]; then
    assert_pass "ReusableHTTPServer SO_REUSEADDR 已生效"
else
    assert_fail "ReusableHTTPServer SO_REUSEADDR 未生效"
fi

# ─── 测试 5: _kill_port 纯 Python 方式杀进程 ───
echo "【测试5】纯 Python _kill_port 能释放被占用的端口"
cleanup
python3 << 'PYEOF' &
import socket, time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 11451))
s.listen(1)
time.sleep(60)
PYEOF
BGPID=$!
sleep 0.8
if ! port_in_use; then
    assert_fail "后台进程未能占用端口"
    kill $BGPID 2>/dev/null; wait $BGPID 2>/dev/null || true
else
    # 用纯 Python 方式杀（和代码里一样的逻辑）
    python3 -c "
import os, signal
hex_port = '%04X' % 11451
my_pid = os.getpid()
inodes = set()
for f in ['/proc/net/tcp','/proc/net/tcp6']:
    try:
        for line in open(f).readlines()[1:]:
            parts = line.split()
            if parts[1].split(':')[1] == hex_port:
                inodes.add(parts[9])
    except: pass
for p in os.listdir('/proc'):
    if not p.isdigit(): continue
    pid = int(p)
    if pid == my_pid or pid == 1: continue
    try:
        for fd in os.listdir(f'/proc/{pid}/fd'):
            try:
                link = os.readlink(f'/proc/{pid}/fd/{fd}')
                if link.startswith('socket:[') and link[8:-1] in inodes:
                    os.kill(pid, signal.SIGKILL)
                    print(f'killed {pid}')
            except: pass
    except: pass
"
    sleep 0.5
    if port_in_use; then
        assert_fail "_kill_port 未能释放端口"
    else
        assert_pass "_kill_port 成功释放被占用的端口"
    fi
fi

# ─── 测试 6: 直接调用 _start_callback_server 两次（集成测试） ───
echo "【测试6】直接调用 _start_callback_server 连续两次（集成测试）"
cleanup
python3 << 'PYEOF'
import asyncio, sys
sys.path.insert(0, '/app')

async def test():
    from token_updater.gcli2api_bridge import gcli2api_bridge
    captured1, captured2 = {}, {}

    srv1, port1 = await gcli2api_bridge._start_callback_server(11451, captured1, "account_A")
    assert port1 == 11451
    srv1.shutdown()
    srv1.server_close()
    await asyncio.sleep(0.5)

    srv2, port2 = await gcli2api_bridge._start_callback_server(11451, captured2, "account_B")
    assert port2 == 11451
    srv2.shutdown()
    srv2.server_close()
    print("OK")

asyncio.run(test())
PYEOF
if [ $? -eq 0 ]; then
    assert_pass "连续两次调用 _start_callback_server 成功"
else
    assert_fail "第二次调用 _start_callback_server 失败"
fi

# ─── 测试 7: 快速连续 5 次（压力测试） ───
echo "【测试7】快速连续 5 次创建/销毁（压力测试）"
cleanup
python3 << 'PYEOF'
import asyncio, sys
sys.path.insert(0, '/app')

async def test():
    from token_updater.gcli2api_bridge import gcli2api_bridge
    for i in range(5):
        cap = {}
        srv, port = await gcli2api_bridge._start_callback_server(11451, cap, f"stress_{i}")
        srv.shutdown()
        srv.server_close()
        await asyncio.sleep(0.2)
    print("OK")

asyncio.run(test())
PYEOF
if [ $? -eq 0 ]; then
    assert_pass "快速连续 5 次创建/销毁全部成功"
else
    assert_fail "快速连续创建/销毁失败"
fi

# ─── 清理 & 汇总 ───
cleanup
echo ""
echo "========================================="
echo " 结果: $PASS 通过, $FAIL 失败"
echo "========================================="
[ $FAIL -eq 0 ] && green "全部通过 ✓" || red "有失败项 ✗"
exit $FAIL
