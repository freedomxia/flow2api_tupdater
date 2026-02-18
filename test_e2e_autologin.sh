#!/bin/bash
# 端到端测试：Google 自动登录字段 (google_email / google_password / totp_secret)
# 在 Docker 环境中通过 API 验证完整 CRUD + 脱敏链路
set +e

TUPDATER_URL="${TUPDATER_URL:-http://127.0.0.1:8002}"
PASSWORD="${ADMIN_PASSWORD:-x232448644}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $name"
        pass=$((pass + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $name"
        fail=$((fail + 1))
    fi
}

echo "=========================================="
echo "  端到端测试: Google 自动登录字段"
echo "=========================================="
echo ""

# --- 1. 服务可达 ---
echo -e "${YELLOW}[1/6] 检查服务可达性${NC}"
status=$(curl -s -o /dev/null -w "%{http_code}" "$TUPDATER_URL/" 2>/dev/null)
check "token updater 可访问" "$([ "$status" = "200" ] && echo true || echo false)"

# --- 2. 登录 ---
echo ""
echo -e "${YELLOW}[2/6] 登录${NC}"
login_resp=$(curl -s "$TUPDATER_URL/api/login" -X POST -H "Content-Type: application/json" -d "{\"password\":\"$PASSWORD\"}" 2>/dev/null)
token=$(echo "$login_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
check "登录成功" "$([ -n "$token" ] && echo true || echo false)"

AUTH="Authorization: Bearer $token"

# --- 3. 创建含 Google 字段的 Profile ---
echo ""
echo -e "${YELLOW}[3/6] 创建含 Google 自动登录字段的 Profile${NC}"
create_resp=$(curl -s "$TUPDATER_URL/api/profiles" -X POST \
    -H "Content-Type: application/json" -H "$AUTH" \
    -d '{
        "name": "e2e_autologin_test",
        "remark": "自动登录测试",
        "google_email": "testuser@gmail.com",
        "google_password": "supersecret123",
        "totp_secret": "JBSWY3DPEHPK3PXP"
    }' 2>/dev/null)
pid=$(echo "$create_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('profile_id',''))" 2>/dev/null)
check "创建 Profile 成功 (id=$pid)" "$([ -n "$pid" ] && echo true || echo false)"

# --- 4. 读取并验证脱敏 ---
echo ""
echo -e "${YELLOW}[4/6] 验证字段脱敏${NC}"
get_resp=$(curl -s "$TUPDATER_URL/api/profiles/$pid" -H "$AUTH" 2>/dev/null)

# 邮箱应保留
email=$(echo "$get_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('google_email',''))" 2>/dev/null)
check "google_email 保留明文" "$([ "$email" = "testuser@gmail.com" ] && echo true || echo false)"

# 密码不应返回
has_pwd_field=$(echo "$get_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('google_password' in d)" 2>/dev/null)
check "google_password 已移除" "$([ "$has_pwd_field" = "False" ] && echo true || echo false)"

has_pwd=$(echo "$get_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('has_google_password',False))" 2>/dev/null)
check "has_google_password = True" "$([ "$has_pwd" = "True" ] && echo true || echo false)"

# TOTP 不应返回
has_totp_field=$(echo "$get_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('totp_secret' in d)" 2>/dev/null)
check "totp_secret 已移除" "$([ "$has_totp_field" = "False" ] && echo true || echo false)"

has_totp=$(echo "$get_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('has_totp_secret',False))" 2>/dev/null)
check "has_totp_secret = True" "$([ "$has_totp" = "True" ] && echo true || echo false)"

# --- 5. 更新字段 ---
echo ""
echo -e "${YELLOW}[5/6] 更新 Google 邮箱${NC}"
update_resp=$(curl -s "$TUPDATER_URL/api/profiles/$pid" -X PUT \
    -H "Content-Type: application/json" -H "$AUTH" \
    -d '{"google_email": "updated@gmail.com"}' 2>/dev/null)
update_ok=$(echo "$update_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null)
check "更新邮箱成功" "$([ "$update_ok" = "True" ] && echo true || echo false)"

# 验证更新后的值
get2_resp=$(curl -s "$TUPDATER_URL/api/profiles/$pid" -H "$AUTH" 2>/dev/null)
email2=$(echo "$get2_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('google_email',''))" 2>/dev/null)
check "邮箱已更新" "$([ "$email2" = "updated@gmail.com" ] && echo true || echo false)"

# 密码未被清除
has_pwd2=$(echo "$get2_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('has_google_password',False))" 2>/dev/null)
check "密码未被清除" "$([ "$has_pwd2" = "True" ] && echo true || echo false)"

# 列表接口也脱敏
echo ""
list_resp=$(curl -s "$TUPDATER_URL/api/profiles" -H "$AUTH" 2>/dev/null)
list_has_pwd=$(echo "$list_resp" | python3 -c "
import sys,json
ps=json.load(sys.stdin)
p=next((x for x in ps if x['id']==$pid), {})
print('google_password' not in p and p.get('has_google_password',False))
" 2>/dev/null)
check "列表接口脱敏正确" "$([ "$list_has_pwd" = "True" ] && echo true || echo false)"

# --- 6. 清理 ---
echo ""
echo -e "${YELLOW}[6/6] 清理${NC}"
del_resp=$(curl -s "$TUPDATER_URL/api/profiles/$pid" -X DELETE -H "$AUTH" 2>/dev/null)
echo "已清理测试 Profile"

# --- 结果 ---
echo ""
echo "=========================================="
total=$((pass + fail))
echo -e "  结果: ${GREEN}$pass 通过${NC} / ${RED}$fail 失败${NC} / $total 总计"
echo "=========================================="

[ "$fail" -gt 0 ] && exit 1 || exit 0
