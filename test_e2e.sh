#!/bin/bash
# 端到端测试：token updater <-> gcli2api 插件连接
# 测试完整链路：服务可达 -> 登录 -> 插件配置 -> 凭证推送 -> 容器内连通
set +e

GCLI2API_URL="http://127.0.0.1:7861"
TUPDATER_URL="http://127.0.0.1:8002"
PASSWORD="x232448644"
PLUGIN_TOKEN="e2e_test_token_$(date +%s)"

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
echo "  端到端测试: token updater <-> gcli2api"
echo "=========================================="
echo ""

# --- 1. 服务可达性 ---
echo -e "${YELLOW}[1/7] 检查服务可达性${NC}"

gcli_status=$(curl -s -o /dev/null -w "%{http_code}" "$GCLI2API_URL/" 2>/dev/null)
check "gcli2api 可访问 ($GCLI2API_URL)" "$([ "$gcli_status" = "200" ] && echo true || echo false)"

tup_status=$(curl -s -o /dev/null -w "%{http_code}" "$TUPDATER_URL/" 2>/dev/null)
check "token updater 可访问 ($TUPDATER_URL)" "$([ "$tup_status" = "200" ] && echo true || echo false)"

# --- 2. gcli2api 登录 ---
echo ""
echo -e "${YELLOW}[2/7] gcli2api 登录${NC}"

login_resp=$(curl -s "$GCLI2API_URL/auth/login" -X POST -H "Content-Type: application/json" -d "{\"password\":\"$PASSWORD\"}" 2>/dev/null)
login_token=$(echo "$login_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
check "gcli2api 登录成功" "$([ -n "$login_token" ] && echo true || echo false)"

# --- 3. token updater 登录 ---
echo ""
echo -e "${YELLOW}[3/7] token updater 登录${NC}"

tup_login=$(curl -s "$TUPDATER_URL/api/login" -X POST -H "Content-Type: application/json" -d "{\"password\":\"$PASSWORD\"}" 2>/dev/null)
tup_token=$(echo "$tup_login" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
check "token updater 登录成功" "$([ -n "$tup_token" ] && echo true || echo false)"

# --- 4. 设置插件 token ---
echo ""
echo -e "${YELLOW}[4/7] 设置 gcli2api 插件连接 token${NC}"

save_resp=$(curl -s "$GCLI2API_URL/config/save" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $login_token" \
    -d "{\"config\":{\"plugin_connection_token\":\"$PLUGIN_TOKEN\"}}" 2>/dev/null)
save_ok=$(echo "$save_resp" | python3 -c "import sys,json; print('true' if '成功' in json.load(sys.stdin).get('message','') else 'false')" 2>/dev/null)
check "插件 token 保存成功" "$save_ok"

plugin_status=$(curl -s "$GCLI2API_URL/api/plugin/status" 2>/dev/null)
plugin_enabled=$(echo "$plugin_status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled',False))" 2>/dev/null)
check "插件状态已启用" "$([ "$plugin_enabled" = "True" ] && echo true || echo false)"

# --- 5. 通过插件 API 推送凭证 ---
echo ""
echo -e "${YELLOW}[5/7] 通过插件 API 推送测试凭证${NC}"

push_resp=$(curl -s "$GCLI2API_URL/api/plugin/update-token" -X POST \
    -H "Content-Type: application/json" \
    -d "{
        \"token\": \"$PLUGIN_TOKEN\",
        \"credential\": {
            \"client_id\": \"e2e-test-client.apps.googleusercontent.com\",
            \"client_secret\": \"e2e-test-secret\",
            \"token\": \"ya29.e2e-test-access-token\",
            \"refresh_token\": \"1//e2e-test-refresh-token\",
            \"scopes\": [\"https://www.googleapis.com/auth/cloud-platform\"],
            \"token_uri\": \"https://oauth2.googleapis.com/token\",
            \"project_id\": \"e2e-test-project\",
            \"expiry\": \"2026-12-31T23:59:59Z\"
        },
        \"mode\": \"geminicli\",
        \"name\": \"e2e-test\"
    }" 2>/dev/null)
push_ok=$(echo "$push_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null)
push_filename=$(echo "$push_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('filename',''))" 2>/dev/null)
check "凭证推送成功 (file=$push_filename)" "$([ "$push_ok" = "True" ] && echo true || echo false)"

# --- 6. 验证凭证已存入 ---
echo ""
echo -e "${YELLOW}[6/7] 验证凭证已存入 gcli2api${NC}"

check_resp=$(curl -s "$GCLI2API_URL/api/plugin/check-tokens" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$PLUGIN_TOKEN\", \"mode\": \"geminicli\"}" 2>/dev/null)
token_count=$(echo "$check_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('tokens',[])))" 2>/dev/null)
check "check-tokens 返回凭证 (count=$token_count)" "$([ "$token_count" -gt 0 ] 2>/dev/null && echo true || echo false)"

has_e2e=$(echo "$check_resp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
found=any('e2e-test' in t.get('filename','') for t in d.get('tokens',[]))
print(found)" 2>/dev/null)
check "e2e-test 凭证存在于列表中" "$([ "$has_e2e" = "True" ] && echo true || echo false)"

# --- 7. 容器内部连通性 ---
echo ""
echo -e "${YELLOW}[7/7] 从 token updater 容器内部测试${NC}"

c_login=$(docker exec flow2api-token-updater curl -s http://host.docker.internal:7861/auth/login -X POST -H "Content-Type: application/json" -d "{\"password\":\"$PASSWORD\"}" 2>/dev/null)
c_token=$(echo "$c_login" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
check "容器内 -> gcli2api 登录" "$([ -n "$c_token" ] && echo true || echo false)"

c_push=$(docker exec flow2api-token-updater curl -s http://host.docker.internal:7861/api/plugin/update-token -X POST \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$PLUGIN_TOKEN\",\"credential\":{\"client_id\":\"container-e2e.apps.googleusercontent.com\",\"client_secret\":\"s\",\"refresh_token\":\"1//container-e2e\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"project_id\":\"container-e2e-proj\"},\"mode\":\"geminicli\"}" 2>/dev/null)
c_push_ok=$(echo "$c_push" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null)
check "容器内 -> gcli2api 插件推送" "$([ "$c_push_ok" = "True" ] && echo true || echo false)"

# gcli2api status API from token updater
c_status=$(docker exec flow2api-token-updater curl -s http://host.docker.internal:7861/api/plugin/status 2>/dev/null)
c_enabled=$(echo "$c_status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled',False))" 2>/dev/null)
check "容器内 -> gcli2api 插件状态查询" "$([ "$c_enabled" = "True" ] && echo true || echo false)"

# --- 清理 ---
echo ""
echo -e "${YELLOW}清理测试数据...${NC}"
curl -s "$GCLI2API_URL/credentials/delete" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $login_token" \
    -d "{\"filename\":\"$push_filename\",\"mode\":\"geminicli\"}" > /dev/null 2>&1
curl -s "$GCLI2API_URL/config/save" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $login_token" \
    -d "{\"config\":{\"plugin_connection_token\":\"\"}}" > /dev/null 2>&1
echo "已清理"

# --- 结果 ---
echo ""
echo "=========================================="
total=$((pass + fail))
echo -e "  结果: ${GREEN}$pass 通过${NC} / ${RED}$fail 失败${NC} / $total 总计"
echo "=========================================="

[ "$fail" -gt 0 ] && exit 1 || exit 0
