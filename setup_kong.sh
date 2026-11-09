#!/bin/bash
set -e

echo "=================================================="
echo "    BẮT ĐẦU THIẾT LẬP KONG GATEWAY 3.9.1 (STATE A)"
echo "=================================================="

echo "[1/5] Kiểm tra container VAmPI..."
if [ ! "$(docker ps -q -f name=vampi)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=vampi)" ]; then
        echo "-> Khởi động lại container vampi..."
        docker start vampi
    else
        echo "-> [CẢNH BÁO] Container vampi chưa tồn tại. Đang khởi chạy vampi..."
        docker run -d --name vampi -p 5000:5000 -e vulnerable=1 vampi:latest
    fi
fi
echo "✓ VAmPI đang hoạt động tốt."

echo "[2/5] Kéo Docker image kong:3.9.1..."
docker pull kong:3.9.1

echo "[3/5] Thiết lập mạng Docker nội bộ lab-net..."
docker network inspect lab-net >/dev/null 2>&1 || docker network create lab-net
docker network connect lab-net vampi 2>/dev/null || true
echo "✓ Mạng lab-net đã kết nối với vampi."

echo "[4/5] Khởi tạo cấu hình và chạy Kong Gateway..."
# Dọn dẹp container kong cũ nếu có
docker rm -f kong-gateway 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KONG_CONF="$SCRIPT_DIR/kong/kong.yml"

if [ ! -f "$KONG_CONF" ]; then
    mkdir -p "$SCRIPT_DIR/kong"
    cat << 'EOF' > "$KONG_CONF"
_format_version: "3.0"
services:
  - name: vampi-service
    url: http://vampi:5000
    routes:
      - name: vampi-route
        paths:
          - /
        strip_path: false
EOF
fi

docker run -d --name kong-gateway \
  --network lab-net \
  -p 8000:8000 \
  -p 8001:8001 \
  -e "KONG_DATABASE=off" \
  -e "KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml" \
  -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
  -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
  -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
  -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
  -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
  -v "$KONG_CONF:/etc/kong/kong.yml:ro" \
  kong:3.9.1

echo "Đang chờ Kong Gateway khởi động trong 3 giây..."
sleep 3

echo "[5/5] Kiểm tra hoạt động..."
docker ps --filter "name=kong-gateway"
echo ""
echo "-> Kết quả gọi API qua Kong Gateway (cổng 8000):"
curl -s http://localhost:8000/
echo ""
echo ""
echo "=================================================="
echo "✓ HOÀN THÀNH: Kong Gateway đã đứng trước VAmPI!"
echo "=================================================="

