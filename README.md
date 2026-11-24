# OWASP API Defense Lab

Lab thực hành phòng thủ API, dùng **VAmPI** làm ứng dụng mục tiêu và **Kong Gateway 3.9.1** làm API gateway ở chế độ DB-less. Dự án tái hiện, khắc phục và kiểm chứng lại ba nhóm rủi ro trong OWASP API Security Top 10:

- **BOLA** (Broken Object Level Authorization);
- **Broken Authentication** qua JWT yếu/giả mạo và token replay;
- **Excessive Data Exposure**.

> Chỉ chạy trong môi trường lab do bạn kiểm soát. Không dùng các script hay kỹ thuật trong repository này với hệ thống không có ủy quyền.

## Kiến trúc

```text
Kali (test/re-test) ---> Kong :8000 ---> VAmPI :5000
                              |              |
                    JWT / ACL / rate limit   ownership / ACL / DTO /
                                               token_version
```

Ở **State B**, chỉ Kong proxy cổng `8000` được publish ra host. Cổng VAmPI `5000` và Kong Admin API `8001` không được publish; VAmPI và Kong giao tiếp qua Docker network `lab-net`.

## Phạm vi State B

| Finding | Kiểm soát gateway | Kiểm soát backend |
| --- | --- | --- |
| JWT giả mạo | JWT plugin, xác minh `iss` và `exp` | Xác minh chữ ký, issuer, subject và token version |
| Brute force / lạm dụng | Rate limiting theo IP | — |
| BOLA | ACL coarse-grained cho consumer đã xác thực | Ownership check ngay trong query; policy theo role |
| Lộ dữ liệu quá mức | — | DTO/serializer whitelist; gỡ `/_debug` và `/createdb` |
| Replay sau đổi mật khẩu | — | Tăng và kiểm tra `token_version` |

ACL của Kong chỉ là lớp lọc coarse-grained; nó **không thay thế** authorization theo ownership, RBAC hoặc quyền admin trong backend. Rate limit `local` hiện phù hợp cho một Kong node trong lab; khi mở rộng nhiều node cần Redis/cluster policy.

## Yêu cầu

- Ubuntu Server hoặc máy Linux có Bash, Docker Engine và Docker CLI;
- Docker permission cho tài khoản chạy deployment;
- Python 3 cho các script regression/re-test;
- Kali (hoặc máy kiểm thử được phép) có thể gọi `http://<SERVER_IP>:8000`.

Image Kong được ghim tại `kong:3.9.1`. Dự án cần một VAmPI database đã có sẵn bộ dữ liệu kiểm thử (ví dụ `victim` và `attacker`) trước khi chuyển sang State B; deployment cố ý từ chối tạo database rỗng.

## Cấu trúc repository

```text
VAmPI/                         Ứng dụng Flask mục tiêu
kong/kong.yml                  Template cấu hình Kong State B (không có secret thật)
kong/kong.state-a.yml          Cấu hình baseline State A
deploy_state_b.sh              Triển khai State B bảo toàn database hiện có
scripts/                       Regression, re-test, collection và verification
security/security-assurance-policy.json
                                Policy cho pipeline W5
docs/plan.md                   Kế hoạch thực hiện
docs/spec.md                   Phạm vi và acceptance criteria
docs/task.md                   Checklist theo tuần
docs/security-assurance-pipeline.md
                                Hướng dẫn chi tiết pipeline W5
lab/backend-patches/           Patch backend và checksum SHA-256
evidence/                      Evidence cục bộ (bị Git ignore)
```

## Triển khai State B

Thực hiện trên Ubuntu Server, từ thư mục gốc repository. Không commit `.env.state-b`, `.state-b/`, `kong/kong.runtime.yml` hoặc nội dung `evidence/`.

1. Chuẩn bị secret runtime:

   ```bash
   cp .env.state-b.example .env.state-b
   secret=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
   sed -i "s|REPLACE_WITH_A_64_CHARACTER_BASE64URL_SECRET|$secret|" .env.state-b
   chmod 600 .env.state-b
   ```

   Secret phải là Base64URL, dài tối thiểu 43 ký tự. Có thể điều chỉnh issuer và TTL trong file này; mặc định là `vampi-state-b` và `900` giây.

2. Bảo đảm container `vampi` hiện có đang chứa database baseline cần giữ. Script sẽ backup database vào `.state-b/backups/` trước khi thay container.

3. Triển khai:

   ```bash
   bash deploy_state_b.sh --replace-vampi
   ```

   Script sẽ render cấu hình Kong runtime với secret, validate cấu hình DB-less, build image `vampi:state-b`, rồi khởi động `vampi` và `kong-gateway` trên `lab-net`.

4. Kiểm tra topology:

   ```bash
   docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
   docker port vampi
   docker port kong-gateway
   curl -i http://127.0.0.1:8000/
   ```

   `docker port vampi` phải không có mapping; Kong chỉ được public proxy `8000`.

## Regression và re-test

Các script chạy qua Kong, không gọi thẳng VAmPI. Chạy từ máy kiểm thử, thay `SERVER_IP` bằng địa chỉ Ubuntu Server.

```bash
# Regression State B: yêu cầu password qua prompt (hoặc biến môi trường phù hợp).
python3 scripts/w3_backend_05_regression.py \
  --api http://SERVER_IP:8000

# Re-test từng finding.
python3 scripts/w4_retest_bola.py --api http://SERVER_IP:8000
python3 scripts/w4_retest_jwt_forgery.py --api http://SERVER_IP:8000
python3 scripts/w4_retest_jwt_replay.py --api http://SERVER_IP:8000
python3 scripts/w4_retest_exposure.py --api http://SERVER_IP:8000
```

Dùng `--help` trên từng script để xem username, title book và thư mục evidence có thể cấu hình. Các script có `--non-interactive` sẽ yêu cầu password được cấp qua biến môi trường thay vì prompt. JWT replay test đổi mật khẩu tạm thời rồi khôi phục; nếu nó báo `manual-restore-required`, hãy dừng các lần test tiếp theo và thực hiện khôi phục theo evidence/script trước khi tiếp tục.

## Security assurance pipeline (W5)

W5 ghép HTTP assertions từ Kali với log đã sanitize từ Ubuntu để xác định control được thực thi tại gateway hay backend. Evidence thiếu log được xem là `INCONCLUSIVE`, không phải PASS.

```bash
# 1. Kali: chạy assertions và tạo manifest.
python3 scripts/w5_security_assurance_kali.py \
  --api http://SERVER_IP:8000 \
  --cooldown-seconds 65

# 2. Ubuntu: dùng chính xác started_at_utc và 4 probe prefix in ra bởi bước 1.
bash scripts/w5_security_assurance_collect_ubuntu.sh \
  --since 'UTC_START_FROM_KALI_MANIFEST' \
  --probe 'W4_BOLA_PROBE' \
  --probe 'W4_JWT_FORGERY_PROBE' \
  --probe 'W4_JWT_REPLAY_PROBE' \
  --probe 'W4_EXPOSURE_PROBE'

# 3. Máy tin cậy: xác minh hai gói evidence đã sao chép cùng nhau.
python3 scripts/w5_security_assurance_verify.py \
  --kali-manifest /path/to/kali-manifest.json \
  --ubuntu-evidence /path/to/ubuntu-evidence-dir
```

Verifier xuất `report.json`, `report.html` và checksum. Xem [docs/security-assurance-pipeline.md](docs/security-assurance-pipeline.md) để biết đầy đủ quy tắc PASS/FAIL/INCONCLUSIVE.

## Kiểm tra patch backend

Các patch State B được lưu để review và áp dụng lại, kèm checksum:

```bash
cd lab/backend-patches
sha256sum -c SHA256SUMS
cd ../..
git apply --check lab/backend-patches/01-bola-ownership.patch
```

Xem [lab/backend-patches/README.md](lab/backend-patches/README.md) trước khi dùng `git am`; không áp dụng patch trực tiếp vào nhánh đang có thay đổi chưa commit.

## Tài liệu

- [Đặc tả và tiêu chí chấp nhận](docs/spec.md)
- [Kế hoạch triển khai](docs/plan.md)
- [Checklist công việc](docs/task.md)
- [Pipeline security assurance W5](docs/security-assurance-pipeline.md)
- [VAmPI upstream/readme](VAmPI/README.md)

## An toàn dữ liệu

- Tạo secret mới cho mỗi môi trường; không đưa secret, password, JWT hoặc database vào Git.
- Evidence runtime, config Kong đã render và thư mục `.state-b/` đã được ignore bởi Git.
- Chỉ sao chép evidence đã sanitize giữa các máy; kiểm tra checksum trước khi kết luận.
- Việc thay container VAmPI có thể ảnh hưởng dữ liệu lab. Review backup do `deploy_state_b.sh` tạo trước khi tiếp tục.
