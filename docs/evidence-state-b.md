# Evidence State B

Tài liệu này quy định cách lưu bằng chứng chạy thật của State B. Mục tiêu là
chứng minh từng control ở Kong và VAmPI mà không đưa secret, JWT, mật khẩu,
database hay ảnh chụp vào Git.

## Nguyên tắc lưu trữ

Toàn bộ runtime evidence nằm dưới `evidence/state-b/` (Kali) hoặc
`.state-b/evidence/` (Ubuntu). Hai thư mục đã bị `.gitignore` loại trừ. Chỉ
script, tài liệu hướng dẫn và mã nguồn được version-control.

Không lưu hoặc commit các dữ liệu sau:

- `.env.state-b`, `kong.runtime.yml`, SQLite database, mật khẩu, JWT;
- request body đăng nhập/đổi password hoặc response body có dữ liệu cá nhân;
- ảnh chụp terminal. Ảnh chỉ dùng trong khóa luận, lưu local.

`scripts/w3_wrap_03_collect_ubuntu_evidence.sh` redaction mọi dòng `secret:`
và Authorization Bearer trước khi ghi file. `scripts/w3_wrap_03_collect_kali_evidence.py`
chỉ allow-list kết quả assertion của regression test.

## Cấu trúc sau khi thu thập

```text
evidence/state-b/w3-wrap-03/
  kali-<UTC>/
    request-response-assertions.json
    README.txt
    SHA256SUMS

.state-b/evidence/w3-wrap-03/
  ubuntu-<UTC>/
    kong-active-sanitized.yml
    runtime-summary.txt
    kong-access.log
    vampi.log
    probe-routing-summary.txt
    SHA256SUMS
```

`request-response-assertions.json` là bằng chứng request/response ở mức an
toàn: endpoint, HTTP expected/actual và PASS/FAIL; nó không chứa body/JWT.
Các ảnh chụp kết quả có thể lưu cạnh thư mục này để chèn khóa luận nhưng không
được commit.

## Quy trình W3-WRAP-03

### 1. Chạy regression từ Kali

Tại clone trên Kali, chạy W3-BACKEND-05 rồi đóng gói manifest:

```bash
cd ~/owasp-api-defense-lab
python3 scripts/w3_backend_05_regression.py --api http://192.168.42.130:8000
python3 scripts/w3_wrap_03_collect_kali_evidence.py
```

Nhập mật khẩu hiện hành khi script hỏi. Output của collector cho ba giá trị cần
ghi lại: `Probe prefix`, `Source start time` và thư mục `kali-<UTC>`.

### 2. Lấy config và log từ Ubuntu

Ngay trước khi chạy regression, trên Ubuntu ghi mốc thời gian:

```bash
date -u --iso-8601=seconds
```

Sau khi Kali regression PASS, thay hai giá trị bên dưới bằng mốc vừa ghi và
`Probe prefix` do Kali in ra:

```bash
cd ~/owasp-api-defense-lab/owasp-api-defense-lab
bash scripts/w3_wrap_03_collect_ubuntu_evidence.sh \
  --since '2026-11-18T04:00:00Z' \
  --probe 'w3backend05-20261118-040010'
```

Collector chỉ đọc container đang chạy; không restart, không thay đổi database
và không thay đổi Kong/VAmPI. Nó tạo checksum để bảo toàn tính toàn vẹn.

## Cách chứng minh tầng nào chặn request

| Kịch bản | Bằng chứng cần đối chiếu | Kết luận đúng |
|---|---|---|
| Không JWT, chữ ký JWT sai hoặc JWT hết hạn (W3-KONG-03) | Probe có trong `kong-access.log`, vắng trong `vampi.log`, HTTP `401` | Kong chặn trước backend. |
| BOLA book của victim (W3-BACKEND-01/05) | Probe có trong **cả hai** log, assertion `404` | Request qua Kong và bị backend từ chối ownership. |
| Attacker gọi user directory/profile victim (W3-BACKEND-02/05) | Probe có trong cả hai log, assertion `403` | Backend áp dụng Access Control Matrix/DB authorization. |
| Token cũ sau đổi password (W3-BACKEND-04/05) | Probe có trong cả hai log, assertion `401` | Kong xác minh chữ ký; backend từ chối `token_version` cũ. |
| Login vượt quota (W3-KONG-05) | Probe có trong log Kong, vắng VAmPI, HTTP `429` | Rate limiting của Kong chặn trước backend. |

Không được suy luận tầng chặn chỉ từ mã HTTP. Luôn đối chiếu cả probe, hai log
và assertion tương ứng.

## Kiểm tra trước khi trích dẫn vào khóa luận

```bash
# Ubuntu
cd ~/owasp-api-defense-lab/owasp-api-defense-lab
find .state-b/evidence/w3-wrap-03 -type f -name SHA256SUMS -execdir sha256sum -c SHA256SUMS \;

# Kali
cd ~/owasp-api-defense-lab
find evidence/state-b/w3-wrap-03 -type f -name SHA256SUMS -execdir sha256sum -c SHA256SUMS \;
```

Sau khi checksum PASS, chụp ảnh phần output assertion và hai phần log đã lọc
theo probe để làm hình minh họa. Không chụp/đưa vào báo cáo bất kỳ secret,
password hoặc JWT nào.
