# W5 Security Assurance Pipeline

## Mục đích

W5 là lớp tự kiểm chứng bổ sung cho State B. Nó không thay thế JWT, ACL,
ownership authorization, DTO hay `token_version`. Thay vào đó, W5 kiểm tra
những control này còn hoạt động ở runtime và tạo evidence đã sanitize để xác
định control được thực thi tại Gateway hay backend.

Mối liên kết được kiểm chứng là:

`finding -> State B control -> W4 assertion -> expected enforcement layer -> sanitized log evidence -> SHA-256`.

`security/security-assurance-policy.json` là policy version-control. File này
không chứa URL secret, password, JWT, response body hay database record.

## Thành phần

| Thành phần | Nơi chạy | Trách nhiệm |
| --- | --- | --- |
| `w5_security_assurance_kali.py` | Kali | Chạy lại bốn W4 re-test, tạo manifest chỉ có assertion/probe metadata. |
| `w5_security_assurance_collect_ubuntu.sh` | Ubuntu | Thu Kong/VAmPI log đã redact, kiểm tra runtime invariant, tạo checksum. |
| `w5_security_assurance_verify.py` | Kali hoặc Ubuntu | Ghép hai gói evidence, đánh giá policy và xuất JSON/HTML report. |

## Quy tắc kết luận

| Layer trong policy | Điều kiện evidence | Ý nghĩa |
| --- | --- | --- |
| `gateway` | Probe có trong Kong log, vắng VAmPI log | Gateway từ chối trước khi request tới backend. |
| `backend` | Probe có trong cả Kong và VAmPI log | Backend nhận request; assertion HTTP quyết định policy backend đã đúng hay sai. |
| `runtime` | Docker ports và Kong config active khớp invariant | Topology/plugin State B không bị drift. |

Thiếu log không được xem là PASS. Verifier trả `INCONCLUSIVE`; report tổng thể
chỉ là `PASS` khi không có `FAIL` hoặc `INCONCLUSIVE`.

## Chạy một phiên assurance

Trên Kali, sau khi pull repository mới:

```bash
cd ~/owasp-api-defense-lab
python3 scripts/w5_security_assurance_kali.py \
  --api http://192.168.42.130:8000
```

Runner hỏi ba giá trị qua terminal: mật khẩu attacker hiện tại, mật khẩu victim
hiện tại và một mật khẩu tạm khác mật khẩu attacker. Mật khẩu tạm chỉ dùng cho
W4 JWT replay; script W4 có recovery/restore. Nếu kết thúc bất thường và báo
`manual-restore-required`, không chạy thêm test; dùng mật khẩu tạm để khôi phục
theo evidence của script hoặc khôi phục SQLite backup trên Ubuntu.

Runner có cooldown mặc định 65 giây trước W4 JWT replay vì State B giới hạn
login theo IP. Có thể thay đổi khi cần:

```bash
python3 scripts/w5_security_assurance_kali.py \
  --api http://192.168.42.130:8000 \
  --cooldown-seconds 65
```

Kết quả Kali là `evidence/assurance/<run-id>/kali-manifest.json` kèm
`SHA256SUMS`. Chỉ khi kết
quả là `PENDING_UBUNTU_EVIDENCE` mới tiếp tục sang Ubuntu. Trạng thái này chưa
phải PASS cuối cùng: nó chỉ cho biết toàn bộ HTTP assertion phía Kali đã pass.

Trên Ubuntu, dùng chính xác `started_at_utc` và bốn probe prefix in ở Kali:

```bash
cd ~/owasp-api-defense-lab
bash scripts/w5_security_assurance_collect_ubuntu.sh \
  --since 'UTC_START_FROM_KALI_MANIFEST' \
  --probe 'W4_BOLA_PROBE' \
  --probe 'W4_JWT_FORGERY_PROBE' \
  --probe 'W4_JWT_REPLAY_PROBE' \
  --probe 'W4_EXPOSURE_PROBE'
```

Không dùng thời gian local thay cho `started_at_utc`; collector dùng timestamp
UTC để tránh nhầm timezone. Ubuntu tạo `.state-b/evidence/assurance/ubuntu-*/`
gồm log Kong/VAmPI đã sanitize, config Kong đã redact, runtime assertions và
`SHA256SUMS`.

Sao chép **cả thư mục Kali evidence** (không chỉ riêng `kali-manifest.json`) và
thư mục Ubuntu evidence về cùng một máy tin cậy. Sau đó chạy verifier:

```bash
python3 scripts/w5_security_assurance_verify.py \
  --kali-manifest /path/to/kali-manifest.json \
  --ubuntu-evidence /path/to/ubuntu-YYYYMMDD-HHMMSS
```

Verifier tạo `report.json`, `report.html` và checksum. HTML phù hợp để xem,
chụp evidence hoặc đưa vào phụ lục; JSON là dữ liệu máy đọc được để kiểm tra
lại. Các tệp evidence được `.gitignore` loại trừ khỏi repository.

## Ví dụ các lỗi được phát hiện

| Trạng thái | Điều kiện phát hiện | Hành động cần làm |
| --- | --- | --- |
| `FAIL: BOLA-BOOK-OWNERSHIP` | Assertion attacker/victim không pass hoặc probe không tới backend như thiết kế | Kiểm tra ownership query theo `book_title` và `user_id`. |
| `FAIL: JWT-FORGED-TOKEN-GATEWAY` | JWT giả mạo tới VAmPI hoặc HTTP assertion sai | Kiểm tra Kong JWT plugin, route protected và runtime credential. |
| `FAIL: JWT-REPLAY-REVOCATION` | Token cũ không bị từ chối | Kiểm tra update/compare `token_version`. |
| `FAIL: PROFILE-DTO-WHITELIST` | `/me` có field ngoài whitelist | Kiểm tra serializer/DTO và regression test. |
| `FAIL: VAMPI-NO-HOST-PORT` | `docker port vampi` có mapping | Gỡ port publish và kiểm tra lại topology. |
| `INCONCLUSIVE` | Thiếu Kong/VAmPI log hoặc checksum không hợp lệ | Không kết luận an toàn; thu lại evidence với đúng UTC/probe. |

## Phạm vi và an toàn

W5 chỉ dành cho lab được kiểm soát. Nó không tự sửa source, không reload Kong,
không tự sửa Docker và không dùng runtime secret. JWT giả được ký bằng dummy
secret local. Password chỉ được đọc qua terminal hoặc biến môi trường của tiến
trình con; manifest, report, log và checksum không lưu password/JWT/body.

Rate limiting là `local` trong lab một node. W5 phát hiện control có active,
nhưng không phải benchmark cho nhiều Kong node hoặc Redis/cluster policy.
