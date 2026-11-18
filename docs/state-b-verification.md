# W3-WRAP-01 — Tiêu chí xác nhận State B

State B không chỉ là các file cấu hình có trong repository. Kết luận chỉ hợp lệ
khi container đang chạy đồng thời thỏa điều kiện topology, gateway và backend
dưới đây.

| Lớp | Tiêu chí | Cách W3-WRAP-01 xác minh |
| --- | --- | --- |
| Topology | Kali chỉ đi vào Kong; VAmPI không publish host port; Kong và VAmPI cùng `lab-net` | Docker inspect/port và probe localhost trên Ubuntu |
| Kong | Cấu hình active parse được; route protected có JWT, ACL, rate-limiting | `kong config parse` và đọc tên plugin, không in secret |
| Backend | Ownership query, DB-backed authorization, DTO whitelist, retired path handling và token version đang ở image chạy thật | Kiểm tra marker source trong container và schema SQLite |
| Chức năng hợp lệ | Victim đọc object của mình; login/đổi password và token mới vẫn hoạt động | Regression W3-BACKEND-05 từ Kali |

## Chạy xác minh runtime

Trên Ubuntu, từ root repository đã pull commit mới:

```bash
bash scripts/w3_wrap_01_state_b_verify.sh
```

Script lưu evidence đã sanitize tại `.state-b/evidence/w3-wrap-01-<timestamp>.txt`.
File này không được Git theo dõi. Script không in `VAMPI_JWT_SECRET`, JWT hoặc
nội dung SQLite; chỉ in trạng thái PASS/FAIL và các tên plugin.

## Điều kiện kết luận

Chỉ đánh dấu W3-WRAP-01 hoàn thành khi script trả `SUMMARY: PASS` và evidence
W3-BACKEND-05 trên Kali cũng trả `W3-BACKEND-05: PASS`. Đây là hai góc nhìn bổ
sung: Ubuntu xác nhận cấu hình/ứng dụng đang chạy, còn Kali xác nhận client bên
ngoài đi qua Kong vẫn dùng được chức năng hợp lệ và bị chặn đúng policy.
