# Mapping W2 → W3 → W4

Tài liệu này tạo traceability từ phát hiện baseline (W2), control đã áp dụng ở
State B (W3), bằng chứng kiểm thử W3 và re-test cần thực hiện ở W4. Mỗi dòng
phân biệt rõ Kong (gateway) với VAmPI (backend); không coi HTTP status đơn lẻ
là bằng chứng về tầng đã chặn request.

## Quy ước đánh giá

- **Kong chặn trước backend:** probe có trong Kong access log nhưng không có
  trong VAmPI log.
- **Backend từ chối:** probe có trong cả hai log; kết luận dựa thêm vào HTTP
  status và assertion tương ứng.
- Chỉ dùng request qua `http://192.168.42.130:8000`. Không re-test trực tiếp
  VAmPI `:5000`, không dùng JWT/secret/mật khẩu thật trong ảnh hoặc Git.

## Bảng mapping chính

| W2 finding và bằng chứng baseline | Control State B (W3) | W3 test/evidence đã có | W4 re-test và tiêu chí PASS |
| --- | --- | --- | --- |
| **BOLA** — W2-BOLA-01→04: attacker thay object identifier thành object của victim và đọc được dữ liệu không thuộc quyền. | **Backend:** W3-BACKEND-01 ràng buộc `book_title` **và** `user_id` của subject trong cùng truy vấn; default-deny, không bypass admin cho endpoint trả secret. **Gateway:** chỉ đảm bảo JWT hợp lệ, không thay ownership check. | W3-BACKEND-05: victim đọc book của mình `200`; attacker đọc `VictimDiary` nhận `404`. W3-WRAP-03: probe `...-attacker-foreign-book` có ở Kong và VAmPI, VAmPI trả `404`. | **W4-RETEST-BOLA:** lặp request attacker→`VictimDiary`. PASS khi `404`, không có body object/secret; probe có trong cả hai log để khẳng định backend ownership từ chối. |
| **JWT bị giả mạo / khóa ký yếu** — W2-JWT-01a→d: trích token, brute-force secret offline, tạo token admin và gọi endpoint nhạy cảm. | **Gateway + backend:** W3-KONG-01 dùng secret runtime ngẫu nhiên tối thiểu 256-bit, không commit; backend pin `HS256`, xác minh signature/`iss`/`exp`/subject. W3-KONG-02/03 áp JWT plugin cho protected routes. W3-KONG-05 giới hạn login 5 request/phút/IP, giảm brute-force online. | W3-KONG-03: no-token, bad-signature, expired đều `401` và vắng VAmPI. W3-WRAP-03: `...-kong-no-token` và `...-kong-invalid-jwt` chỉ có trong Kong, đều `401`. | **W4-RETEST-JWT-A:** không dùng secret thật; gửi JWT malformed hoặc ký bằng secret giả tới `/me`. PASS khi `401`, response không lộ secret, probe chỉ có Kong log. Ghi rõ rate-limit không thay thế secret mạnh và không biến hashcat offline thành test cần chạy lại. |
| **JWT replay sau đổi password** — W2-JWT-02a→c: token hợp lệ trước đổi password vẫn có thể được replay cho đến khi hết hạn. | **Backend:** W3-BACKEND-04 thêm `token_version` vào JWT/SQLite; tăng version khi đổi password; mọi request protected so sánh claim với database. Kong vẫn chỉ xác minh chữ ký/expiry. | W3-BACKEND-05: old token `200` trước đổi password, password change `204`, old token `401`, token mới `200`, restore password `204`. W3-WRAP-03: `...-old-token-stale` có ở cả hai log với `401`. | **W4-RETEST-JWT-B:** login → giữ token cũ → đổi password → replay token cũ. PASS khi `401` ở cả Kong/VAmPI logs; login mới và token mới vẫn `200`. Khôi phục password sau test. |
| **Excessive Data Exposure** — W2-EXPOSURE-01→04: `/_debug` lộ password/email/admin; profile/directory trả field không cần thiết. | **Backend:** W3-BACKEND-02 DB-backed Access Control Matrix chặn directory/cross-user `403`; W3-BACKEND-03 dùng DTO whitelist cho `/me`, gỡ `/_debug` và `/createdb` khỏi code/OpenAPI. | W3-BACKEND-05: `/me` `200` và DTO whitelist PASS; `/users/v1/_debug`, `/createdb` đều `404`; directory/victim profile `403`. W3-WRAP-03 xác nhận các probe này tới backend và nhận đúng status. | **W4-RETEST-EXPOSURE:** so sánh field-by-field với JSON baseline W2. PASS khi `/me` chỉ có `username`,`email` theo DTO; `password`, hash, token, secret, `admin` không xuất hiện; `/_debug`/`createdb` `404`; directory/profile trái phép `403`. |

## Kế hoạch ghi kết quả W4

Mỗi re-test phải lưu một thư mục dưới `evidence/retest/<lohong>/` với:

1. request/response đã sanitize (không JWT, password hoặc body nhạy cảm);
2. HTTP expected/actual và assertion PASS/FAIL;
3. Kong log và VAmPI log lọc theo cùng một `probe`;
4. ảnh chụp local để đưa vào khóa luận, không commit vào Git;
5. ghi chú rõ control chặn tại Kong hay từ chối tại backend.

Khi một kết quả không đúng kỳ vọng, ghi nhận trung thực status, body đã
sanitize và tầng xử lý; không sửa baseline evidence để làm đẹp kết quả.

## Liên kết với báo cáo

Khi viết chương đánh giá, dùng bảng này làm khung: **lỗ hổng State A → nguyên
nhân → control State B → kết quả re-test → giới hạn**. Giới hạn quan trọng:
Kong ACL chỉ là kiểm soát coarse-grained theo Consumer; ownership, quyền admin
và `token_version` vẫn bắt buộc ở backend.
