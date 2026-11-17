# Access Control Matrix State B

## Nguyên tắc thực thi

Kong xác thực JWT và áp dụng ACL theo Consumer ở biên. Kong không biết quan hệ
giữa một user và từng bản ghi VAmPI, vì vậy backend phải xác minh subject của
JWT, tải user từ database và quyết định quyền cho từng request. Không dùng
claim `role` do client gửi để cấp quyền admin; chỉ dùng `users.admin` trong
database.

`401` biểu thị token thiếu, sai, hết hạn hoặc subject không còn tương ứng với
một user. `403` biểu thị token hợp lệ nhưng user không có quyền theo policy.

| Route và action | Anonymous | Authenticated user | Admin được xác minh từ DB | Điều kiện backend |
| --- | --- | --- | --- | --- |
| `POST /users/v1/register` | Allow | Allow | Allow | Chỉ tạo standard user; body không được đặt `admin`. |
| `POST /users/v1/login` | Allow | Allow | Allow | Xác thực username/password; issuance JWT. |
| `GET /me` | Deny | Allow | Allow | Chỉ trả profile của subject hiện hành. |
| `GET /users/v1/{username}` | Deny | Allow nếu `username == subject` | Allow | Admin lookup basic profile; user thường chỉ self. |
| `PUT /users/v1/{username}/email` | Deny | Allow nếu `username == subject` | Allow nếu self | Không có cross-user update qua endpoint này. |
| `PUT /users/v1/{username}/password` | Deny | Allow nếu `username == subject` | Allow nếu self | Không có cross-user password reset; token invalidation ở W3-BACKEND-04. |
| `DELETE /users/v1/{username}` | Deny | Deny | Allow, trừ self-delete | Role lấy từ database; bảo toàn ít nhất admin đang đăng nhập. |
| `GET /users/v1` | Deny | Deny | Allow | Danh sách tài khoản chỉ phục vụ quản trị; DTO whitelist chỉ trả `username`. |
| `GET /users/v1/_debug` | Disabled | Disabled | Disabled | Route bị gỡ hoàn toàn; không có API trả password hoặc field debug. |
| `GET /createdb` | Disabled | Disabled | Disabled | Destructive reset bị gỡ khỏi HTTP API; chỉ seed qua vận hành nội bộ. |
| `GET /books/v1` | Deny | Allow | Allow | Chỉ liệt kê book của subject hiện hành. |
| `POST /books/v1` | Deny | Allow | Allow | `user_id` lấy từ subject hiện hành, không từ request body. |
| `GET /books/v1/{book_title}` | Deny | Allow nếu owner | Allow nếu owner | `book_title` và `user_id` nằm cùng truy vấn; không có admin bypass tại endpoint trả secret. |

## Phạm vi và kiểm thử

Matrix này áp dụng các decision ở backend cho mọi route nhạy cảm hiện có. Các
route public chỉ là register/login. Route debug và database reset đã bị gỡ khỏi
HTTP API. DTO whitelist trả profile chỉ với `username`, `email`, và directory
quản trị chỉ với `username`; không tuần tự hóa password, hash, token, secret,
hay cờ `admin` cho client. Kiểm thử regression của matrix, DTO/field filtering
và token lifecycle được thực hiện lần lượt trong W3-BACKEND-03,
W3-BACKEND-04 và W3-BACKEND-05.
