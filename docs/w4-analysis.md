# Phân tích đối chiếu State A và State B

Tài liệu này tổng hợp các re-test W4 trên cùng topology lab. Baseline State A
được đối chiếu bằng evidence W2 lưu local; State B dùng manifest đã sanitize
trên Kali và Kong/VAmPI logs đã checksum trên Ubuntu. Không đưa JWT, password,
response body nhạy cảm hoặc ảnh vào Git.

## 1. Phương pháp và quy tắc diễn giải

- Cùng tập dữ liệu `attacker`, `victim`, `VictimDiary`; client chỉ gọi Kong
  `:8000` ở State B.
- `HTTP 401/403/404` chỉ là kết quả HTTP. Tầng thực thi được kết luận bằng
  probe: chỉ có Kong log nghĩa là gateway chặn; có cả Kong và VAmPI log nghĩa
  là request tới backend.
- File manifest Kali `w4-retest-manifest-20261118-051853.json` xác nhận bốn
  nhóm re-test PASS: BOLA 4 assertion, JWT-A 4, JWT-B 9, Exposure 6.

## 2. BOLA — W4-ANALYSIS-01

| Tiêu chí | State A / W2-BOLA | State B / W4-RETEST-BOLA | Kết luận |
| --- | --- | --- | --- |
| Request | Attacker thay object identifier thành book của victim. | Attacker gọi cùng target `GET /books/v1/VictimDiary`. | Giữ nguyên mục tiêu nghiệp vụ của PoC. |
| HTTP | `200` (theo evidence baseline W2). | `404`. | Không tiết lộ object tồn tại hay không thuộc owner. |
| Dữ liệu book/secret | Bị truy cập trái quyền. | Không xuất hiện trong response. | Rò rỉ dữ liệu đã bị loại bỏ. |
| Request hợp lệ victim | Có object owner hợp lệ. | Victim vẫn nhận `200`; owner xác nhận là `victim`. | Bản vá không làm hỏng chức năng hợp lệ. |
| Tầng xử lý | Không có ownership enforcement đầy đủ. | Probe `w4bola-20261118-045626-attacker-foreign` có ở Kong **và** VAmPI với `404`. | Backend thực thi ownership check, không phải Kong ACL. |

Control quyết định là truy vấn backend ràng buộc đồng thời `book_title` và
`user_id` của subject. Chọn `404` thay vì `403` cũng giảm khả năng enumeration
object title đối với user không phải owner.

## 3. Broken Authentication — W4-ANALYSIS-02

### 3.1 Forged-admin JWT

| Tiêu chí | State A / W2-JWT-01 | State B / W4-RETEST-JWT-A | Kết luận |
| --- | --- | --- | --- |
| Kịch bản | Baseline dùng secret yếu bị brute-force rồi ký token admin giả. | JWT có `admin=true` nhưng được ký bằng dummy secret local, không phải runtime secret. | Re-test không trích xuất/lộ secret hardened. |
| Kết quả | Token giả được backend chấp nhận trong baseline. | Forged token nhận `401`; thiếu token cũng `401`. | Kong JWT plugin từ chối token không có signature hợp lệ. |
| Tầng chặn | Chưa có gateway JWT enforcement. | Probe `w4jwtforge-20261118-050306-no-token` và `-forged-admin` có Kong log, vắng VAmPI log. | Kong chặn trước backend. |
| Chức năng hợp lệ | N/A | Login hợp lệ và `/me` hợp lệ đều `200`. | Control không chặn client hợp lệ. |

Không được suy luận rằng một thử nghiệm dummy-secret đo được "thời gian không
thể bẻ khóa". Nó chứng minh đường xử lý signature không hợp lệ. Khả năng chống
brute-force offline được cải thiện bởi secret runtime ngẫu nhiên tối thiểu
256-bit, không commit vào repo; số liệu thời gian hashcat baseline phải được
trích nguyên văn từ log W2 local khi viết khóa luận, không được bịa số.

### 3.2 Token replay sau đổi password

| Tiêu chí | State A / W2-JWT-02 | State B / W4-RETEST-JWT-B | Kết luận |
| --- | --- | --- | --- |
| Token cũ trước đổi password | Hợp lệ. | `200`. | Baseline để so sánh đúng. |
| Replay sau đổi password | Token cũ vẫn dùng được đến khi hết hạn. | `401`. | Token lifecycle State B thu hồi token cũ. |
| Token mới | N/A | Login lại/token mới `200`; final token sau restore `200`. | Không phá luồng hợp lệ. |
| Tầng thực thi | JWT stateless không có state revoke. | Probe `w4jwtreplay-20261118-050913-old-stale` có ở Kong và VAmPI với `401`. | Backend so sánh `token_version` với DB và từ chối replay. |

## 4. Excessive Data Exposure — W4-ANALYSIS-03

| Endpoint/field | State A / W2 | State B / W4 | Kết luận |
| --- | --- | --- | --- |
| `GET /users/v1/_debug` | Lộ `password`, `email`, `admin`. | `404`. | Route debug bị retire hoàn toàn. |
| `GET /createdb` | Bề mặt reset database không cần cho client. | `404`. | Operation destructive không còn qua HTTP. |
| `GET /me` | Có nguy cơ serialization field nội bộ. | `200`; fields chính xác `email`, `username`. | DTO whitelist thay vì serialize object user. |
| `GET /users/v1` bởi user thường | Có thể công khai directory. | `403`. | DB-backed Access Control Matrix chặn. |
| `GET /users/v1/victim` bởi attacker | Có nguy cơ lộ profile chéo user. | `403`. | Backend kiểm tra subject/role. |

Probe `w4exposure-20261118-051402` xuất hiện tại cả Kong và VAmPI với status
`200/403/403/404/404` tương ứng; hai log checksum PASS. Điều này xác nhận DTO,
retired routes và authorization là control backend, không phải chỉ gateway.

## 5. Giới hạn kỹ thuật — W4-ANALYSIS-04

1. Kong JWT/ACL là control biên và coarse-grained; không thể thay ownership,
   DB-backed role check hoặc `token_version` ở backend.
2. Rate limiting `policy: local` phù hợp lab một node; khi scale cần shared
   policy như Redis/cluster để quota nhất quán.
3. `iss` được thêm vì Kong dùng nó tra JWT credential; không phải role hay
   business authorization claim.
4. Secret mạnh làm brute-force offline không khả thi trong phạm vi lab, nhưng
   vẫn cần rotation, quyền file chặt và không log/commit secret.
5. Evidence log xác minh luồng xử lý trong lab; môi trường production cần log
   tập trung, retention, access control và giám sát chống sửa đổi.

## 6. Kết luận đánh giá

Ba kịch bản baseline đều bị ngăn đúng tầng ở State B: forged JWT bị Kong chặn
trước backend; BOLA, cross-user access, DTO và replay token được backend quyết
định theo object/user state. Các flow hợp lệ đã re-test `200`, do đó kết quả
không chỉ là block traffic mà còn bảo toàn chức năng nghiệp vụ hợp lệ.
