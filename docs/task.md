# TASK.md — Danh sách công việc chi tiết

> Dựa trên `plan.md` (trình tự) và `spec.md` (mục tiêu/tiêu chí chấp nhận). Đây là checklist thực thi — cập nhật trạng thái trực tiếp trong file này khi làm việc, để biết chính xác đang ở đâu và tránh làm trùng/xung đột công việc.

**Quy ước trạng thái:** `[ ]` chưa làm · `[~]` đang làm · `[x]` xong · `[!]` bị chặn/có vấn đề (ghi chú lý do ngay dưới dòng đó).

**Quy ước ID task:** `W<tuần>-<nhóm>-<số thứ tự>` (ví dụ `W1-INFRA-03`) để tham chiếu chéo trong báo cáo hoặc commit message (ví dụ: `git commit -m "W3-KONG-02: add jwt plugin"`).

---

## TUẦN 1 — Dựng hạ tầng Lab

### W1-INFRA — Hạ tầng ảo hóa & mạng

- [X] `W1-INFRA-01` Cài đặt VirtualBox/VMware Workstation trên máy host. (Đã cài VMware Workstation Pro 17.6.4)
- [X] `W1-INFRA-02` Tạo VM Kali Linux (máy tấn công) — cập nhật, cài Burp Suite Community + Postman nếu chưa có sẵn. (Kali 2026.3)
- [X] `W1-INFRA-03` Tạo VM Ubuntu Server (máy chủ dịch vụ) — cài Docker + Docker Compose. (Ubuntu 26.04.1, Docker 29.9.3)
- [X] `W1-INFRA-04` Thiết lập mạng giữa 2 VM (bridged/host-only network) — xác nhận Kali ping được tới Ubuntu Server.

### W1-VAMPI — Triển khai ứng dụng mục tiêu

- [X] `W1-VAMPI-01` Clone mã nguồn VAmPI từ GitHub vào Ubuntu Server.
- [X] `W1-VAMPI-02` Build & chạy VAmPI qua Docker; xác nhận container healthy.
- [X] `W1-VAMPI-03` Kiểm tra công tắc bật/tắt chế độ `vulnerable` — test cả 2 trạng thái, ghi chú cách bật/tắt (biến môi trường/endpoint) vào README.
- [X] `W1-VAMPI-04` Tạo bộ dữ liệu test cố định: 2 tài khoản `victim` và `attacker` (và `admin` nếu kịch bản JWT cần) — **dùng xuyên suốt dự án, không tạo lại sau này**.
- [X] `W1-VAMPI-05` Đặt VAmPI ở chế độ **vulnerable** (chuẩn bị cho baseline Tuần 2).

### W1-KONG — Khung Kong Gateway cơ bản

- [X] `W1-KONG-01` Pull image `kong:3.9.1` (ghim đúng version — **không dùng `latest`**).
- [X] `W1-KONG-02` Viết `kong.yml` tối thiểu (DB-less mode): 1 service trỏ tới VAmPI, 1 route — **chưa thêm plugin bảo mật nào**.
- [X] `W1-KONG-03` Chạy Kong container, xác nhận request từ Kali qua Kong tới VAmPI trả về đúng kết quả (so với gọi thẳng VAmPI).
- [X] `W1-KONG-04` Xác nhận quy trình reload cấu hình (`kong reload` hoặc restart container) hoạt động ổn định — tránh phát sinh ở Tuần 3.
- [X] `W1-KONG-05` Commit `kong.yml` ban đầu vào Git.

### W1-DOC — Tài liệu & kiến trúc

- [X] `W1-DOC-01` Vẽ sơ đồ kiến trúc hệ thống (Kali → Kong → VAmPI, kèm Docker network) — lưu vào `docs/architecture.md`.
- [X] `W1-DOC-02` Khởi tạo repo GitHub (README nháp, cấu trúc thư mục theo `plan.md` §4).

**Checkpoint cuối Tuần 1** *(xem `plan.md` §5)*: Lab chạy được, bộ dữ liệu test đã chốt, sơ đồ kiến trúc đã có.

---

## TUẦN 2 — Red Team: Tấn công giả lập (Baseline / State A)

### W2-BOLA — Broken Object Level Authorization

- [X] `W2-BOLA-01` Xác định endpoint mục tiêu có tham số object ID (ví dụ `/users/{id}` hoặc tương đương trong VAmPI).
- [X] `W2-BOLA-02` Đăng nhập bằng `attacker`, bắt request bằng Burp Suite Proxy.
- [X] `W2-BOLA-03` Sửa tham số ID thành ID của `victim`, gửi lại (Repeater), xác nhận truy cập được dữ liệu không thuộc quyền.
- [X] `W2-BOLA-04` Export request/response từ Burp (`.txt`/XML), chụp màn hình → lưu vào `evidence/baseline/bola/`.

### W2-JWT — Broken Authentication

- [X] `W2-JWT-01a` Trích xuất 1 JWT hợp lệ (của `victim` hoặc `attacker`) từ phiên đăng nhập.
- [X] `W2-JWT-01b` Dùng hashcat brute-force SECRET_KEY offline (ghi lại thời gian bẻ khóa — số liệu này sẽ dùng ở báo cáo).
- [X] `W2-JWT-01c` Dùng jwt.io (hoặc script) tạo token mới với payload `role=admin`, ký bằng SECRET_KEY vừa tìm được.
- [X] `W2-JWT-01d` Gửi request dùng token giả mạo tới 1 endpoint yêu cầu quyền admin — xác nhận được chấp nhận.
- [X] `W2-JWT-02a` Lấy & lưu lại token hiện tại của `victim`.
- [X] `W2-JWT-02b` Thực hiện đổi mật khẩu cho `victim` (qua API đổi mật khẩu của VAmPI).
- [X] `W2-JWT-02c` Replay lại token cũ đã lưu — kiểm tra còn dùng được không, ghi nhận kết quả (kể cả nếu VAmPI đã chặn — đây vẫn là dữ liệu hợp lệ).
- [X] `W2-JWT-03` Export toàn bộ log hashcat + request/response Burp cho cả (a) và (b) → lưu vào `evidence/baseline/jwt-auth/`.

### W2-EXPOSURE — Excessive Data Exposure

- [X] `W2-EXPOSURE-01` Liệt kê endpoint user/profile: `GET /users/v1`, `GET /users/v1/_debug`, `GET /users/v1/{username}` và `GET /me`.
- [X] `W2-EXPOSURE-02` Gọi các endpoint qua Kong port `8000` bằng curl trên Kali và lưu body JSON cùng response headers tại `~/w2-exposure/`.
- [X] `W2-EXPOSURE-03` Đối chiếu field response: `/_debug` lộ `password` dạng rõ, `email` và `admin`; các endpoint public còn lại cũng công khai email.
- [X] `W2-EXPOSURE-04` Lưu response JSON/header cục bộ tại `~/w2-exposure/`, chụp evidence và tạo báo cáo Word; file JWT tạm dùng cho `/me` đã được xóa.

### W2-WRAP — Tổng hợp Tuần 2

- [ ] `W2-WRAP-01` Kiểm tra lại đủ 3/3 kịch bản có bằng chứng đầy đủ (ảnh + log) theo tiêu chí `spec.md` §7.
- [ ] `W2-WRAP-02` Nếu có kịch bản thất bại/không rõ ràng → xem mục "Xử lý khi kịch bản không thành công" bên dưới, điều chỉnh **trước khi** sang Tuần 3.
- [ ] `W2-WRAP-03` Commit toàn bộ evidence baseline vào Git.

**Checkpoint cuối Tuần 2**: Cả 3 kịch bản tấn công thành công & có PoC đầy đủ.

---

## TUẦN 3 — Blue Team: Triển khai phòng thủ hai lớp (chuyển sang State B)

### W3-KONG — Lớp ngoài: Cấu hình plugin Kong

- [X] `W3-KONG-00` **Cô lập mạng trước tiên:** gỡ publish host port của VAmPI (không còn `5000:5000`); chỉ Kong proxy `:8000` được công khai và Kong Admin API `:8001` không được publish. Từ Kali, gọi thẳng VAmPI phải thất bại. *(Hoàn thành 2026-11-15; bằng chứng: `evidence/state-b/w3-kong-00/` và log runtime `.state-b/evidence/` trên Ubuntu.)*
- [X] `W3-KONG-01` Sửa issuance/validation JWT ở VAmPI: lấy `SECRET_KEY` ngẫu nhiên tối thiểu 256-bit từ biến môi trường, fail-closed khi thiếu secret; phát hành `iss`, `iat`, `exp`, `sub`; pin algorithm `HS256`; backend phải xác minh signature, algorithm, `iss`, `exp` và subject hợp lệ. Ghi rõ `iss` là tích hợp Kong, không phải logic nghiệp vụ. Chỉ thêm `aud` khi backend thực sự xác minh audience (không thêm claim chỉ để đủ trường). *(Hoàn thành 2026-11-15: secret runtime 64 ký tự, JWT claim test PASS, `/me` trả 200; bằng chứng local tại `evidence/state-b/w3-kong-01/`.)*
- [X] `W3-KONG-02` Tách route public (login/register) và protected; cấu hình Kong Consumer + JWT credential, rồi thêm plugin `jwt` **chỉ** vào protected route trong `kong.yml`. Dùng `iss` làm credential key; login/register phải vẫn hoạt động không cần Bearer token. *(Hoàn thành 2026-11-16: login public `200`; `/me` thiếu token `401`; `/me` với JWT hợp lệ `200`; bằng chứng local tại `evidence/state-b/w3-kong-02/`.)*
- [X] `W3-KONG-03` Test và lưu evidence gateway: valid JWT đi qua protected route; token thiếu, sai chữ ký hoặc hết hạn bị Kong chặn `401/403`; request bị chặn không xuất hiện trong access log VAmPI. Đồng thời xác nhận route public hoạt động. *(Hoàn thành 2026-11-16: valid `200`; thiếu token, sai chữ ký và hết hạn đều `401`; ba probe có trong Kong log và vắng mặt trong VAmPI log; bằng chứng local tại `evidence/state-b/w3-kong-03/`.)*
- [X] `W3-KONG-04` Thêm plugin `acl` theo nhóm coarse-grained tối thiểu `authenticated`. Ghi rõ trong tài liệu: ACL Kong chỉ lọc Consumer/group đã xác thực, **không** thay ownership check, RBAC hay quyền admin theo từng người dùng ở backend. *(Hoàn thành 2026-11-16: login public `200`; JWT ánh xạ Consumer group `authenticated` qua `/me` `200`; thiếu token `401`; bằng chứng local tại `evidence/state-b/w3-kong-04/`.)*
- [X] `W3-KONG-05` Thêm plugin `rate-limiting`: login/register theo IP; protected route theo IP trong lab một node (tránh một Consumer dùng chung tạo bucket chung cho mọi user). Chọn ngưỡng lab công khai trong `kong.yml`; chứng minh request vượt ngưỡng nhận `429`. Ghi chú `local` chỉ phù hợp một node, cần Redis/cluster khi scale. *(Hoàn thành 2026-11-16: login 5 lần `200`, lần 6 `429`; protected 60 lần `200`, lần 61 `429`; có `Retry-After` và rate-limit headers; bằng chứng local tại `evidence/state-b/w3-kong-05/`.)*
- [X] `W3-KONG-06` Test tổng hợp State B: chỉ Kong `:8000` truy cập được; direct port VAmPI thất bại; JWT/ACL/rate-limit hoạt động đúng; lưu access log Kong và log VAmPI có request/correlation ID để chỉ rõ tầng chặn. *(Hoàn thành 2026-11-16: direct `:5000` thất bại; login `200`; protected không token `401`; JWT+ACL `200`; header rate-limit `60`; Kong/VAmPI logs xác nhận đúng tầng chặn; bằng chứng local tại `evidence/state-b/w3-kong-06/`.)*
- [X] `W3-KONG-07` Commit theo đơn vị có thể rollback: (1) patch JWT issuance/validation, (2) JWT + ACL, (3) rate-limit + network. Không commit secret thật, `.env.state-b`, runtime config hay database; kiểm tra `git diff` trước mỗi commit. *(Hoàn thành 2026-11-16: audit trên Ubuntu xác nhận `974b8c3`; `.env.state-b`, `.state-b/`, `kong/kong.runtime.yml` và `evidence/` đều bị ignore; bằng chứng local tại `evidence/state-b/w3-kong-07/`.)*

### W3-BACKEND — Lớp trong: Vá mã nguồn Backend

- [X] `W3-BACKEND-01` Vá BOLA theo nguyên tắc default-deny: thêm ownership check **ngay trong truy vấn** của endpoint đã khai thác ở `W2-BOLA`; user thường chỉ đọc object của mình; admin chỉ vượt ownership khi Access Control Matrix có policy tường minh. *(Hoàn thành 2026-11-16: attacker đọc `VictimDiary` nhận `404`; attacker tạo/đọc book của mình nhận `200`; Kong và VAmPI logs cùng xác nhận ba probe; evidence local tại `evidence/state-b/w3-backend-01/`.)*
- [X] `W3-BACKEND-02` Định nghĩa và version-control Access Control Matrix `(role × action × resource × điều kiện)` cho mọi route nhạy cảm; áp dụng kiểm tra quyền backend tương ứng. Không tin quyền chỉ vì request đã đi qua Kong, và không tin `role=admin` từ payload nếu chưa được backend xác thực theo policy. *(Hoàn thành 2026-11-17: matrix tại `docs/access-control-matrix.md`; backend lấy subject từ JWT rồi tra `users.admin` trong DB. Attacker nhận `403` khi liệt kê user, đọc profile victim hoặc đổi email/password victim; register có `admin=true` nhận `400`; Kong và VAmPI logs cùng xác nhận probe; evidence local tại `evidence/state-b/w3-backend-02-03/`.)*
- [X] `W3-BACKEND-03` Thêm response DTO/serializer **whitelist** cho endpoint `W2-EXPOSURE`; gỡ hẳn route `/_debug` cùng khai báo OpenAPI liên quan. Không trả password, password hash, token, secret, field nội bộ hoặc field quản trị không cần cho client. *(Hoàn thành 2026-11-17: `/me` chỉ trả `username`, `email`; assertion DTO pass; `/_debug` và `/createdb` đã gỡ khỏi OpenAPI/code. Corrective commit `45f83e6` xử lý route động để `/_debug` với JWT hợp lệ trả `404`; evidence local tại `evidence/state-b/w3-backend-02-03/`.)*
- [X] `W3-BACKEND-04` Thêm token invalidation có trạng thái bằng `token_version`: đưa version vào JWT, tăng version khi đổi password và so sánh với bản ghi user ở mỗi request protected. Token cũ của `W2-JWT-02` phải bị backend từ chối `401` dù có thể vẫn qua kiểm tra chữ ký tại Kong. *(Hoàn thành 2026-11-17: migration SQLite giữ nguyên DB và thêm cột với default `0`; token cũ `0` dùng được trước đổi password nhưng bị `401` sau đó; token mới là version `1` và nhận `200`; password đã khôi phục. Probe stale-token xuất hiện ở cả Kong và VAmPI với `401`, chứng minh backend từ chối; evidence local tại `evidence/state-b/w3-backend-04/`.)*
- [ ] `W3-BACKEND-05` Viết test nhỏ hoặc script assertion có thể chạy lại: victim đọc dữ liệu của mình thành công; attacker bị chặn BOLA; login/đổi password vẫn hoạt động; token cũ bị `401`; `/_debug` bị `404`; response không chứa field cấm. Lưu output pass/fail làm evidence State B.
- [ ] `W3-BACKEND-06` Lưu diff/patch trước-sau cho từng file đã sửa vào `lab/backend-patches/`, rồi commit riêng theo loại vá: (1) BOLA/ACL backend, (2) data filtering/debug removal, (3) token lifecycle. Không đưa database, JWT hay secret thật vào commit.

### W3-WRAP — Tổng hợp Tuần 3

- [ ] `W3-WRAP-01` Xác nhận hệ thống đã ở đúng **State B** (Kong đủ 3 plugin + Backend đã vá) mà không đổi topology tổng thể so với Tuần 1.
- [ ] `W3-WRAP-02` Cập nhật sơ đồ kiến trúc (nếu có thay đổi so với bản Tuần 1) — đánh dấu rõ phần mới thêm (plugin, patch).
- [ ] `W3-WRAP-03` Lưu evidence State B có cấu trúc: cấu hình đã sanitize, Kong access log, VAmPI log, request/response và kết quả test assertion. Chứng minh rõ request nào bị chặn tại Kong, request nào bị backend từ chối.
- [ ] `W3-WRAP-04` Viết bảng mapping `W2 finding → W3 control → W3 test → W4 re-test` để tránh nhầm gateway control với backend control khi phân tích kết quả.

**Checkpoint cuối Tuần 3**: Hệ thống phòng thủ hai lớp hoàn chỉnh, chức năng hợp lệ không bị hỏng.

---

## TUẦN 4 — Re-test, tổng hợp & đóng gói

### W4-RETEST — Kiểm thử lại

- [ ] `W4-RETEST-BOLA` Lặp lại chính xác `W2-BOLA-02`/`03` trên State B → ghi nhận kết quả (kỳ vọng: bị chặn/từ chối).
- [ ] `W4-RETEST-JWT-A` Lặp lại `W2-JWT-01a→d` trên State B → ghi nhận kết quả (kỳ vọng: token giả mạo bị Kong chặn trước khi tới Backend).
- [ ] `W4-RETEST-JWT-B` Lặp lại `W2-JWT-02a→c` trên State B → ghi nhận kết quả, kể cả nếu giới hạn kỹ thuật vẫn còn tồn tại (ghi nhận trung thực).
- [ ] `W4-RETEST-EXPOSURE` Lặp lại `W2-EXPOSURE-02` trên State B → so sánh field trả về với bảng đánh dấu ở Tuần 2.
- [ ] `W4-RETEST-EVIDENCE` Lưu toàn bộ log/ảnh chụp re-test vào `evidence/retest/<lohong>/` theo đúng cấu trúc baseline.

### W4-ANALYSIS — Đối chiếu & số liệu

- [ ] `W4-ANALYSIS-01` Dựng bảng đối chiếu trước/sau cho BOLA (HTTP status, dữ liệu rò rỉ có/không).
- [ ] `W4-ANALYSIS-02` Dựng bảng đối chiếu trước/sau cho JWT (thời gian/khả năng bẻ khóa, hành vi replay, tầng nào chặn).
- [ ] `W4-ANALYSIS-03` Dựng bảng đối chiếu trước/sau cho Excessive Data Exposure (field-by-field).
- [ ] `W4-ANALYSIS-04` Viết nhận định về giới hạn kỹ thuật đã biết (Gateway không thay thế được logic nghiệp vụ; claim `iss` là yêu cầu tích hợp) — đối chiếu với `spec.md` §6.

### W4-REPORT — Báo cáo & tài liệu

- [ ] `W4-REPORT-01` Viết báo cáo kỹ thuật theo cấu trúc ở `plan.md` §3 (Tuần 4, mục 3).
- [ ] `W4-REPORT-02` Chèn toàn bộ bằng chứng (ảnh, bảng đối chiếu) vào đúng mục liên quan trong báo cáo.
- [ ] `W4-REPORT-03` Rà soát chính tả/định dạng theo yêu cầu nộp bài của học phần (nếu có mẫu riêng từ GVHD).

### W4-PACKAGE — Đóng gói mã nguồn

- [ ] `W4-PACKAGE-01` Hoàn thiện README GitHub: hướng dẫn dựng lại toàn bộ Lab từ đầu (Docker, Kong, VAmPI, patch).
- [ ] `W4-PACKAGE-02` Rà soát repo: không commit nhầm secret thật (SECRET_KEY demo dùng trong lab có thể giữ lại vì là mục đích minh họa, nhưng không được chứa thông tin cá nhân thật).
- [ ] `W4-PACKAGE-03` Push toàn bộ lên GitHub, đặt repo ở chế độ công khai (public) theo yêu cầu đề cương.

### W4-SLIDES — Slide bảo vệ

- [ ] `W4-SLIDES-01` Soạn slide: Đặt vấn đề → Mục tiêu → Kiến trúc Lab → 3 kịch bản tấn công (tóm tắt) → Giải pháp phòng thủ → Số liệu đối chiếu → Kết luận.
- [ ] `W4-SLIDES-02` Chèn ảnh/số liệu nổi bật nhất (không nhồi nhét toàn bộ log) để slide dễ trình bày trong thời gian bảo vệ.

**Checkpoint cuối Tuần 4**: Đủ 4 deliverable theo `spec.md` §5 — hệ thống Lab, báo cáo, mã nguồn GitHub, slide.

---

## Mục rủi ro & kế hoạch dự phòng (Contingency)

### Xử lý khi một kịch bản tấn công Tuần 2 không thành công ngay

- **BOLA không khai thác được**: kiểm tra lại VAmPI có đang ở đúng `vulnerable mode` không (`W1-VAMPI-03`); thử endpoint khác trong danh sách API của VAmPI có tham số ID.
- **Brute-force SECRET_KEY quá lâu**: giảm độ phức tạp wordlist/dùng wordlist rút gọn phù hợp với SECRET_KEY mẫu của VAmPI (nếu tài liệu VAmPI có gợi ý độ khó mặc định); ghi nhận thời gian thực tế dù dài, đó vẫn là số liệu hợp lệ cho báo cáo.
- **Token Replay không có hiệu ứng rõ** (vì bản thân VAmPI đã chặn hoặc chưa implement đổi mật khẩu đúng cách): ghi nhận trung thực, chuyển trọng tâm phần JWT sang kịch bản (a) giả mạo Admin — vẫn đáp ứng `spec.md` §3.1.

### Xử lý khi Kong plugin phá vỡ chức năng hợp lệ ở Tuần 3

- Rollback về `kong.yml` commit trước đó (nhờ đã commit từng bước ở `W1-KONG-05`/`W3-KONG-07`), thêm lại plugin một cách tăng dần (JWT → test → ACL → test → Rate Limiting → test) thay vì thêm cả 3 cùng lúc.

### Nếu thời gian Tuần 4 không đủ cho cả báo cáo + slide + đóng gói

- Ưu tiên theo thứ tự: (1) Re-test có số liệu → (2) Đóng gói GitHub → (3) Báo cáo → (4) Slide — vì số liệu đối chiếu là phần chứng minh cốt lõi của đề tài (`spec.md` §2.3), còn slide có thể rút gọn nếu cần.

---

## Nhật ký cập nhật (Changelog của chính file này)

> Ghi lại mỗi khi phạm vi công việc thay đổi so với bản gốc, kèm ngày và lý do — giúp tránh xung đột khi nhìn lại tiến độ.

- `2026-11-05` — Khởi tạo `task.md` từ `spec.md`/`plan.md`, bám sát đề cương gốc.
- `2026-11-15` — Tinh chỉnh kế hoạch State B theo nguyên tắc defense-in-depth: làm rõ validation JWT, giới hạn của ACL Kong, rate-limit một node, token revocation có trạng thái, evidence logging và regression test.
