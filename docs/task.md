# TASK.md — Danh sách công việc chi tiết

> Dựa trên `plan.md` (trình tự) và `spec.md` (mục tiêu/tiêu chí chấp nhận). Đây là checklist thực thi — cập nhật trạng thái trực tiếp trong file này khi làm việc, để biết chính xác đang ở đâu và tránh làm trùng/xung đột công việc.

**Quy ước trạng thái:** `[ ]` chưa làm · `[~]` đang làm · `[x]` xong · `[!]` bị chặn/có vấn đề (ghi chú lý do ngay dưới dòng đó).

**Quy ước ID task:** `W<tuần>-<nhóm>-<số thứ tự>` (ví dụ `W1-INFRA-03`) để tham chiếu chéo trong báo cáo hoặc commit message (ví dụ: `git commit -m "W3-KONG-02: add jwt plugin"`).

---

## TUẦN 1 — Dựng hạ tầng Lab

### W1-INFRA — Hạ tầng ảo hóa & mạng
- [ ] `W1-INFRA-01` Cài đặt VirtualBox/VMware Workstation trên máy host.
- [ ] `W1-INFRA-02` Tạo VM Kali Linux (máy tấn công) — cập nhật, cài Burp Suite Community + Postman nếu chưa có sẵn.
- [ ] `W1-INFRA-03` Tạo VM Ubuntu Server (máy chủ dịch vụ) — cài Docker + Docker Compose.
- [ ] `W1-INFRA-04` Thiết lập mạng giữa 2 VM (bridged/host-only network) — xác nhận Kali ping được tới Ubuntu Server.

### W1-VAMPI — Triển khai ứng dụng mục tiêu
- [ ] `W1-VAMPI-01` Clone mã nguồn VAmPI từ GitHub vào Ubuntu Server.
- [ ] `W1-VAMPI-02` Build & chạy VAmPI qua Docker; xác nhận container healthy.
- [ ] `W1-VAMPI-03` Kiểm tra công tắc bật/tắt chế độ `vulnerable` — test cả 2 trạng thái, ghi chú cách bật/tắt (biến môi trường/endpoint) vào README.
- [ ] `W1-VAMPI-04` Tạo bộ dữ liệu test cố định: 2 tài khoản `victim` và `attacker` (và `admin` nếu kịch bản JWT cần) — **dùng xuyên suốt dự án, không tạo lại sau này**.
- [ ] `W1-VAMPI-05` Đặt VAmPI ở chế độ **vulnerable** (chuẩn bị cho baseline Tuần 2).

### W1-KONG — Khung Kong Gateway cơ bản
- [ ] `W1-KONG-01` Pull image `kong:3.9.1` (ghim đúng version — **không dùng `latest`**).
- [ ] `W1-KONG-02` Viết `kong.yml` tối thiểu (DB-less mode): 1 service trỏ tới VAmPI, 1 route — **chưa thêm plugin bảo mật nào**.
- [ ] `W1-KONG-03` Chạy Kong container, xác nhận request từ Kali qua Kong tới VAmPI trả về đúng kết quả (so với gọi thẳng VAmPI).
- [ ] `W1-KONG-04` Xác nhận quy trình reload cấu hình (`kong reload` hoặc restart container) hoạt động ổn định — tránh phát sinh ở Tuần 3.
- [ ] `W1-KONG-05` Commit `kong.yml` ban đầu vào Git.

### W1-DOC — Tài liệu & kiến trúc
- [ ] `W1-DOC-01` Vẽ sơ đồ kiến trúc hệ thống (Kali → Kong → VAmPI, kèm Docker network) — lưu vào `report/assets/`.
- [ ] `W1-DOC-02` Khởi tạo repo GitHub (README nháp, cấu trúc thư mục theo `plan.md` §4).

**Checkpoint cuối Tuần 1** *(xem `plan.md` §5)*: Lab chạy được, bộ dữ liệu test đã chốt, sơ đồ kiến trúc đã có.

---

## TUẦN 2 — Red Team: Tấn công giả lập (Baseline / State A)

### W2-BOLA — Broken Object Level Authorization
- [ ] `W2-BOLA-01` Xác định endpoint mục tiêu có tham số object ID (ví dụ `/users/{id}` hoặc tương đương trong VAmPI).
- [ ] `W2-BOLA-02` Đăng nhập bằng `attacker`, bắt request bằng Burp Suite Proxy.
- [ ] `W2-BOLA-03` Sửa tham số ID thành ID của `victim`, gửi lại (Repeater), xác nhận truy cập được dữ liệu không thuộc quyền.
- [ ] `W2-BOLA-04` Export request/response từ Burp (`.txt`/XML), chụp màn hình → lưu vào `evidence/baseline/bola/`.

### W2-JWT — Broken Authentication
- [ ] `W2-JWT-01a` Trích xuất 1 JWT hợp lệ (của `victim` hoặc `attacker`) từ phiên đăng nhập.
- [ ] `W2-JWT-01b` Dùng hashcat brute-force SECRET_KEY offline (ghi lại thời gian bẻ khóa — số liệu này sẽ dùng ở báo cáo).
- [ ] `W2-JWT-01c` Dùng jwt.io (hoặc script) tạo token mới với payload `role=admin`, ký bằng SECRET_KEY vừa tìm được.
- [ ] `W2-JWT-01d` Gửi request dùng token giả mạo tới 1 endpoint yêu cầu quyền admin — xác nhận được chấp nhận.
- [ ] `W2-JWT-02a` Lấy & lưu lại token hiện tại của `victim`.
- [ ] `W2-JWT-02b` Thực hiện đổi mật khẩu cho `victim` (qua API đổi mật khẩu của VAmPI).
- [ ] `W2-JWT-02c` Replay lại token cũ đã lưu — kiểm tra còn dùng được không, ghi nhận kết quả (kể cả nếu VAmPI đã chặn — đây vẫn là dữ liệu hợp lệ).
- [ ] `W2-JWT-03` Export toàn bộ log hashcat + request/response Burp cho cả (a) và (b) → lưu vào `evidence/baseline/jwt-auth/`.

### W2-EXPOSURE — Excessive Data Exposure
- [ ] `W2-EXPOSURE-01` Liệt kê các endpoint trả thông tin user/profile.
- [ ] `W2-EXPOSURE-02` Dùng Postman/Burp gọi từng endpoint, lưu toàn bộ response JSON.
- [ ] `W2-EXPOSURE-03` Đối chiếu field trả về với field thực sự cần cho chức năng client — đánh dấu rõ field nhạy cảm dư thừa (password hash, token nội bộ, email không cần public...).
- [ ] `W2-EXPOSURE-04` Lưu response JSON gốc + bảng đánh dấu field nhạy cảm → `evidence/baseline/data-exposure/`.

### W2-WRAP — Tổng hợp Tuần 2
- [ ] `W2-WRAP-01` Kiểm tra lại đủ 3/3 kịch bản có bằng chứng đầy đủ (ảnh + log) theo tiêu chí `spec.md` §7.
- [ ] `W2-WRAP-02` Nếu có kịch bản thất bại/không rõ ràng → xem mục "Xử lý khi kịch bản không thành công" bên dưới, điều chỉnh **trước khi** sang Tuần 3.
- [ ] `W2-WRAP-03` Commit toàn bộ evidence baseline vào Git.

**Checkpoint cuối Tuần 2**: Cả 3 kịch bản tấn công thành công & có PoC đầy đủ.

---

## TUẦN 3 — Blue Team: Triển khai phòng thủ hai lớp (chuyển sang State B)

### W3-KONG — Lớp ngoài: Cấu hình plugin Kong
- [ ] `W3-KONG-01` Sửa token issuance logic của VAmPI để thêm claim `iss` vào JWT (yêu cầu kỹ thuật của Kong JWT plugin) — ghi rõ trong code comment/commit rằng đây là thay đổi tích hợp, không phải logic nghiệp vụ.
- [ ] `W3-KONG-02` Cấu hình Kong consumer + JWT credential tương ứng; thêm plugin `jwt` vào route VAmPI trong `kong.yml`.
- [ ] `W3-KONG-03` Test nhanh: request có token hợp lệ (đã có `iss`) đi qua được Kong; request thiếu/sai token bị Kong chặn (401/403) — xác nhận chặn **tại Kong**, chưa chạm VAmPI (kiểm tra qua log VAmPI không ghi nhận request đó).
- [ ] `W3-KONG-04` Thêm plugin `acl`, định nghĩa nhóm quyền, gán route theo nhóm.
- [ ] `W3-KONG-05` Thêm plugin `rate-limiting`, cấu hình giới hạn request/phút theo IP hoặc consumer.
- [ ] `W3-KONG-06` Test tổng hợp: VAmPI không còn truy cập trực tiếp được từ ngoài (chỉ qua Kong) — xác nhận bằng cách thử gọi thẳng port VAmPI từ Kali.
- [ ] `W3-KONG-07` Commit `kong.yml` cập nhật + patch token issuance vào Git (commit riêng cho từng plugin).

### W3-BACKEND — Lớp trong: Vá mã nguồn Backend
- [ ] `W3-BACKEND-01` Thêm ownership check tại endpoint đã khai thác BOLA ở `W2-BOLA` — verify `current_user.id == object.owner_id` trước khi trả dữ liệu.
- [ ] `W3-BACKEND-02` Định nghĩa Access Control Matrix (vai trò × hành động) cho các route nhạy cảm; áp dụng kiểm tra quyền tương ứng.
- [ ] `W3-BACKEND-03` Thêm lớp lọc field (whitelist) cho response của các endpoint đã ghi nhận ở `W2-EXPOSURE` — loại bỏ field nhạy cảm không cần thiết.
- [ ] `W3-BACKEND-04` Thử tay (hoặc viết test nhỏ) xác nhận chức năng hợp lệ không bị hỏng: `victim` vẫn truy cập được dữ liệu của chính mình, đăng nhập/đổi mật khẩu vẫn hoạt động.
- [ ] `W3-BACKEND-05` Lưu diff/patch (trước–sau) cho từng file đã sửa vào `lab/backend-patches/`.
- [ ] `W3-BACKEND-06` Commit các bản vá Backend vào Git (commit riêng cho từng loại vá: BOLA / ACL / data filtering).

### W3-WRAP — Tổng hợp Tuần 3
- [ ] `W3-WRAP-01` Xác nhận hệ thống đã ở đúng **State B** (Kong đủ 3 plugin + Backend đã vá) mà không đổi topology tổng thể so với Tuần 1.
- [ ] `W3-WRAP-02` Cập nhật sơ đồ kiến trúc (nếu có thay đổi so với bản Tuần 1) — đánh dấu rõ phần mới thêm (plugin, patch).

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
