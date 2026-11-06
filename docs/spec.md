# SPEC.md — Đặc tả dự án

> **Đề tài:** Nghiên cứu các lỗ hổng an ninh theo tiêu chuẩn OWASP API Security Top 10 và triển khai giải pháp phòng thủ hai lớp bằng API Gateway kết hợp Secure Coding
> **Mã học phần:** 010412304602 — Chuyên đề Hệ thống mạng và Bảo mật
> **Sinh viên:** Huỳnh Thị Quý Trân — MSSV 051305000763
> **GVHD:** Thầy Bùi Dương Thế
> **Trường:** ĐH Giao thông Vận tải TP.HCM — Viện CNTT và Điện, Điện tử
> **Văn bản gốc:** `HuynhThiQuyTran_DeCuong_CĐHeThongMangVaBaoMat_v2.docx`

Tài liệu này mô tả **CÁI GÌ** cần xây dựng và **TẠI SAO**, không mô tả trình tự thực hiện (xem `plan.md`) hay checklist công việc (xem `task.md`). Mọi quyết định kỹ thuật trong dự án phải truy ngược được về tài liệu này; nếu phát sinh điều gì không có trong `spec.md`, phải cập nhật `spec.md` trước, không tự ý mở rộng phạm vi.

---

## 1. Bối cảnh & Vấn đề cần giải quyết

Kiến trúc hiện đại (Microservices, Mobile, Cloud) khiến **Web API** trở thành bề mặt tấn công trung tâm. Theo OWASP, lỗi phổ biến nhất không phải là các lỗi web cổ điển (SQLi, XSS trên form HTML — đã bị khai thác cạn trong học thuật) mà là:

- **Lỗi kiểm soát truy cập ở mức đối tượng (BOLA)** — object không được kiểm tra quyền sở hữu.
- **Xác thực lỏng lẻo** (JWT yếu, không thu hồi được token).

Các công cụ quét lỗ hổng web truyền thống (DAST cổ điển) **không phát hiện tốt** các lỗi logic nghiệp vụ này vì chúng đòi hỏi hiểu ngữ cảnh "ai được phép xem object nào", không chỉ đơn thuần là payload injection.

**Vấn đề đề tài giải quyết:** Chứng minh bằng thực nghiệm (không chỉ lý thuyết) rằng một mô hình **phòng thủ hai lớp** — (1) chặn ở Gateway trước khi vào hệ thống, (2) vá tận gốc tại mã nguồn Backend — là cần thiết và đủ hiệu quả, đồng thời làm rõ **giới hạn kỹ thuật** của việc chỉ dùng Gateway mà không sửa code.

---

## 2. Mục tiêu (Objectives)

### 2.1 Mục tiêu nghiên cứu
Nghiên cứu cơ chế hoạt động và **thực nghiệm khai thác** 3 lỗ hổng trọng tâm trong OWASP API Security Top 10:

| # | Lỗ hổng | Mã OWASP tham chiếu |
|---|---------|----------------------|
| V1 | Broken Object Level Authorization (BOLA) | API1:2023 |
| V2 | Broken Authentication (lỗ hổng JWT) | API2:2023 |
| V3 | Excessive Data Exposure | API3:2019 / liên quan API3/API6:2023 |

### 2.2 Mục tiêu xây dựng
Xây dựng **mô hình phòng thủ hai lớp**:

- **Lớp ngoài (Gateway layer):** API Gateway kiểm soát, lọc, xác thực lưu lượng **trước khi** vào hệ thống backend.
- **Lớp trong (Code layer):** Vá lỗi tận gốc tại mã nguồn Backend (Secure Coding) — vì Gateway không thể thay thế logic nghiệp vụ.

### 2.3 Mục tiêu đo lường
Đo lường và **chứng minh định lượng** hiệu quả phòng thủ bằng kết quả tấn công lại (re-test) **trước và sau** khi triển khai giải pháp, với bằng chứng (PoC, log, ảnh chụp màn hình) cho từng pha.

### Tiêu chí hoàn thành (Definition of Done cấp đề tài)
Đề tài được coi là đạt mục tiêu khi và chỉ khi có đủ:
1.  3/3 kịch bản tấn công **thành công** trên hệ thống chưa vá (baseline "vulnerable").
2.  3/3 kịch bản tấn công **thất bại hoặc bị giảm thiểu có đo lường** trên hệ thống đã vá (sau khi áp 2 lớp phòng thủ).
3.  Có bảng đối chiếu trước/sau cho từng lỗ hổng (request/response, mã trạng thái HTTP, dữ liệu rò rỉ hoặc không).
4.  Báo cáo kỹ thuật + mã nguồn (gồm config Gateway và bản vá) đóng gói, công khai trên GitHub.
5.  Slide bảo vệ tổng hợp toàn bộ quá trình.

---

## 3. Phạm vi (Scope)

### 3.1 Trong phạm vi (In-scope)

**Mô hình Lab song song:**
- **Red Team** (tấn công giả lập): thực hiện 3 kỹ thuật tấn công tương ứng 3 lỗ hổng.
- **Blue Team** (phòng thủ & giám sát): triển khai 2 lớp phòng thủ tương ứng.
- Thực hiện **tuần tự trên cùng một hệ thống mục tiêu** (không phải 2 hệ thống độc lập) — nghĩa là: tấn công trước (baseline) → vá → tấn công lại (re-test) trên cùng VAmPI instance đã chuyển từ chế độ vulnerable sang secure.

**Red Team — chi tiết kỹ thuật bắt buộc:**

| Lỗ hổng | Kỹ thuật thực nghiệm | Công cụ |
|---|---|---|
| BOLA | Chặn bắt & sửa tham số ID trong API request để truy cập trái phép dữ liệu người dùng khác | Burp Suite Community |
| Broken Authentication | (a) Brute-force khóa bí mật JWT (SECRET_KEY) để giả mạo quyền Admin; (b) Token Replay — tái sử dụng token cũ còn hạn sau khi nạn nhân đổi mật khẩu (khai thác JWT stateless không có cơ chế thu hồi — API2:2023) | hashcat, jwt.io, Burp Suite/Postman |
| Excessive Data Exposure | Phân tích payload JSON trả về từ Backend để tìm trường dữ liệu nhạy cảm không được lọc | Burp Suite, Postman |

**Blue Team — chi tiết kỹ thuật bắt buộc:**

| Lớp phòng thủ | Giải pháp | Vị trí triển khai |
|---|---|---|
| Kiểm soát lưu lượng tại Gateway | Rate Limiting chống quét dò API tự động; lọc IP độc hại | Kong Gateway |
| Xác thực tập trung | Chuyển xác thực JWT lên tầng Gateway, chặn token giả mạo trước khi tới Backend; bổ sung claim `iss` vào token (yêu cầu kỹ thuật bắt buộc của Kong JWT plugin cho tra cứu credential, **không thay đổi logic nghiệp vụ**) | Kong Gateway (plugin `jwt`) |
| Vá lỗi tại Backend | Bổ sung kiểm tra quyền sở hữu đối tượng (ownership check) chống BOLA; áp dụng Access Control Matrix; lọc trường dữ liệu nhạy cảm ở response | Mã nguồn Flask/VAmPI |

> **Ràng buộc kỹ thuật quan trọng (phải được nêu rõ trong báo cáo):** API Gateway chỉ giảm thiểu BOLA ở tầng định tuyến/phân quyền thô (route-level), **không thể** thay thế kiểm tra logic nghiệp vụ ở tầng object. Do đó sửa mã nguồn Backend là **bắt buộc**, không phải tùy chọn, để xử lý triệt để BOLA.

### 3.2 Ngoài phạm vi (Out-of-scope)

Để tránh phình phạm vi (scope creep) trong 4 tuần, các mục sau **không** thuộc đề tài này:
- Các lỗ hổng khác trong OWASP API Top 10 ngoài 3 mục đã chọn (ví dụ: SSRF, Injection, Unsafe Consumption of APIs, Mass Assignment...) — có thể ghi nhận nếu phát hiện phụ nhưng không phải mục tiêu đo lường chính.
- Kiểm thử tải/hiệu năng (performance/load testing) của Kong Gateway.
- Triển khai production-grade (HA, clustering, TLS termination thật, WAF layer riêng).
- Phát triển tính năng mới cho VAmPI — chỉ vá lỗi bảo mật trên code có sẵn.
- Viết ứng dụng target từ đầu — dùng VAmPI (mã nguồn mở có sẵn), không tự dựng API mục tiêu.
- Tấn công ngoài phạm vi lab nội bộ (không có hoạt động pentest trên hệ thống thật/public).
- CI/CD, tự động hoá pipeline bảo mật (SAST/DAST tự động) — không bắt buộc theo đề cương, có thể là mở rộng nếu còn thời gian.

---

## 4. Yêu cầu hệ thống & Công nghệ (Technical Requirements)

| Thành phần | Công nghệ chọn | Ghi chú ràng buộc |
|---|---|---|
| Môi trường ảo hóa | VirtualBox hoặc VMware Workstation | Chọn 1, dùng xuyên suốt dự án |
| Hệ điều hành tấn công | Kali Linux | Máy Red Team |
| Hệ điều hành dịch vụ | Ubuntu Server | Máy chủ chạy VAmPI + Kong (qua Docker) |
| Ứng dụng mục tiêu | **VAmPI** (Vulnerable API) | Thay thế crAPI vì gọn nhẹ hơn (1 container Flask + SQLite so với crAPI ~6–8GB nhiều service); có sẵn công tắc bật/tắt chế độ vulnerable để đối chiếu trước/sau |
| Công cụ tấn công | Burp Suite Community, Postman, jwt.io, hashcat | Burp: chặn bắt/sửa request. Postman: gọi API có kiểm soát. jwt.io/hashcat: phân tích & bẻ khóa JWT |
| API Gateway | **Kong Gateway OSS**, image ghim phiên bản `kong:3.9.1` | Đây là bản OSS miễn phí cuối cùng còn Docker image chính thức — **không được đổi version** trừ khi ghi chú lại lý do trong `task.md`. Chạy chế độ **DB-less / declarative config** (`kong.yml`), triển khai qua Docker |
| Ngôn ngữ Backend | Python / Flask / SQLite | Theo đúng mã nguồn gốc của VAmPI, không thay framework |
| Quản lý hạ tầng | Docker (và Docker Compose nếu cần điều phối nhiều container) | VAmPI và Kong đều chạy trên Docker |

### Ràng buộc kiến trúc bắt buộc
1. **VAmPI phải có 2 instance hoặc 1 instance có công tắc bật/tắt vulnerable mode** để so sánh trước/sau mà không làm sai lệch dữ liệu đo lường.
2. **Kong phải đứng trước VAmPI** theo đúng mô hình reverse-proxy/gateway — mọi traffic tấn công ở pha re-test phải đi qua Kong trước khi tới Flask app.
3. **JWT claim `iss`** phải được thêm vào token issuance logic của VAmPI (hoặc lớp phát hành token) để tương thích với Kong JWT plugin — đây là yêu cầu kỹ thuật, cần ghi rõ trong báo cáo là **không làm thay đổi logic nghiệp vụ** của ứng dụng.
4. Toàn bộ cấu hình Kong (`kong.yml`) và các bản vá Backend phải được version-control (Git) ngay từ đầu, không làm "tay" rồi chép lại cuối kỳ.

---

## 5. Kết quả bàn giao (Deliverables)

Theo đúng mục 6 của đề cương, dự án phải bàn giao:

1. **Hệ thống Lab mạng cục bộ hoàn chỉnh** — thể hiện rõ quy trình tấn công và phòng thủ qua từng giai đoạn (có thể demo trực tiếp hoặc qua video/ảnh chụp).
2. **Báo cáo kỹ thuật chi tiết**, gồm:
   - Phân tích từng lỗ hổng (cơ chế, nguyên nhân gốc rễ).
   - Các bước khai thác (PoC từng bước, có ảnh chụp màn hình/log).
   - Cấu hình thiết bị phòng thủ (Kong plugin config, giải thích từng tham số).
   - Đoạn mã nguồn đã vá (diff trước/sau, giải thích logic).
   - **Số liệu đối chiếu hiệu quả trước/sau** khi triển khai giải pháp (bảng/biểu đồ).
3. **Mã nguồn dự án** — đóng gói, công khai trên GitHub, bao gồm:
   - Cấu hình Gateway (`kong.yml` hoặc tương đương).
   - Các bản vá Backend (source code đã sửa + có thể kèm diff/patch file).
   - Script/hướng dẫn dựng lại toàn bộ Lab (reproducibility).
4. **Slide bảo vệ** tổng hợp toàn bộ quá trình nghiên cứu và kết quả.

---

## 6. Ràng buộc & Rủi ro đã biết (Constraints & Known Risks)

| Loại | Nội dung | Ảnh hưởng |
|---|---|---|
| Thời gian | Chỉ 4 tuần, 1 sinh viên thực hiện (nhóm 1 người) | Không có dư địa cho mở rộng phạm vi; phải bám sát kế hoạch tuần |
| Kỹ thuật | Kong JWT plugin yêu cầu claim `iss` để tra cứu credential | Phải sửa token issuance của VAmPI dù không thuộc lỗi bảo mật — cần làm rõ trong báo cáo đây là yêu cầu tích hợp, không phải phát hiện lỗ hổng mới |
| Kỹ thuật | API Gateway không chặn được BOLA ở tầng logic nghiệp vụ | Phải đảm bảo bản vá Backend thực sự chống được BOLA — đây là phần việc không thể bỏ qua hoặc làm hời hợt |
| Đạo đức/Phạm vi | Toàn bộ tấn công chỉ trong lab nội bộ, hệ thống tự dựng (VAmPI) | Không thực hiện bất kỳ thao tác nào ngoài máy ảo của mình |

---

## 7. Tiêu chí chấp nhận cho từng lỗ hổng (Acceptance Criteria chi tiết)

### V1 — BOLA
- **Trước vá:** Sửa `user_id`/object ID trong request → truy cập được dữ liệu của user khác (HTTP 200 + dữ liệu không thuộc về mình).
- **Sau vá:** Cùng request → bị từ chối (HTTP 403/404 tùy thiết kế) kèm log ghi nhận hành vi bất thường.
- Bằng chứng: Burp Suite request/response trước và sau, side-by-side.

### V2 — Broken Authentication (JWT)
- **Trước vá:** (a) SECRET_KEY bị bẻ khóa bằng hashcat trong thời gian hợp lý → tạo được token Admin giả mạo được chấp nhận. (b) Token cũ vẫn dùng được sau khi đổi mật khẩu (replay).
- **Sau vá:** (a) Xác thực JWT chuyển lên Kong, token giả mạo (do sai `iss`/signature không khớp) bị chặn **trước khi tới Backend** — thể hiện qua response của Kong (401/403) chứ không phải của Flask. (b) Ghi nhận rõ cơ chế xử lý replay (nếu được xử lý) hoặc nêu rõ giới hạn còn tồn tại nếu kiến trúc stateless chưa giải quyết triệt để — đây là phát hiện hợp lệ cần nêu trung thực trong báo cáo, không bắt buộc "vá hoàn hảo" nếu giới hạn kỹ thuật được giải thích rõ.
- Bằng chứng: log hashcat, request trước/sau, log Kong chặn token.

### V3 — Excessive Data Exposure
- **Trước vá:** Response JSON chứa trường nhạy cảm (ví dụ password hash, email nội bộ, token...) không cần thiết cho client.
- **Sau vá:** Response đã lọc, chỉ trả về trường cần thiết; so sánh JSON trước/sau theo từng field.
- Bằng chứng: Response JSON đầy đủ (trước) vs đã lọc (sau), đối chiếu từng key.

---

## 8. Thuật ngữ & Tài liệu tham chiếu

- **BOLA** — Broken Object Level Authorization (API1:2023).
- **JWT** — JSON Web Token.
- **PoC** — Proof of Concept (bằng chứng khai thác).
- **DB-less / declarative config** — chế độ Kong không cần database, cấu hình toàn bộ qua file YAML.
- **VAmPI** — Vulnerable API, ứng dụng mã nguồn mở mô phỏng OWASP API Security Top 10.
- Tham chiếu chính thức: OWASP API Security Top 10 (2023), tài liệu Kong Gateway OSS, mã nguồn VAmPI (GitHub).

---

*Tài liệu này là nguồn sự thật (source of truth) về phạm vi và mục tiêu. Mọi thay đổi scope phải được cập nhật tại đây trước, sau đó phản ánh vào `plan.md` và `task.md`.*
