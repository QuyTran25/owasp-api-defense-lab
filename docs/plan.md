# PLAN.md — Kế hoạch triển khai

> Dựa trên `spec.md`. Tài liệu này mô tả **LÀM NHƯ THẾ NÀO** và **THEO TRÌNH TỰ NÀO**. Không lặp lại mục tiêu/phạm vi (đã có ở `spec.md`); không liệt kê checklist công việc từng gạch đầu dòng (xem `task.md`).
>
> Nguyên tắc xuyên suốt: **mỗi lỗ hổng phải đi trọn vòng đời Baseline (tấn công trước) → Vá (Blue Team) → Re-test (tấn công lại) → Ghi nhận số liệu**, trên **cùng một hệ thống mục tiêu**, để đảm bảo so sánh trước/sau có giá trị.

---

## 1. Kiến trúc hệ thống Lab

### 1.1 Sơ đồ tổng quan (mô tả luồng)

```
┌─────────────────────────┐        ┌──────────────────────────────────────┐
│   Máy tấn công (Kali)   │        │   Máy chủ dịch vụ (Ubuntu Server)     │
│                          │        │                                        │
│  - Burp Suite Community │        │  ┌──────────────┐     ┌─────────────┐ │
│  - Postman              │  HTTP  │  │ Kong Gateway  │ --> │   VAmPI      │ │
│  - hashcat / jwt.io      │ ─────> │  │ (kong:3.9.1)  │     │ (Flask+SQLite)│ │
│                          │        │  │ DB-less mode  │     │  Docker      │ │
└─────────────────────────┘        │  └──────────────┘     └─────────────┘ │
                                    │        ^ (Docker network nội bộ)      │
                                    └──────────────────────────────────────┘
```

### 1.2 Giai đoạn kiến trúc — QUAN TRỌNG

Hệ thống **không tĩnh** trong suốt 4 tuần — nó tiến hóa theo 2 trạng thái rõ rệt, và việc chuyển trạng thái phải được kiểm soát để không làm hỏng khả năng so sánh:

| Trạng thái | Khi nào | Đặc điểm |
|---|---|---|
| **State A — Baseline (Vulnerable)** | Tuần 1–2 | VAmPI chạy ở chế độ vulnerable; **tấn công trực tiếp vào VAmPI** (chưa có Kong chặn phía trước, hoặc Kong mới chỉ là reverse-proxy trần không plugin bảo mật) |
| **State B — Hardened (Secure)** | Tuần 3–4 | Kong đã bật đủ 3 plugin (JWT, ACL, Rate Limiting); Backend đã vá (ownership check, lọc field); **mọi traffic bắt buộc đi qua Kong** trước khi tới VAmPI |

> Lưu ý thiết kế: Ở Tuần 1, Kong được cài đặt **khung cơ bản, chưa cấu hình plugin** — nghĩa là Kong đã đứng trước VAmPI về mặt hạ tầng (routing) ngay từ đầu, nhưng ở State A nó chỉ đóng vai trò reverse-proxy, không thực hiện kiểm soát bảo mật nào. Điều này giúp Tuần 2 tấn công đúng qua đường dẫn sẽ dùng ở Tuần 4, tránh sai lệch do thay đổi topology giữa 2 lần đo.

### 1.3 Các thành phần kỹ thuật cố định

- **VAmPI**: chạy trong Docker container, có switch bật/tắt `vulnerable mode` (biến môi trường hoặc endpoint cấu hình theo tài liệu VAmPI). Dữ liệu seed (users, tokens) phải được chuẩn hóa thành 1 bộ dữ liệu test cố định — dùng lại cho cả 2 lần đo (baseline và re-test) để số liệu so sánh được.
- **Kong Gateway**: `kong:3.9.1`, DB-less mode, cấu hình khai báo trong `kong.yml`. Route tới VAmPI service. Plugin áp dụng tuần tự theo Tuần 3 (xem mục 3).
- **Mạng Docker**: Kong và VAmPI nằm trên cùng Docker network nội bộ; chỉ port của Kong được expose ra ngoài ở State B (VAmPI không được truy cập trực tiếp nữa — đây chính là bằng chứng kiến trúc cho việc Gateway kiểm soát lối vào).

---

## 2. Phương pháp luận (Methodology)

### 2.1 Vòng lặp thực nghiệm cho mỗi lỗ hổng

Áp dụng **cùng một quy trình 5 bước** cho cả 3 lỗ hổng (BOLA, JWT, Excessive Data Exposure) để đảm bảo tính nhất quán và dễ viết báo cáo:

1. **Thiết lập baseline** — xác định endpoint/kịch bản mục tiêu, chuẩn bị 2 tài khoản test (nạn nhân + kẻ tấn công).
2. **Khai thác (Red Team)** — thực hiện đúng kỹ thuật đã định trong `spec.md` §3.1, ghi log request/response bằng Burp Suite (Save Item / Export).
3. **Ghi nhận PoC** — chụp màn hình + lưu log thô (file `.txt`/`.json` export từ Burp/Postman) vào thư mục bằng chứng, đặt tên theo quy ước (xem §4).
4. **Triển khai phòng thủ (Blue Team)** — áp dụng đúng giải pháp tương ứng trong `spec.md` §3.2.
5. **Re-test** — lặp lại chính xác bước 2 với cùng request/payload (chỉ khác hệ thống đã được vá), ghi log, so sánh side-by-side.

### 2.2 Nguyên tắc "cùng request, khác thời điểm"

Để số liệu đối chiếu có giá trị khoa học, **payload tấn công ở bước re-test phải giống hệt** (hoặc chỉ khác đúng phần cần thiết, có ghi chú) so với payload baseline. Không được "làm mới" kịch bản tấn công ở Tuần 4 — nếu không, không thể kết luận "giải pháp chặn được" hay "do kịch bản khác".

### 2.3 Quản lý phiên bản & tái lập (Reproducibility)

- Toàn bộ `kong.yml`, patch code Backend, script dựng Docker (Dockerfile/docker-compose.yml nếu có) được commit vào Git **ngay khi tạo ra**, không gom cuối kỳ.
- Mỗi thay đổi lớn (ví dụ: thêm plugin, sửa 1 file backend) nên là 1 commit riêng với message rõ ràng (ví dụ: `feat(kong): add jwt plugin with iss claim support`, `fix(backend): add ownership check for /users/{id}`).
- README của repo phải đủ để người khác dựng lại toàn bộ Lab từ đầu (yêu cầu ở `spec.md` §5.3).

---

## 3. Lộ trình 4 tuần (chi tiết hoá từ đề cương)

### Tuần 1 — Dựng hạ tầng Lab
**Mục tiêu:** Có một hệ thống Lab chạy được, đúng kiến trúc State A, sẵn sàng cho tấn công Tuần 2.

- Cài Docker trên Ubuntu Server; cài Kali Linux (máy riêng hoặc VM riêng).
- Triển khai VAmPI qua Docker — xác nhận 2 chế độ vulnerable/secure hoạt động đúng (test thủ công, không cần vá gì).
- Cài khung Kong Gateway cơ bản (DB-less, `kong.yml` tối thiểu: 1 service trỏ tới VAmPI, 1 route) — **chưa bật plugin bảo mật nào**.
- Chuẩn hóa bộ dữ liệu test: tạo 2 user cố định (ví dụ `victim` và `attacker`) dùng xuyên suốt dự án.
- Vẽ sơ đồ kiến trúc hệ thống (dùng cho báo cáo và slide).

**Đầu ra:** Hệ thống Lab hoạt động (VAmPI qua Kong, chế độ vulnerable); sơ đồ kiến trúc.

**Rủi ro cần theo dõi:** Nếu Kong DB-less reload `kong.yml` không ổn định → nên xác nhận quy trình `kong reload`/restart container ngay từ Tuần 1, tránh phát sinh ở Tuần 3 khi đang gấp.

---

### Tuần 2 — Red Team: Tấn công giả lập (Baseline)
**Mục tiêu:** Thực nghiệm thành công cả 3 kịch bản tấn công trên hệ thống State A, thu đủ PoC.

- **BOLA**: dùng Burp Suite Proxy chặn request của `attacker` tới 1 endpoint có tham số ID; sửa ID thành của `victim`; xác nhận truy cập được dữ liệu không thuộc quyền.
- **Broken Authentication (JWT)**:
  - (a) Trích xuất 1 JWT hợp lệ, dùng hashcat brute-force SECRET_KEY (offline), dùng jwt.io để tạo lại token với claim role=admin đã ký bằng key vừa tìm được; gửi request dùng token giả mạo.
  - (b) Lấy token của `victim`, cho `victim` đổi mật khẩu, sau đó replay lại token cũ — kiểm tra token cũ còn hoạt động không.
- **Excessive Data Exposure**: gọi các endpoint trả thông tin user/profile, dùng Burp/Postman kiểm tra toàn bộ field trong response JSON, đối chiếu với field thực sự cần thiết cho client.
- Toàn bộ 3 kịch bản: export log Burp (request + response), chụp màn hình, lưu vào thư mục bằng chứng baseline.

**Đầu ra:** Bằng chứng khai thác (PoC) cho từng lỗ hổng — đây là input bắt buộc cho báo cáo (mục "trước khi vá").

---

### Tuần 3 — Blue Team: Triển khai phòng thủ hai lớp
**Mục tiêu:** Chuyển hệ thống từ State A sang State B mà không phá vỡ khả năng test lại.

**Lớp ngoài — Kong Gateway (dựa trên khung đã dựng Tuần 1):**
1. Plugin **JWT**: cấu hình consumer + credential; xử lý yêu cầu claim `iss` trong token VAmPI phát hành (sửa nhỏ ở token issuance logic — ghi rõ đây là yêu cầu tích hợp kỹ thuật, không phải sửa lỗi bảo mật).
2. Plugin **ACL** (Access Control List): giới hạn route/consumer theo nhóm quyền, hỗ trợ chặn truy cập trái phép ở tầng route trước khi chạm Backend.
3. Plugin **Rate Limiting**: giới hạn số request/phút theo IP hoặc consumer, chống brute-force/quét dò tự động (giảm thiểu lại chính kỹ thuật đã dùng ở Tuần 2 cho JWT).

**Lớp trong — Vá Backend (Flask/VAmPI):**
1. BOLA: thêm ownership check — mọi truy vấn object theo ID phải xác minh `current_user == object.owner` trước khi trả dữ liệu.
2. Access Control Matrix: định nghĩa rõ ma trận vai trò ↔ hành động được phép, áp dụng vào các route nhạy cảm.
3. Excessive Data Exposure: thêm lớp serialization lọc field (ví dụ dùng schema/whitelist field thay vì trả nguyên object ORM) cho các response liên quan tới user/profile.

**Đầu ra:** Hệ thống phòng thủ hai lớp hoàn chỉnh, sẵn sàng re-test Tuần 4.

**Ràng buộc:** Không được gỡ bỏ cấu hình Kong cơ bản của Tuần 1 — chỉ **thêm** plugin vào service/route đã có, để giữ nguyên topology khi so sánh.

---

### Tuần 4 — Re-test, tổng hợp & đóng gói
**Mục tiêu:** Chứng minh hiệu quả bằng số liệu, hoàn thiện mọi deliverable.

1. **Re-test**: lặp lại đúng 3 kịch bản Tuần 2 (cùng payload/kỹ thuật) trên State B. Ghi log, chụp màn hình, lưu vào thư mục bằng chứng re-test.
2. **Đối chiếu trước/sau**: dựng bảng/biểu đồ so sánh (HTTP status code, dữ liệu rò rỉ có/không, thời gian brute-force bị chặn ở bước nào, v.v.) cho từng lỗ hổng — đây là phần "chứng minh định lượng" bắt buộc theo `spec.md` §2.3.
3. **Viết báo cáo kỹ thuật** theo cấu trúc: Đặt vấn đề → Lỗ hổng & cơ chế → PoC khai thác → Giải pháp phòng thủ (cấu hình chi tiết) → Mã nguồn đã vá (diff) → Số liệu đối chiếu → Kết luận & giới hạn.
4. **Đóng gói mã nguồn** lên GitHub: `kong.yml`, patch backend, README dựng lại Lab, thư mục bằng chứng (ảnh/log) có tổ chức.
5. **Soạn slide bảo vệ**: tóm tắt vấn đề, phương pháp, kết quả, demo (ảnh/video ngắn nếu có).

**Đầu ra:** Báo cáo hoàn chỉnh, mã nguồn trên GitHub, slide bảo vệ — đúng 3 deliverable cuối của `spec.md` §5.

---

## 4. Quy ước đặt tên & tổ chức bằng chứng

Để tránh lẫn lộn giữa Tuần 2 (baseline) và Tuần 4 (re-test), đề xuất cấu trúc thư mục:

```
evidence/
├── baseline/              # Tuần 2 - trước khi vá
│   ├── bola/
│   ├── jwt-auth/
│   └── data-exposure/
└── retest/                # Tuần 4 - sau khi vá
    ├── bola/
    ├── jwt-auth/
    └── data-exposure/

lab/
├── kong/
│   └── kong.yml
├── vampi/                 # nếu cần patch/config riêng
└── backend-patches/       # diff hoặc source đã sửa

report/
└── bao-cao-ky-thuat.md (hoặc .docx theo yêu cầu nộp)

slides/
└── slide-bao-ve.pptx
```

Tên file bằng chứng nên theo mẫu: `<tuan>_<lohong>_<hanh-dong>.png` (ví dụ: `tuan2_bola_sua-id-request.png`) để dễ tra cứu khi viết báo cáo.

---

## 5. Theo dõi tiến độ & điểm kiểm soát (Checkpoints)

| Cuối tuần | Câu hỏi kiểm tra (self-check trước khi qua tuần tiếp theo) |
|---|---|
| Tuần 1 | Lab chạy được chưa? Request từ Kali tới VAmPI qua Kong có phản hồi đúng không? Đã chốt bộ dữ liệu test (`victim`/`attacker`) chưa? |
| Tuần 2 | Cả 3 kịch bản tấn công đã **thành công và có bằng chứng lưu lại** chưa? Nếu 1 kịch bản chưa thành công, có cần điều chỉnh kỹ thuật tấn công không (xem `task.md` mục rủi ro)? |
| Tuần 3 | Cả 3 plugin Kong đã bật và không phá vỡ route hiện có chưa? Bản vá Backend có unit-test/thử tay xác nhận không làm hỏng chức năng hợp lệ (ví dụ: `victim` vẫn truy cập được dữ liệu của chính mình) chưa? |
| Tuần 4 | Re-test có dùng **đúng payload** như Tuần 2 không? Bảng đối chiếu đã có số liệu cụ thể (không chỉ mô tả định tính) chưa? Repo GitHub đã có README đủ để dựng lại chưa? |

---

*Mọi điều chỉnh về trình tự hoặc kỹ thuật triển khai cập nhật tại đây. Nếu điều chỉnh làm thay đổi phạm vi/mục tiêu, phải đồng bộ lại với `spec.md` trước.*
