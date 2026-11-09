# SƠ ĐỒ KIẾN TRÚC HỆ THỐNG LAB (W1-DOC-01)

> **Học phần:** Chuyên đề Hệ thống mạng và Bảo mật (010412304602)  
> **Sinh viên:** Huỳnh Thị Quý Trân — MSSV: 051305000763  
> **GVHD:** Thầy Bùi Dương Thế  
> **Giai đoạn:** State A — Baseline (Hệ thống chưa vá / Kong Reverse-Proxy trần)

---

## 1. Sơ đồ luồng dữ liệu và phân vùng mạng

```mermaid
graph LR
    subgraph Host["Máy Host vật lý (VMware Workstation 17 Pro)"]
        subgraph Subnet["Virtual Network Subnet: 192.168.8.0/24"]
            
            subgraph Kali["Máy ảo Red Team (Kali Linux 2026.3)"]
                Burp["Burp Suite Community<br>(Intercept Proxy & Repeater)"]
                Postman["Postman / cURL API Client"]
                Hashcat["hashcat / jwt.io<br>(Bẻ khóa & giả mạo token)"]
                Firefox["Trình duyệt Firefox"]
            end
            
            subgraph Ubuntu["Máy chủ Blue Team (Ubuntu Server 26.04.1) - IP: 192.168.8.130"]
                subgraph DockerEngine["Docker Engine 29.9.3"]
                    subgraph LabNet["Mạng Docker nội bộ: lab-net (bridge)"]
                        Kong["Kong Gateway OSS 3.9.1<br>(DB-less mode / kong.yml)<br>Port: 8000 (Proxy), 8001 (Admin)"]
                        VAmPI["VAmPI Target App<br>(Flask + SQLite)<br>ENV vulnerable=1<br>Port nội bộ: 5000"]
                    end
                end
            end
            
        end
    end

    Firefox -->|"HTTP: 192.168.8.130:8000/"| Kong
    Burp -->|"HTTP Request / Tampering (Port 8000)"| Kong
    Postman -->|"API Requests (Port 8000)"| Kong
    Kong -->|"Reverse-Proxy: http://vampi:5000"| VAmPI
```

---

## 2. Bảng phân định trách nhiệm các thành phần

| Thành phần | Địa chỉ & Cổng | Vai trò kỹ thuật trong đề tài |
|---|---|---|
| **Máy Red Team (Kali Linux)** | `192.168.8.x` | Môi trường kiểm thử an ninh: Chạy Burp Suite để đánh cắp/sửa Object ID (BOLA); chạy `hashcat` brute-force khóa bí mật JWT; phân tích response JSON để phát hiện rò rỉ dữ liệu. |
| **Máy Blue Team (Ubuntu Server)** | `192.168.8.130` | Máy chủ dịch vụ lưu trữ: Cung cấp môi trường Docker điều phối cổng Gateway và Backend. |
| **Kong API Gateway** | `192.168.8.130:8000`<br>`192.168.8.130:8001` | Điểm tiếp nhận lưu lượng tập trung duy nhất từ bên ngoài. Phiên bản `kong:3.9.1` DB-less. Ở State A: Đóng vai trò Reverse-Proxy trần. Ở State B: Kích hoạt JWT, ACL, Rate Limiting. |
| **VAmPI Backend** | Cổng container: `5000`<br>(mạng `lab-net`) | Ứng dụng mục tiêu mô phỏng OWASP API Security Top 10 (Python Flask + SQLite). Đang chạy chế độ `vulnerable=1` với `SECRET_KEY = 'random'`. |
| **Mạng Docker `lab-net`** | Bridge driver nội bộ | Cô lập kết nối giữa Gateway và Backend; cho phép Kong phân giải DNS và gọi đến VAmPI bằng tên container `http://vampi:5000`. |

