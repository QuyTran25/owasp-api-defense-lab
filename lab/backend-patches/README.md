# Backend patch archive - State B

## Mục đích

Thư mục này lưu bản sao `git format-patch` có thể review và áp dụng lại của
các thay đổi backend State B. Patch là artifact mã nguồn, không phải evidence
runtime: không chứa database SQLite, JWT, file `.env.state-b`, runtime Kong
config, password hoặc ảnh chụp màn hình.

Mỗi patch giữ nguyên metadata commit nguồn. Vì vậy reviewer có thể đối chiếu
commit, parent commit, diff từng file và áp dụng lại chính xác bằng `git am`.

## Danh mục patch

| Nhóm vá | Patch | Commit nguồn | Parent | Nội dung chính |
| --- | --- | --- | --- | --- |
| BOLA ownership | `01-bola-ownership.patch` | `b555c3d` | `974b8c3` | Ràng buộc owner trong truy vấn book; cập nhật đặc tả endpoint. |
| ACL, DTO và gỡ debug/reset | `02-acl-data-filtering-debug-removal.patch` | `e0c7037` | `b555c3d` | Access Control Matrix, DB-backed authorization, DTO whitelist, gỡ operation debug/reset. |
| Corrective route retirement | `02b-debug-route-corrective.patch` | `45f83e6` | `e0c7037` | Ngăn `/_debug` khớp nhầm route động và trả `404`. |
| Token lifecycle | `03-token-lifecycle.patch` | `0589868` | `45f83e6` | Migration `token_version`, claim JWT và token invalidation sau đổi mật khẩu. |

> Lưu ý lịch sử: `e0c7037` là commit gộp W3-BACKEND-02 và phần chính
> W3-BACKEND-03. Archive giữ nguyên commit đó để bảo toàn khả năng kiểm tra và
> tránh viết lại lịch sử đã được push. Corrective patch `45f83e6` tách riêng
> vì nó được phát hiện trong retest route `/_debug`.

## Kiểm tra tính toàn vẹn

Hash SHA-256 của các patch nằm trong file `SHA256SUMS` cùng thư mục.

Trên Linux, kiểm tra bằng:

```bash
cd lab/backend-patches
sha256sum -c SHA256SUMS
```

Hoặc đối chiếu từng file bằng `sha256sum *.patch`.

## Review patch

Từ root repository:

```bash
git apply --check lab/backend-patches/01-bola-ownership.patch
git apply --check lab/backend-patches/02-acl-data-filtering-debug-removal.patch
git apply --check lab/backend-patches/02b-debug-route-corrective.patch
git apply --check lab/backend-patches/03-token-lifecycle.patch
```

`git apply --check` chỉ xác nhận patch có thể áp dụng trên base phù hợp; không
thay đổi working tree. Mỗi patch có parent riêng, vì vậy phải review theo thứ
tự danh mục.

## Dựng lại chuỗi patch trong worktree thử nghiệm

Không áp dụng patch trực tiếp trên nhánh `main` đang làm việc. Tạo worktree
hoặc clone thử nghiệm tại parent trước State B, sau đó chạy:

```bash
git am --3way lab/backend-patches/01-bola-ownership.patch
git am --3way lab/backend-patches/02-acl-data-filtering-debug-removal.patch
git am --3way lab/backend-patches/02b-debug-route-corrective.patch
git am --3way lab/backend-patches/03-token-lifecycle.patch
```

Nếu xảy ra conflict khi áp dụng vào một base khác, dùng `git am --abort` để
quay lại trạng thái trước khi áp dụng. Không dùng `git reset --hard` trên
nhánh có công việc chưa commit.

## Rollback trong lịch sử hiện tại

Các thay đổi đã có commit nguồn trên `main`. Khi cần rollback trong một nhánh
riêng, dùng `git revert <commit>` theo commit tương ứng thay vì xóa hoặc sửa
lịch sử đã công bố. Ví dụ, rollback token lifecycle dùng:

```bash
git revert 0589868
```

Sau rollback, phải rebuild VAmPI và chạy lại regression test State B trước khi
triển khai tiếp.
