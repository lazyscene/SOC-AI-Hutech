# Changelog (so với commit `e37db67`)

- **Branch:** `scene`
- **Commit trước:** `e37db67` — `feat(contingency-room): active controls single source of truth, orphan/drift reconciliation, and safety gate`
- **Mục tiêu:** Chuẩn hóa toàn bộ hệ thống icon giao diện Web SOC sang **Lucide Icons (`lucide@1.73.0`)** lưu cục bộ, thay thế các `<svg>` tự chế và emoji trên UI controls để đảm bảo tính đồng bộ trên mọi hệ điều hành và hoạt động offline.

---

## 1. File mới thêm

- `agent/web/static/vendor/lucide.min.js`: Bundle UMD `lucide@1.73.0` (`487 KB`, `2,355` icons) phục vụ trực tiếp từ `/static/vendor/lucide.min.js`, không phụ thuộc CDN.

## 2. Core & Khởi tạo Frontend

- `agent/web/static/js/core/utils.js`:
  - Thêm `_toLucidePascalName(name)`, `renderIcon(name, cls, extraAttrs)` để dựng inline `<svg>` trực tiếp từ `window.lucide.icons` cho các vùng DOM cập nhật theo chu kỳ polling `1500ms`.
  - Thêm `initLucideStaticIcons(root)` để hydrate các thẻ `<i data-lucide="...">` tĩnh qua `lucide.createIcons()`.
- `agent/web/static/js/core/shell.js`:
  - Cập nhật `updateThemeButton()` dùng `renderIcon('moon' | 'sun', 'w-3.5 h-3.5')` thay cho emoji `🌙`/`☀️`.
- `agent/web/static/js/app.js`:
  - Gọi `initLucideStaticIcons()` trong `initAppShell()` khi khởi tạo trang.

## 3. Giao diện HTML (`agent/web/templates/index.html`)

- Nạp `<script src="/static/vendor/lucide.min.js"></script>` trước `store.js`.
- Thay thế **11 thẻ `<svg>` tự chế** (logo Sidebar, nút thu gọn/mở menu, 5 mục điều hướng Sidebar, nút menu mobile, kính lúp Global Search, biểu tượng War Room) bằng `<i data-lucide="...">`.
- Thay thế toàn bộ emoji trên các thành phần điều khiển UI:
  - Topbar (`eraser`, `zap`, `#theme-toggle-icon`), Hero buttons (`folder-open`, `siren`), 4 KPI Dashboard (`radio`, `flame`, `check-circle-2`, `shield`), Active Topology (`globe`, `flame`, `search`, `monitor`, `brain`).
  - War Room header & subtabs (`tag`, `plus`, `trash-2`, `x`, `sparkles`, `bar-chart-3`, `message-square`, `scale`, `folder-open`, `inbox`, `bot`, `gavel`).
  - Tiêu đề & ô tìm kiếm Cases / Assets / MISP (`folder-open`, `monitor`, `database`, `refresh-cw`, `link-2`, `search`, `x`), bỏ emoji khỏi `<option>` trong form Decisions.
  - Modal `#modal-confirm-revert` (`triangle-alert`, `x`, `undo-2`).
- Giữ nguyên biểu đồ sóng hoạt động `#dashboard-wave-svg`.

## 4. Các Module UI (`agent/web/static/js/modules/`)

- `dashboard.js`: Đồng bộ icon nút `Giả Lập Alert` (`loader-2` / `zap`), `Xóa Blocklist` (`loader-2` / `eraser`), danh sách `#st-blocked` (`flame`, `shield`), trạng thái rỗng `#decision-box` (`shield-check`), và các badge MITRE / Threat Intel / Wazuh Active Response (`shield`, `globe`, `shield-alert`).
- `misp.js`: Đồng bộ spinner `loader-2` trên nút `Cập Nhật Feed Từ OSINT` khi đang sync.
- `cases.js`: Đồng bộ icon nút thao tác Case (`link-2`, `unlock`, `lock`, `waypoints`, `refresh-cw`, `scroll-text`, `chevron-up`, `chevron-down`, `siren`), đổi chú thích màu Kill-Chain sang chấm màu Tailwind (`w-2 h-2 rounded-full`), giữ nguyên đồ thị tương tác `renderAttackGraphSvg`.
- `assets.js`: Đồng bộ badge containment (`shield-alert`), cảnh báo orphan (`triangle-alert`), nút liên kết Decision (`link-2`), và các nút `Sửa` (`pencil`), `Xóa` (`trash-2`), `Lưu` (`save`).
- `rooms.js`: Đồng bộ 8 thẻ KPI Board (`unplug`, `scale`, `undo-2`, `clipboard-list`, `shield-alert`, `flame`, `ban`, `crosshair`), thẻ Case trên Board (`building-2`, `user`, `file-text`, `scale`, `x`), nút & banner trạng thái AI (`loader-2`, `bot`, `cpu`), banner cảnh báo Safety Gate (`triangle-alert`, `siren`), và toàn bộ badge/nút trên danh sách Decisions (`clock`, `shield`, `bot`, `refresh-cw`, `triangle-alert`, `hourglass`, `check`, `x`, `rotate-ccw`, `undo-2`).

## 5. Kiểm thử & Xác minh

- Kiểm tra 56 tên icon Lucide sử dụng trong HTML & JS đều tồn tại trong `lucide@1.73.0` (`Missing icons: []`).
- Kiểm tra cú pháp `node --check` cho toàn bộ 9 file JS dưới `agent/web/static/js/`: **Pass**.
- Chạy bộ test `python3 -m unittest discover -s tests -v`: **28/28 tests OK**.
- Kiểm tra HTTP thực tế `GET /` và `GET /static/vendor/lucide.min.js` trả về HTTP `200`.
