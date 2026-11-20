# Changelog (so với commit `ece381e`)

- **Branch:** `scene`
- **Commit trước:** `ece381e` — `feat(ui): standardize icons to local Lucide bundle and add change.md`
- **Mục tiêu:** Xây dựng module đánh giá độc lập (Alert Triage Benchmark) theo yêu cầu thu thập 200–300 cảnh báo thực tế từ lab Wazuh, đánh giá hiệu quả lọc cảnh báo giả (False Positive Reduction), tỷ lệ bỏ sót cảnh báo thật (Missed True Alerts / FNR), và đo lường thời gian phản hồi (Latency) của AI Agent so với 2 Baseline luật tĩnh Wazuh.
- **Ràng buộc tuân thủ:**
  - **Feature Freeze trên `agent/`:** Tuyệt đối không chỉnh sửa bất kỳ file nào trong thư mục `agent/` (0 files modified).
  - **Ngôn ngữ:** Python thuần (stdlib + `requests`), không cài thêm thư viện/framework AI ngoài.

---

## 1. Cấu trúc thư mục mới `benchmark/`

- `benchmark/common.py`:
  - Trình nạp biến môi trường `.env` bằng Python thuần (không dùng thư viện ngoài).
  - Tự động thiết lập `SOC_DISABLE_STATE_PERSISTENCE=1` để cô lập hoàn toàn trạng thái thực thi khỏi môi trường production/runtime.
  - Bộ phân tích timestamp chuẩn hóa hỗ trợ cả ISO 8601 (`YYYY-MM-DDTHH:MM:SS.sss+0700`, `Z`) lẫn Wazuh legacy format (`YYYY/MM/DD HH:MM:SS`).
  - Hàm chuẩn hóa nhãn `normalize_verdict()` chuyển đổi linh hoạt nhãn từ LLM / controller (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`, `MALICIOUS`, v.v.) về nhãn chuẩn `TRUE_POSITIVE` hoặc `FALSE_POSITIVE`.
  - Bộ tiện ích đọc/ghi JSONL an toàn, hỗ trợ flush và `os.fsync` ghi nhận từng dòng xuống đĩa ngay lập tức.
- `benchmark/extract_alerts.py` (Script 1):
  - Trích xuất cảnh báo từ file `alerts.json` (hoặc copy từ volume `soc-siem`).
  - Tái sử dụng chính xác bộ lọc từ `agent/watchers/tailers.py` (ngưỡng `rule.level >= 6`, nhóm luật an ninh `security_rule_groups`, sự kiện FIM thêm/sửa file có hash sha256/md5, loại trừ noise `agent/controller`).
  - Hỗ trợ lọc theo khung thời gian (`--start`, `--end`) và gán nhãn hàng loạt (`--default-label`, `--scenario`).
  - Cơ chế lấy mẫu đa dạng hóa (`--max-per-rule`, mặc định 12 mẫu/rule) dựa trên tuple đặc trưng `(srcip, syscheck.path, agent.name)` và `full_log`, tránh việc một rule spam áp đảo tập dữ liệu.
  - Hỗ trợ cờ `--append` để gộp nhiều đợt trích xuất (đợt tấn công và đợt hoạt động lành) vào chung một file dữ liệu (`dataset_raw.jsonl`), tự động tăng tiến mã định danh mẫu `BM-XXXX` và loại trùng lặp `alert_id`.
- `benchmark/run_benchmark.py` (Script 2):
  - Replay đánh giá offline tập dữ liệu đã gán nhãn mà không gửi cảnh báo giả lên luồng realtime.
  - **Chế độ Dry-Run an toàn tuyệt đối:** Sử dụng `DryRunSandbox` monkeypatch / mock toàn bộ các hàm SOAR thực thi (`tool_block_firewall_ip`, các hàm gọi pfSense API, Wazuh Active Response API, lưu Case DB). Giả lập phản hồi `[DRY-RUN] Simulated action succeeded` / `Thành công` mà KHÔNG chặn IP thật, KHÔNG gửi lệnh Active Response thật ra hệ thống lab.
  - **Cô lập trạng thái:** Khởi tạo lại `web.state.STATE` và reset `last_alert_time` cho từng mẫu để mỗi cảnh báo được đánh giá độc lập hoàn toàn, không bị ảnh hưởng bởi cooldown/deduplication.
  - **Bảo vệ Rate-limit Threat Intel:** Tận dụng file cache TI riêng biệt của benchmark (`benchmark/data/ti_benchmark_cache.json`). Khi gặp lỗi mạng hoặc 429 Rate Limit từ VirusTotal/AbuseIPDB, tự động gán cờ `ti_rate_limited: true` thay vì làm gián đoạn script.
  - **Checkpoint & Resume:** Ghi kết quả từng mẫu ngay lập tức vào `benchmark/results/predictions_<run_name>.jsonl`. Cho phép resume an toàn khi gặp sự cố, tự động bỏ qua các mẫu đã chạy.
  - Đo thời gian xử lý chính xác đến microsecond bằng `time.perf_counter()`.
- `benchmark/evaluate_report.py` (Script 3):
  - Phân tích và tính toán ma trận nhầm lẫn (Confusion Matrix: TP, FP, TN, FN) kèm thống kê số ca UNKNOWN/ERROR.
  - Tính 3 chỉ số cốt lõi:
    1. **Tỷ lệ giảm cảnh báo giả (False Positive Reduction Rate):** $\text{TN} / (\text{TN} + \text{FP}) \times 100\%$.
    2. **Số lượng & Tỷ lệ bỏ sót cảnh báo thật (Missed True Alerts / FNR):** $\text{FN}$ và $\text{FN} / (\text{TP} + \text{FN}) \times 100\%$.
    3. **Thời gian xử lý mỗi cảnh báo (Latency):** Trung bình (Mean), Trung vị (Median / P50), và Percentile 95 (P95).
  - Bổ sung các chỉ số học máy tiêu chuẩn: Accuracy, Precision, Recall, F1-Score.
  - Đối sánh trực tiếp với 2 Baseline luật tĩnh Wazuh:
    - **Baseline 1 (Wazuh mặc định, rule level >= 6):** Coi tất cả các cảnh báo được sinh ra là True Positive (FP Reduction = 0%, Missed TP = 0%).
    - **Baseline 2 (Wazuh siết ngưỡng cứng, rule level >= 10):** Chỉ coi các cảnh báo có level >= 10 là True Positive, còn lại coi là False Positive để phản ánh sự đánh đổi đánh rơi cảnh báo thật của luật tĩnh.
  - Xuất báo cáo khoa học định dạng Markdown (`benchmark/results/report_<run_name>.md`) chi tiết theo từng kịch bản (`scenario_group`).
  - Xuất file danh sách mẫu AI đoán sai (`benchmark/results/errors_<run_name>.csv`) hỗ trợ phân tích nguyên nhân và tối ưu prompt cho vòng sau.
- `benchmark/README.md`:
  - Tài liệu hướng dẫn đầy đủ quy trình trích xuất cảnh báo từ container `soc-siem`, gán nhãn kiểm chứng thủ công, thực thi dry-run replay và tạo báo cáo tổng hợp.
- `benchmark/data/.gitkeep` & `benchmark/results/.gitkeep`:
  - Thư mục lưu trữ tập dữ liệu và kết quả benchmark.

---

## 2. Kiểm thử tự động (`tests/test_benchmark_pipeline.py`)

- Xây dựng 4 bộ test suite toàn diện kiểm tra toàn bộ luồng benchmark mà không cần gọi API ngoài hay Ollama:
  1. `TestBenchmarkCommon`: Kiểm tra phân tích timestamp, bộ nạp `.env`, hàm chuẩn hóa verdict và ghi JSONL an toàn.
  2. `TestExtractAlerts`: Kiểm tra logic lọc cảnh báo (level, group, FIM), giới hạn đa dạng hóa `--max-per-rule`, và cơ chế append tăng dần ID.
  3. `TestRunBenchmarkDryRun`: Kiểm tra cơ chế DryRunSandbox cô lập hoàn toàn pfSense / Wazuh AR, ghi nhận tools_called, xử lý fallback khi gặp rate-limit TI, và cơ chế checkpoint resume.
  4. `TestEvaluateReport`: Kiểm tra tính toán ma trận nhầm lẫn, các chỉ số FP Reduction, Missed True Alerts, thống kê Latency, tính toán Baseline 1 & 2, và xuất báo cáo Markdown / CSV.
- Kết quả kiểm thử: **32/32 tests PASSED** (toàn bộ 28 test cũ của hệ thống + 4 test suites mới của benchmark).

---

# Changelog các phiên bản trước

## Changelog (so với commit `e37db67`)

- **Branch:** `scene`
- **Commit trước:** `e37db67` — `feat(contingency-room): active controls single source of truth, orphan/drift reconciliation, and safety gate`
- **Mục tiêu:** Chuẩn hóa toàn bộ hệ thống icon giao diện Web SOC sang **Lucide Icons (`lucide@1.73.0`)** lưu cục bộ, thay thế các `<svg>` tự chế và emoji trên UI controls để đảm bảo tính đồng bộ trên mọi hệ điều hành và hoạt động offline.

### 1. File mới thêm

- `agent/web/static/vendor/lucide.min.js`: Bundle UMD `lucide@1.73.0` (`487 KB`, `2,355` icons) phục vụ trực tiếp từ `/static/vendor/lucide.min.js`, không phụ thuộc CDN.

### 2. Core & Khởi tạo Frontend

- `agent/web/static/js/core/utils.js`:
  - Thêm `_toLucidePascalName(name)`, `renderIcon(name, cls, extraAttrs)` để dựng inline `<svg>` trực tiếp từ `window.lucide.icons` cho các vùng DOM cập nhật theo chu kỳ polling `1500ms`.
  - Thêm `initLucideStaticIcons(root)` để hydrate các thẻ `<i data-lucide="...">` tĩnh qua `lucide.createIcons()`.
- `agent/web/static/js/core/shell.js`:
  - Cập nhật `updateThemeButton()` dùng `renderIcon('moon' | 'sun', 'w-3.5 h-3.5')` thay cho emoji `🌙`/`☀️`.
- `agent/web/static/js/app.js`:
  - Gọi `initLucideStaticIcons()` trong `initAppShell()` khi khởi tạo trang.

### 3. Giao diện HTML (`agent/web/templates/index.html`)

- Nạp `<script src="/static/vendor/lucide.min.js"></script>` trước `store.js`.
- Thay thế **11 thẻ `<svg>` tự chế** (logo Sidebar, nút thu gọn/mở menu, 5 mục điều hướng Sidebar, nút menu mobile, kính lúp Global Search, biểu tượng War Room) bằng `<i data-lucide="...">`.
- Thay thế toàn bộ emoji trên các thành phần điều khiển UI:
  - Topbar (`eraser`, `zap`, `#theme-toggle-icon`), Hero buttons (`folder-open`, `siren`), 4 KPI Dashboard (`radio`, `flame`, `check-circle-2`, `shield`), Active Topology (`globe`, `flame`, `search`, `monitor`, `brain`).
  - War Room header & subtabs (`tag`, `plus`, `trash-2`, `x`, `sparkles`, `bar-chart-3`, `message-square`, `scale`, `folder-open`, `inbox`, `bot`, `gavel`).
  - Tiêu đề & ô tìm kiếm Cases / Assets / MISP (`folder-open`, `monitor`, `database`, `refresh-cw`, `link-2`, `search`, `x`), bỏ emoji khỏi `<option>` trong form Decisions.
  - Modal `#modal-confirm-revert` (`triangle-alert`, `x`, `undo-2`).
  - Giữ nguyên biểu đồ sóng hoạt động `#dashboard-wave-svg`.

### 4. Các Module UI (`agent/web/static/js/modules/`)

- `dashboard.js`: Đồng bộ icon nút `Giả Lập Alert` (`loader-2` / `zap`), `Xóa Blocklist` (`loader-2` / `eraser`), danh sách `#st-blocked` (`flame`, `shield`), trạng thái rỗng `#decision-box` (`shield-check`), và các badge MITRE / Threat Intel / Wazuh Active Response (`shield`, `globe`, `shield-alert`).
- `misp.js`: Đồng bộ spinner `loader-2` trên nút `Cập Nhật Feed Từ OSINT` khi đang sync.
- `cases.js`: Đồng bộ icon nút thao tác Case (`link-2`, `unlock`, `lock`, `waypoints`, `refresh-cw`, `scroll-text`, `chevron-up`, `chevron-down`, `siren`), đổi chú thích màu Kill-Chain sang chấm màu Tailwind (`w-2 h-2 rounded-full`), giữ nguyên đồ thị tương tác `renderAttackGraphSvg`.
- `assets.js`: Đồng bộ badge containment (`shield-alert`), cảnh báo orphan (`triangle-alert`), nút liên kết Decision (`link-2`), và các nút `Sửa` (`pencil`), `Xóa` (`trash-2`), `Lưu` (`save`).
- `rooms.js`: Đồng bộ 8 thẻ KPI Board (`unplug`, `scale`, `undo-2`, `clipboard-list`, `shield-alert`, `flame`, `ban`, `crosshair`), thẻ Case trên Board (`building-2`, `user`, `file-text`, `scale`, `x`), nút & banner trạng thái AI (`loader-2`, `bot`, `cpu`), banner cảnh báo Safety Gate (`triangle-alert`, `siren`), và toàn bộ badge/nút trên danh sách Decisions (`clock`, `shield`, `bot`, `refresh-cw`, `triangle-alert`, `hourglass`, `check`, `x`, `rotate-ccw`, `undo-2`).

### 5. Kiểm thử & Xác minh

- Kiểm tra 56 tên icon Lucide sử dụng trong HTML & JS đều tồn tại trong `lucide@1.73.0` (`Missing icons: []`).
- Kiểm tra cú pháp `node --check` cho toàn bộ 9 file JS dưới `agent/web/static/js/`: **Pass**.
- Chạy bộ test `python3 -m unittest discover -s tests -v`: **28/28 tests OK**.
- Kiểm tra HTTP thực tế `GET /` và `GET /static/vendor/lucide.min.js` trả về HTTP `200`.
