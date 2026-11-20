# Module Benchmark Phân Loại Cảnh Báo (`benchmark/`)

Bộ công cụ đánh giá hiệu quả lọc cảnh báo giả (**False Positive Reduction**), tỷ lệ bỏ sót (**Missed True Alerts / FNR**) và thời gian xử lý (**Latency**) của AI Agent trên dữ liệu cảnh báo thực tế từ lab Wazuh, hoàn toàn **độc lập với luồng realtime** và chạy chế độ **Dry-Run an toàn tuyệt đối**.

## Cấu trúc thư mục

- `benchmark/extract_alerts.py` — Trích xuất & lấy mẫu đa dạng từ `alerts.json` (theo đúng ngưỡng lọc của `agent/watchers/tailers.py`).
- `benchmark/run_benchmark.py` — Replay qua `tailers.py` + `controller.py` ở chế độ **Dry-Run** (mock pfSense, Wazuh AR, tắt ghi đè `soc_state.json`/`ti_cache.json`, hỗ trợ Checkpoint/Resume).
- `benchmark/evaluate_report.py` — Tổng hợp Confusion Matrix, 3 chỉ số chính, đối sánh Baseline Wazuh mặc định & siết ngưỡng, xuất Markdown report và file CSV phân tích lỗi.
- `benchmark/data/` — Chứa file `alerts.json` copy ra từ volume Wazuh và dataset `.jsonl`.
- `benchmark/results/` — Chứa `predictions_<run>.jsonl`, `report_<run>.md`, `errors_<run>.csv`.

---

## Quy trình thu thập & chạy đánh giá (200–300 cảnh báo)

### Bước 1: Copy `alerts.json` từ container Wazuh
```bash
docker cp soc-siem:/var/ossec/logs/alerts/alerts.json benchmark/data/alerts.json
```

### Bước 2: Trích xuất theo từng đợt kịch bản (nối chung vào `dataset_raw.jsonl`)
Chạy tách từng khung giờ sạch trong lab để gán nhãn mặc định và giữ đa dạng rule (`--max-per-rule 12`):

```bash
# Đợt 1a: Hoạt động quản trị lành tính (SSH admin, apt update, dịch vụ hợp lệ...)
python3 benchmark/extract_alerts.py \
  --input benchmark/data/alerts.json \
  --start "2026-11-20 08:00:00" \
  --end "2026-11-20 09:00:00" \
  --default-label FALSE_POSITIVE \
  --scenario benign_admin \
  --max-per-rule 12 \
  --output benchmark/data/dataset_raw.jsonl

# Đợt 1b: Nhiễu CIS Benchmark / SCA / Rule dễ nổ nhầm
python3 benchmark/extract_alerts.py \
  --input benchmark/data/alerts.json \
  --start "2026-11-20 09:00:00" \
  --end "2026-11-20 10:00:00" \
  --default-label FALSE_POSITIVE \
  --scenario benign_cis \
  --max-per-rule 12 \
  --output benchmark/data/dataset_raw.jsonl \
  --append

# Đợt 2a: Tấn công Nmap / Brute-force / Web Attack từ Kali
python3 benchmark/extract_alerts.py \
  --input benchmark/data/alerts.json \
  --start "2026-11-20 10:00:00" \
  --end "2026-11-20 10:45:00" \
  --default-label TRUE_POSITIVE \
  --scenario attack_nmap \
  --max-per-rule 12 \
  --output benchmark/data/dataset_raw.jsonl \
  --append

# Đợt 2b: EICAR / FIM & Sysmon PowerShell độc hại trên Endpoint
python3 benchmark/extract_alerts.py \
  --input benchmark/data/alerts.json \
  --start "2026-11-20 10:45:00" \
  --end "2026-11-20 11:30:00" \
  --default-label TRUE_POSITIVE \
  --scenario attack_fim_eicar \
  --max-per-rule 12 \
  --output benchmark/data/dataset_raw.jsonl \
  --append
```

### Bước 3: Tự rà soát & gán nhãn tay (Human Ground-Truth Verification)
Copy `benchmark/data/dataset_raw.jsonl` sang `benchmark/data/dataset_labeled.jsonl`, rà lại từng dòng (đặc biệt những cảnh báo nhiễu lọt vào khung giờ tấn công hoặc ngược lại), chỉnh lại `"ground_truth"` (`"TRUE_POSITIVE"` / `"FALSE_POSITIVE"`) nếu cần và đổi `"label_verified": true`.

### Bước 4: Chạy Offline Replay Benchmark (Dry-Run)
```bash
# Chạy toàn bộ tập đã rà nhãn (có thể thêm --only-verified hoặc --limit 20 để test trước)
python3 benchmark/run_benchmark.py \
  --input benchmark/data/dataset_labeled.jsonl \
  --run-name v1_qwen35 \
  --only-verified
```

Nếu quá trình chạy bị ngắt giữa chừng (hoặc có mẫu `ERROR` do Ollama timeout), chạy lại đúng `--run-name` cũ (thêm `--retry-errors` để đánh giá lại các ca lỗi):
```bash
python3 benchmark/run_benchmark.py \
  --input benchmark/data/dataset_labeled.jsonl \
  --run-name v1_qwen35 \
  --only-verified \
  --retry-errors
```

### Bước 5: Tổng hợp 3 chỉ số & Xuất báo cáo so sánh Baseline
```bash
python3 benchmark/evaluate_report.py \
  --input benchmark/results/predictions_v1_qwen35.jsonl \
  --dataset benchmark/data/dataset_labeled.jsonl
```

Kết quả đầu ra:
- `benchmark/results/report_v1_qwen35.md` — Bảng 3 chỉ số chính, đối sánh Baseline Wazuh mặc định (`>= 6`) & siết ngưỡng (`>= 10`), Confusion Matrix, phân rã theo `scenario_group`.
- `benchmark/results/errors_v1_qwen35.csv` — Danh sách riêng các ca `FN`, `FP`, `UNKNOWN`, `ERROR` mở trực tiếp trên Excel để phân tích lỗi cho Vòng 2.
