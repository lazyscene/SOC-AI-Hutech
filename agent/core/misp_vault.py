import os
import json
import sqlite3
import datetime
import requests
from typing import Optional, List, Dict, Any, Tuple
from web.state import log_event

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "misp_vault.db")
LEGACY_JSON_PATH = os.path.join(DATA_DIR, "misp_iocs.json")

def get_db_connection() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_misp_vault():
    """Khởi tạo cấu trúc bảng SQLite và seed dữ liệu ban đầu từ file JSON nếu database trống"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                threat_name TEXT,
                source TEXT DEFAULT 'Lab Custom',
                confidence TEXT DEFAULT 'High',
                updated_at TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);")
        conn.commit()

        # Kiểm tra nếu DB chưa có dữ liệu thì nạp dữ liệu ban đầu từ misp_iocs.json
        cursor.execute("SELECT COUNT(*) as count FROM iocs;")
        row = cursor.fetchone()
        if row and row["count"] == 0 and os.path.exists(LEGACY_JSON_PATH):
            try:
                with open(LEGACY_JSON_PATH, "r", encoding="utf-8") as f:
                    legacy_iocs = json.load(f)
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                seed_data = []
                for item in legacy_iocs:
                    val = str(item.get("value", "")).strip()
                    if val:
                        itype = item.get("type", "ip")
                        if itype == "ip-src":
                            itype = "ip"
                        seed_data.append((
                            val,
                            itype,
                            item.get("comment", "Lab Custom IOC"),
                            "Lab Custom",
                            item.get("threat_level", "High"),
                            item.get("date", now_str)
                        ))
                if seed_data:
                    cursor.executemany("""
                        INSERT OR IGNORE INTO iocs (indicator, type, threat_name, source, confidence, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                    """, seed_data)
                    conn.commit()
                    log_event("SYSTEM", f"Đã nạp {len(seed_data)} IOCs phòng Lab ban đầu vào SQLite misp_vault.db")
            except Exception as e:
                log_event("ERROR", f"Lỗi seed dữ liệu từ misp_iocs.json: {e}")

init_misp_vault()

def query_ioc_vault(indicator: str) -> Optional[Dict[str, Any]]:
    """
    Tra cứu siêu nhanh chỉ số xâm phạm (IOC) trong kho dữ liệu SQLite misp_vault.db.
    Đảm bảo so sánh chuẩn xác tuyệt đối cho IP, Hash, CVE và khớp subdomain cho domain.
    """
    if not indicator:
        return None
    clean = indicator.strip()
    if not clean:
        return None

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # 1. Truy vấn khớp chính xác hoàn toàn (cho IP, Hash, CVE, URL, Domain)
            cursor.execute("""
                SELECT id, indicator, type, threat_name, source, confidence, updated_at
                FROM iocs
                WHERE indicator = ? COLLATE NOCASE
                LIMIT 1;
            """, (clean,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": f"IOC-{row['id']:04d}",
                    "type": row["type"],
                    "value": row["indicator"],
                    "threat_level": row["confidence"],
                    "comment": f"[{row['source']}] {row['threat_name']}",
                    "source": row["source"],
                    "threat_name": row["threat_name"],
                    "date": row["updated_at"]
                }

            # 2. Nếu là domain, kiểm tra xem có khớp subdomain của domain độc hại không
            if "." in clean and not clean.replace(".", "").isdigit():
                cursor.execute("""
                    SELECT id, indicator, type, threat_name, source, confidence, updated_at
                    FROM iocs
                    WHERE type = 'domain' AND ? LIKE '%.' || indicator
                    LIMIT 1;
                """, (clean.lower(),))
                row = cursor.fetchone()
                if row:
                    return {
                        "id": f"IOC-{row['id']:04d}",
                        "type": row["type"],
                        "value": row["indicator"],
                        "threat_level": row["confidence"],
                        "comment": f"[{row['source']}] Subdomain của {row['indicator']}: {row['threat_name']}",
                        "source": row["source"],
                        "threat_name": row["threat_name"],
                        "date": row["updated_at"]
                    }
    except Exception as e:
        log_event("ERROR", f"Lỗi truy vấn misp_vault.db: {e}")

    return None

def add_ioc_record(indicator: str, ioc_type: str, threat_name: str, source: str = "Lab Custom", confidence: str = "High") -> Dict[str, Any]:
    """Thêm hoặc cập nhật một IOC vào SQLite misp_vault.db"""
    clean_val = indicator.strip()
    clean_type = ioc_type.strip().lower()
    if clean_type == "ip-src":
        clean_type = "ip"
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO iocs (indicator, type, threat_name, source, confidence, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                type = excluded.type,
                threat_name = excluded.threat_name,
                source = excluded.source,
                confidence = excluded.confidence,
                updated_at = excluded.updated_at;
        """, (clean_val, clean_type, threat_name.strip(), source, confidence, now_str))
        conn.commit()
        last_id = cursor.lastrowid

    log_event("MISP", f"Đã lưu IOC vào SQLite vault: [{clean_type}] {clean_val} ({source})")
    return {
        "id": f"IOC-{last_id:04d}",
        "type": clean_type,
        "value": clean_val,
        "threat_level": confidence,
        "comment": f"[{source}] {threat_name}",
        "source": source,
        "date": now_str
    }

def get_ioc_records(limit: int = 100, offset: int = 0, search: str = "") -> Tuple[List[Dict[str, Any]], int]:
    """Lấy danh sách IOCs và tổng số lượng phục vụ hiển thị trên giao diện Web"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if search:
            q = f"%{search.strip()}%"
            cursor.execute("SELECT COUNT(*) as count FROM iocs WHERE indicator LIKE ? OR threat_name LIKE ?;", (q, q))
            total = cursor.fetchone()["count"]
            cursor.execute("""
                SELECT id, indicator, type, threat_name, source, confidence, updated_at
                FROM iocs
                WHERE indicator LIKE ? OR threat_name LIKE ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?;
            """, (q, q, limit, offset))
        else:
            cursor.execute("SELECT COUNT(*) as count FROM iocs;")
            total = cursor.fetchone()["count"]
            cursor.execute("""
                SELECT id, indicator, type, threat_name, source, confidence, updated_at
                FROM iocs
                ORDER BY id DESC
                LIMIT ? OFFSET ?;
            """, (limit, offset))

        rows = cursor.fetchall()
        results = []
        for r in rows:
            results.append({
                "id": f"IOC-{r['id']:04d}",
                "type": r["type"],
                "value": r["indicator"],
                "threat_level": r["confidence"],
                "comment": f"[{r['source']}] {r['threat_name']}",
                "source": r["source"],
                "threat_name": r["threat_name"],
                "date": r["updated_at"]
            })
        return results, total

def fetch_open_misp_feeds() -> Dict[str, Any]:
    """
    Tự động kéo dữ liệu từ các nguồn Threat Feed công khai miễn phí chuẩn MISP/OSINT:
    1. Feodo Tracker (Botnet C2 IPs)
    2. URLhaus (Malware URLs / Domains / Online IPs)
    3. Ipsum High-Confidence Threat Feed
    Lưu trữ đồng loạt hàng nghìn records vào SQLite misp_vault.db.
    """
    log_event("MISP", "Bắt đầu đồng bộ Threat Feeds từ OSINT công khai...")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ingested_records = []
    sources_synced = []

    headers = {"User-Agent": "Mini-SOC-AI-Agent-OSINT/2.0"}

    # -------------------------------------------------------------
    # FEED 1: Feodo Tracker (Botnet C2 IPs) - JSON
    # -------------------------------------------------------------
    try:
        feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        res = requests.get(feodo_url, headers=headers, timeout=12)
        if res.status_code == 200:
            data = res.json()
            count = 0
            for item in data:
                ip = item.get("ip_address")
                if ip:
                    malware = item.get("malware", "Botnet C2")
                    ingested_records.append((
                        ip.strip(),
                        "ip",
                        f"Feodo C2 ({malware})",
                        "Feodo Tracker",
                        "High",
                        now_str
                    ))
                    count += 1
            sources_synced.append(f"Feodo Tracker ({count} C2 IPs)")
            log_event("MISP", f"Feodo Tracker: Đã tải {count} Botnet C2 IPs.")
    except Exception as e:
        log_event("ERROR", f"Lỗi tải Feodo Tracker: {e}")

    # -------------------------------------------------------------
    # FEED 2: URLhaus (Malware URLs & Online Malicious Hosts)
    # -------------------------------------------------------------
    try:
        urlhaus_loaded = 0
        # Thử endpoint chính của URLhaus
        urlhaus_api = "https://urlhaus.abuse.ch/downloads/json_recent/"
        res = requests.get(urlhaus_api, headers=headers, timeout=8)
        if res.status_code == 200:
            try:
                data = res.json()
                for url, details in data.items():
                    if isinstance(details, dict):
                        ingested_records.append((
                            url.strip(),
                            "url",
                            f"URLhaus ({details.get('threat', 'malware')})",
                            "URLhaus",
                            "High",
                            now_str
                        ))
                        urlhaus_loaded += 1
            except Exception:
                pass

        # Fallback tự động sang Mirror chính thức mở của URLhaus nếu endpoint chính 410/đổi chính sách
        if urlhaus_loaded == 0:
            mirror_url = "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-online.txt"
            res = requests.get(mirror_url, headers=headers, timeout=12)
            if res.status_code == 200:
                for line in res.text.splitlines()[:5000]:
                    line = line.strip()
                    if line and not line.startswith("!") and not line.startswith("#"):
                        itype = "ip" if (line.replace(".", "").isdigit() and line.count(".") == 3) else "domain"
                        ingested_records.append((
                            line,
                            itype,
                            "URLhaus Active Malware Host",
                            "URLhaus",
                            "High",
                            now_str
                        ))
                        urlhaus_loaded += 1

        sources_synced.append(f"URLhaus ({urlhaus_loaded} IOCs)")
        log_event("MISP", f"URLhaus: Đã nạp {urlhaus_loaded} chỉ số mã độc.")
    except Exception as e:
        log_event("ERROR", f"Lỗi tải URLhaus Feed: {e}")

    # -------------------------------------------------------------
    # FEED 3: Ipsum OSINT High-Confidence Attacker IP Feed (Level 2+)
    # -------------------------------------------------------------
    try:
        ipsum_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"
        res = requests.get(ipsum_url, headers=headers, timeout=10)
        if res.status_code == 200:
            ipsum_count = 0
            for line in res.text.splitlines()[:4000]:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    ip_val = parts[0].strip()
                    ingested_records.append((
                        ip_val,
                        "ip",
                        "High Reputation Blacklist IP",
                        "Ipsum Threat Feed",
                        "High",
                        now_str
                    ))
                    ipsum_count += 1
            sources_synced.append(f"Ipsum Feed ({ipsum_count} Malicious IPs)")
            log_event("MISP", f"Ipsum Feed: Đã nạp {ipsum_count} IP nguy hiểm cao.")
    except Exception as e:
        log_event("ERROR", f"Lỗi tải Ipsum Feed: {e}")

    # -------------------------------------------------------------
    # BATCH INSERT VÀO SQLITE DATABASE
    # -------------------------------------------------------------
    total_added = len(ingested_records)
    total_in_db = 0
    if ingested_records:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO iocs (indicator, type, threat_name, source, confidence, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    type = excluded.type,
                    threat_name = excluded.threat_name,
                    source = excluded.source,
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at;
            """, ingested_records)
            conn.commit()
            cursor.execute("SELECT COUNT(*) as count FROM iocs;")
            total_in_db = cursor.fetchone()["count"]

    log_event("MISP", f"Hoàn tất đồng bộ! Đã nạp {total_added} records. Tổng số IOCs hiện tại trong SQLite: {total_in_db}")
    return {
        "status": "success",
        "total_in_db": total_in_db,
        "added_or_updated": total_added,
        "sources": sources_synced
    }

