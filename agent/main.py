import os
import threading
import time
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from web.routes import router as web_router
from web.state import log_event, load_persistent_state
from watchers.tailers import tail_wazuh
from tools.firewall_tools import sync_pfsense_blocklist

# Import các tools để kích hoạt decorator đăng ký tự động
import tools.firewall_tools
import tools.analysis_tools
import tools.threat_intel_tools
import tools.wazuh_tools


def _periodic_pfsense_sync():
    """Đồng bộ danh sách chặn từ pfSense lúc khởi động và định kỳ mỗi 60 giây."""
    sync_pfsense_blocklist(quiet=False)
    while True:
        time.sleep(60)
        sync_pfsense_blocklist(quiet=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    restored = load_persistent_state()
    log_event("SYSTEM", "Khởi động hệ thống Mini SOC AI Agent (pfSense REST API v2 & Wazuh SIEM)")
    if restored:
        log_event("SYSTEM", "🧠 Đã khôi phục trí nhớ trạng thái hệ thống từ soc_state.json")
    # Đồng bộ trạng thái pfSense SOC_BLOCKLIST ngay khi khởi động và định kỳ 60s
    threading.Thread(target=_periodic_pfsense_sync, daemon=True).start()
    # Khởi chạy luồng theo dõi log Wazuh SIEM
    threading.Thread(target=tail_wazuh, daemon=True).start()
    yield

app = FastAPI(title="AI Agent Mini SOC Visualizer", lifespan=lifespan)
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static")
os.makedirs(_STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
app.include_router(web_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, log_level="warning")
