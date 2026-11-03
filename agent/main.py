import threading
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from web.routes import router as web_router
from web.state import log_event
from watchers.tailers import tail_wazuh

# Import các tools để kích hoạt decorator đăng ký tự động
import tools.firewall_tools
import tools.analysis_tools
import tools.threat_intel_tools

@asynccontextmanager
async def lifespan(app: FastAPI):
    log_event("SYSTEM", "Khởi động hệ thống Mini SOC AI Agent (pfSense REST API v2 & Wazuh SIEM)")
    # Khởi chạy luồng theo dõi log Wazuh SIEM
    t = threading.Thread(target=tail_wazuh, daemon=True)
    t.start()
    yield

app = FastAPI(title="AI Agent Mini SOC Visualizer", lifespan=lifespan)
app.include_router(web_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, log_level="warning")
