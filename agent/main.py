import threading
import uvicorn
from fastapi import FastAPI
from web.routes import router as web_router
from web.state import log_event
from watchers.tailers import tail_wazuh, tail_suricata

# Import các tools để kích hoạt decorator đăng ký tự động
import tools.firewall_tools
import tools.analysis_tools

app = FastAPI(title="AI Agent Mini SOC Visualizer")
app.include_router(web_router)

if __name__ == "__main__":
    log_event("SYSTEM", "Khởi động hệ thống Mini SOC AI Agent (Modular Architecture)")
    threading.Thread(target=tail_wazuh, daemon=True).start()
    threading.Thread(target=tail_suricata, daemon=True).start()
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, log_level="warning")

