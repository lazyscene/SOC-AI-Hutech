TOOLS_SCHEMA = []
TOOLS_MAP = {}

def register_tool(schema):
    """Decorator tự động gom Schema và hàm thực thi vào Registry"""
    def decorator(func):
        TOOLS_SCHEMA.append({"type": "function", "function": schema})
        TOOLS_MAP[schema["name"]] = func
        return func
    return decorator

