import ipaddress
import datetime
from app.database import repositories

def execute(ip: str = None, username: str = None, protocol: str = None, table_name: str = None, start_time: str = None, end_time: str = None, limit: int = 50) -> dict:
    # 1. Validate IP if provided
    if ip:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                "status": "error",
                "message": f"Invalid IP address format: '{ip}'"
            }
            
    # 2. Validate Limit
    try:
        limit = int(limit)
        if limit <= 0:
            limit = 50
        elif limit > 100:
            limit = 100
    except (ValueError, TypeError):
        limit = 50
        
    t_start = None
    t_end = None
    
    if start_time:
        try:
            t_start = datetime.datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        except ValueError:
            pass
            
    if end_time:
        try:
            t_end = datetime.datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        except ValueError:
            pass
            
    try:
        data = repositories.search_security_events(
            ip=ip, username=username, protocol=protocol, table_name=table_name,
            start_time=t_start, end_time=t_end, limit=limit
        )
        return {
            "status": "success",
            "data": data,
            "summary": f"Found {len(data)} matching security events."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database query failed during event search: {str(e)}"
        }
