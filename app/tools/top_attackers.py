import datetime
from app.database import repositories

def execute(limit: int = 5, protocol: str = None, start_time: str = None, end_time: str = None) -> dict:
    try:
        limit = int(limit)
        if limit <= 0:
            limit = 5
        elif limit > 100:
            limit = 100
    except (ValueError, TypeError):
        limit = 5
        
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
        data = repositories.get_top_attackers(limit=limit, protocol=protocol, start_time=t_start, end_time=t_end)
        return {
            "status": "success",
            "data": data,
            "summary": f"Retrieved top {len(data)} attacking IP addresses."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database query failed: {str(e)}"
        }
