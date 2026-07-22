import ipaddress
from app.database import repositories

def execute(query_str: str = None, ip: str = None, md5: str = None, filename: str = None, url: str = None, limit: int = 20) -> dict:
    if ip:
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                "status": "error",
                "message": f"Invalid IP address format: '{ip}'"
            }
            
    # Validate md5 length if provided (MD5 is 32 chars hex)
    if md5:
        md5 = md5.strip().lower()
        if len(md5) != 32 or not all(c in '0123456789abcdef' for c in md5):
            return {
                "status": "error",
                "message": "Invalid MD5 hash format."
            }
            
    try:
        limit = int(limit)
        if limit <= 0:
            limit = 20
        elif limit > 100:
            limit = 100
    except (ValueError, TypeError):
        limit = 20
        
    try:
        data = repositories.search_binaries_analytics(
            query_str=query_str, ip=ip, md5=md5, filename=filename, url=url, limit=limit
        )
        return {
            "status": "success",
            "data": data,
            "summary": f"Found {len(data)} matching binary analysis records."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database query failed during binary search: {str(e)}"
        }
