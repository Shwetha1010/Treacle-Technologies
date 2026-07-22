import ipaddress
from app.database import repositories

def execute(ip: str) -> dict:
    if not ip:
        return {
            "status": "error",
            "message": "IP address parameter is required."
        }
        
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "status": "error",
            "message": f"Invalid IP address format: '{ip}'"
        }
        
    try:
        data = repositories.investigate_ip(ip)
        if data["event_count"] == 0:
            return {
                "status": "success",
                "data": data,
                "summary": f"No security events found for IP address {ip}."
            }
            
        summary = f"IP address {ip} was found in {len(data['tables_involved'])} log sources, with {data['event_count']} total events."
        if data["usernames"]:
            summary += f" Associated usernames: {', '.join(data['usernames'])}."
        if data["protocols_involved"]:
            summary += f" Protocols observed: {', '.join(data['protocols_involved'])}."
            
        return {
            "status": "success",
            "data": data,
            "summary": summary
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database query failed during IP investigation: {str(e)}"
        }
