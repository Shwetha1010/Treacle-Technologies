from app.database import repositories

def execute() -> dict:
    try:
        data = repositories.get_protocol_summary()
        summary = "Security event counts grouped by protocol/source dataset retrieved successfully."
        return {
            "status": "success",
            "data": data,
            "summary": summary
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Database query failed: {str(e)}"
        }
