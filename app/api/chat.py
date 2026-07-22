from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from app.security import authentication
from app.agents import orchestrator

router = APIRouter(prefix="/chat", tags=["chat"])

class QueryRequest(BaseModel):
    query: str

def get_current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header."
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Use 'Bearer <token>'."
        )
    token = authorization.split(" ")[1]
    payload = authentication.decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token."
        )
    return payload

@router.post("")
def chat(payload: QueryRequest, current_user: dict = Depends(get_current_user)):
    if not payload.query or not payload.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query parameter is required and cannot be empty."
        )
        
    try:
        response = orchestrator.run_query(payload.query)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query execution failed: {str(e)}"
        )
