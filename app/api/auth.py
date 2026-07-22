from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from app.security import authentication
from app.database import repositories

router = APIRouter(prefix="/auth", tags=["auth"])

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = Field("analyst", pattern="^(admin|analyst|viewer)$")

class UserLogin(BaseModel):
    username: str
    password: str

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    # Check if user already exists
    existing = repositories.get_user_by_username(user.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )
        
    pwd_hash = authentication.hash_password(user.password)
    try:
        user_id = repositories.register_user(user.username, pwd_hash, user.role)
        return {
            "status": "success",
            "message": "User registered successfully.",
            "user_id": user_id
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/login")
def login(user: UserLogin):
    db_user = repositories.get_user_by_username(user.username)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )
        
    # Verify password hash
    if not authentication.verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )
        
    # Generate token
    token = authentication.create_access_token({
        "sub": db_user["username"],
        "role": db_user["role"]
    })
    
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "username": db_user["username"],
        "role": db_user["role"]
    }
