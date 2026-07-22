import pytest
from unittest.mock import patch
from app.security import authentication

def test_password_hashing():
    password = "SuperSecurePassword123"
    hashed = authentication.hash_password(password)
    assert hashed.startswith("pbkdf2_sha256$")
    assert authentication.verify_password(password, hashed)
    assert not authentication.verify_password("wrong_password", hashed)

@patch("app.database.repositories.get_user_by_username")
@patch("app.database.repositories.register_user")
def test_successful_registration(mock_register, mock_get_user, client):
    # Mock user does not exist
    mock_get_user.return_value = None
    mock_register.return_value = 1
    
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "new_analyst", "password": "securepassword", "role": "analyst"}
    )
    
    assert response.status_code == 201
    assert response.json()["status"] == "success"
    assert response.json()["user_id"] == 1
    
    mock_get_user.assert_called_once_with("new_analyst")
    mock_register.assert_called_once()

@patch("app.database.repositories.get_user_by_username")
def test_registration_duplicate_username(mock_get_user, client):
    # Mock user already exists
    mock_get_user.return_value = {
        "id": 1,
        "username": "existing_analyst",
        "password_hash": "somehash",
        "role": "analyst"
    }
    
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "existing_analyst", "password": "securepassword", "role": "analyst"}
    )
    
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]

@patch("app.database.repositories.get_user_by_username")
def test_successful_login(mock_get_user, client):
    # Hash of "correctpassword"
    pwd_hash = authentication.hash_password("correctpassword")
    mock_get_user.return_value = {
        "id": 5,
        "username": "active_analyst",
        "password_hash": pwd_hash,
        "role": "analyst"
    }
    
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "active_analyst", "password": "correctpassword"}
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "access_token" in response.json()
    assert response.json()["username"] == "active_analyst"
    assert response.json()["role"] == "analyst"

@patch("app.database.repositories.get_user_by_username")
def test_failed_login_wrong_password(mock_get_user, client):
    pwd_hash = authentication.hash_password("correctpassword")
    mock_get_user.return_value = {
        "id": 5,
        "username": "active_analyst",
        "password_hash": pwd_hash,
        "role": "analyst"
    }
    
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "active_analyst", "password": "wrongpassword"}
    )
    
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]
