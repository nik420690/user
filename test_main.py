from fastapi.testclient import TestClient
from main import app  # Import your app from your main file
import pytest
from pydantic import UUID4
from main import User, LoginData

client = TestClient(app)

# Test data
test_user = {
    "username": "test_user",
    "password": "test_password",
    "name": "Test",
    "surname": "User",
    "type": "user"
}

test_login_data = {
    "username": "test_user",
    "password": "test_password"
}

def test_create_user():
    response = client.post("/users/", json=test_user)
    assert response.status_code == 200
    assert response.json()["username"] == "test_user"

def test_get_users():
    response = client.get("/users/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_user_by_id():
    # Here we need an existing user id, for simplicity, I'm using a random UUID.
    user_id = UUID4()
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 404

def test_get_all_users():
    response = client.get("/getusers/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_all_admins():
    response = client.get("/getadmins/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_delete_user():
    # Here we need an existing user id, for simplicity, I'm using a random UUID.
    user_id = UUID4()
    response = client.delete(f"/users/{user_id}")
    assert response.status_code == 404

def test_delete_all_users():
    response = client.delete("/users/")
    assert response.status_code == 200

def test_update_user():
    # Here we need an existing user id, for simplicity, I'm using a random UUID.
    user_id = UUID4()
    response = client.put(f"/users/{user_id}", json=test_user)
    assert response.status_code == 404

def test_login_user():
    response = client.post("/login/", json=test_login_data)
    # Here we assume that the test user is not created, so we expect 401
    assert response.status_code == 401

def test_read_users_me():
    response = client.get("/me/")
    assert response.status_code == 400
