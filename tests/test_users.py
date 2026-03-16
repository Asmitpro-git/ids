import pytest
from backend import users

def test_add_and_verify_user():
    username = 'testuser'
    password = 'testpass'
    users.add_user(username, password)
    assert users.verify_user(username, password)
    assert not users.verify_user(username, 'wrongpass')

def test_admin_exists():
    assert users.verify_user('admin', 'admin123')
