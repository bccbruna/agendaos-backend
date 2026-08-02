"""
Basic signup/login/JWT tests.
"""


def test_signup_creates_account_and_returns_token(client):
    res = client.post("/usuarios", json={
        "nome_negocio": "Barbearia Signup", "email": "signup_teste@teste.com", "senha": "senha123456",
    })
    data = res.json()
    assert data["ok"] is True
    assert data["token"]
    assert data["slug"] == "barbearia-signup"


def test_signup_rejects_short_password(client):
    res = client.post("/usuarios", json={
        "nome_negocio": "Barbearia X", "email": "curta@teste.com", "senha": "123",
    })
    assert res.json()["ok"] is False


def test_signup_rejects_duplicate_email(client):
    client.post("/usuarios", json={
        "nome_negocio": "Barbearia Dup", "email": "dup@teste.com", "senha": "senha123456",
    })
    res = client.post("/usuarios", json={
        "nome_negocio": "Outra Barbearia", "email": "dup@teste.com", "senha": "senha123456",
    })
    assert res.json()["ok"] is False


def test_login_with_correct_password_succeeds(client):
    client.post("/usuarios", json={
        "nome_negocio": "Barbearia Login", "email": "login_teste@teste.com", "senha": "senha123456",
    })
    res = client.post("/login", json={"email": "login_teste@teste.com", "senha": "senha123456"})
    data = res.json()
    assert data["ok"] is True
    assert data["token"]


def test_login_with_wrong_password_fails(client):
    client.post("/usuarios", json={
        "nome_negocio": "Barbearia Login2", "email": "login_teste2@teste.com", "senha": "senha123456",
    })
    res = client.post("/login", json={"email": "login_teste2@teste.com", "senha": "senhaerrada"})
    assert res.json()["ok"] is False


def test_endpoint_rejects_missing_token(client):
    res = client.get("/clientes")
    assert res.status_code == 401


def test_endpoint_rejects_garbage_token(client):
    res = client.get("/clientes", headers={"Authorization": "Bearer isso-nao-e-um-jwt-valido"})
    assert res.status_code == 401
