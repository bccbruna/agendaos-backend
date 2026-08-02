import os
os.environ["DB_NAME"] = "agendaos_test"

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import main
from database import Base, engine, SessionLocal


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    main.limiter.reset()
    yield


@pytest.fixture(autouse=True)
def mock_external_requests():
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {}
    with patch("main.requests.post", return_value=resp) as mock_post, \
         patch("main.requests.get", return_value=resp) as mock_get, \
         patch("main.requests.put", return_value=resp) as mock_put:
        yield {"post": mock_post, "get": mock_get, "put": mock_put, "resp": resp}


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def signup(client):
    """Helper: creates a dono account and returns (token, dono_id, slug, email)."""
    counter = {"n": 0}

    def _signup(nome_negocio="Barbearia Teste", senha="senha123456"):
        counter["n"] += 1
        email = f"teste{counter['n']}_{id(counter)}@teste.com"
        res = client.post("/usuarios", json={
            "nome_negocio": nome_negocio, "email": email, "senha": senha,
        })
        data = res.json()
        assert data["ok"], data
        return {"token": data["token"], "dono_id": data["id"], "slug": data["slug"], "email": email}

    return _signup
