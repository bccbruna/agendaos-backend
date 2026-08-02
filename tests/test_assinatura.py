"""
Regression tests for subscription gating (trial, soft-lock after expiry).
"""
from datetime import datetime, timedelta

from database import SessionLocal, Usuario


def _expirar_trial(dono_id):
    db = SessionLocal()
    usuario = db.query(Usuario).filter(Usuario.id == dono_id).first()
    usuario.trial_termina_em = datetime.now() - timedelta(days=1)
    db.commit()
    db.close()


def test_new_account_starts_on_active_trial(client, signup):
    dono = signup()
    res = client.get("/assinatura", headers={"Authorization": f"Bearer {dono['token']}"})
    data = res.json()
    assert data["status"] == "trial"
    assert data["ativa"] is True


def test_public_negocio_endpoint_reflects_active_trial(client, signup):
    dono = signup()
    res = client.get(f"/negocio/{dono['slug']}")
    assert res.json()["aceita_agendamentos"] is True


def test_expired_trial_blocks_creating_clients(client, signup):
    dono = signup()
    _expirar_trial(dono["dono_id"])

    res = client.post(f"/clientes?slug={dono['slug']}", json={
        "nome": "Cliente", "telefone": "11933334444", "email": "", "tipo": "cliente",
    })
    assert res.status_code == 402


def test_expired_trial_blocks_creating_servicos(client, signup):
    dono = signup()
    _expirar_trial(dono["dono_id"])

    res = client.post("/servicos", json={"nome": "Corte", "duracao": 30, "preco": 40},
                       headers={"Authorization": f"Bearer {dono['token']}"})
    assert res.status_code == 402


def test_expired_trial_reflected_on_public_negocio_endpoint(client, signup):
    dono = signup()
    _expirar_trial(dono["dono_id"])

    res = client.get(f"/negocio/{dono['slug']}")
    assert res.json()["aceita_agendamentos"] is False


def test_pre_existing_accounts_are_grandfathered_active(db):
    """Contas criadas antes da feature de assinatura (assinatura_status NULL)
    devem ser tratadas como ativas pela migração de compatibilidade.
    Insere via SQL bruto pra simular de verdade uma linha antiga com NULL
    (o ORM aplicaria o default='trial' se passássemos None pelo Usuario())."""
    from sqlalchemy import text
    import main

    db.execute(text(
        "INSERT INTO usuarios (nome_negocio, slug, email, senha, assinatura_status) "
        "VALUES ('Conta Antiga', 'conta-antiga-teste', 'contaantiga@teste.com', 'hash-fake', NULL)"
    ))
    db.commit()

    with main.engine.connect() as conn:
        conn.execute(text("UPDATE usuarios SET assinatura_status = 'ativa' WHERE assinatura_status IS NULL"))
        conn.commit()

    usuario = db.query(Usuario).filter(Usuario.email == "contaantiga@teste.com").first()
    assert usuario.assinatura_status == "ativa"
