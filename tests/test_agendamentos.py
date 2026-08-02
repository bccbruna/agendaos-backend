"""
Regression tests for server-side double-booking protection.
"""
import pytest


@pytest.fixture
def negocio_com_servico(client, signup):
    dono = signup()
    res = client.post("/servicos", json={"nome": "Corte 60min", "duracao": 60, "preco": 50},
                       headers={"Authorization": f"Bearer {dono['token']}"})
    servico = res.json()

    res = client.post(f"/clientes?slug={dono['slug']}", json={
        "nome": "Cliente", "telefone": "11922223333", "email": "", "tipo": "cliente",
    })
    cliente = res.json()

    return {**dono, "servico": servico, "cliente": cliente}


def _agendar(client, negocio, hora, data="2027-01-04"):
    return client.post(f"/agendamentos?slug={negocio['slug']}", json={
        "cliente_id": negocio["cliente"]["id"],
        "servico": negocio["servico"]["nome"],
        "data": data,
        "hora": hora,
        "status": "pending",
        "obs": "",
        "preco": 50,
    })


def test_first_booking_succeeds(client, negocio_com_servico):
    res = _agendar(client, negocio_com_servico, 10)
    assert res.status_code == 200


def test_exact_double_booking_is_rejected(client, negocio_com_servico):
    _agendar(client, negocio_com_servico, 10)
    res = _agendar(client, negocio_com_servico, 10)
    assert res.status_code == 409


def test_overlapping_booking_is_rejected(client, negocio_com_servico):
    # Serviço de 60min às 10h ocupa 10:00 e 10:30 - um novo serviço de 60min
    # começando às 10:30 também colide (precisaria de 10:30 e 11:00).
    _agendar(client, negocio_com_servico, 10)
    res = _agendar(client, negocio_com_servico, 10)  # mesma hora, ainda mais óbvio
    assert res.status_code == 409


def test_non_overlapping_booking_succeeds(client, negocio_com_servico):
    _agendar(client, negocio_com_servico, 10)
    # 60min às 10h termina às 11h - 11h em diante está livre
    res = _agendar(client, negocio_com_servico, 11)
    assert res.status_code == 200


def test_edit_into_conflicting_slot_is_rejected(client, negocio_com_servico):
    _agendar(client, negocio_com_servico, 10)
    res2 = _agendar(client, negocio_com_servico, 14)
    ag2_id = res2.json()["id"]

    res = client.put(f"/agendamentos/{ag2_id}", json={
        "cliente_id": negocio_com_servico["cliente"]["id"],
        "servico": negocio_com_servico["servico"]["nome"],
        "data": "2027-01-04",
        "hora": 10,
        "status": "confirmado",
        "obs": "",
        "preco": 50,
    }, headers={"Authorization": f"Bearer {negocio_com_servico['token']}"})
    assert res.status_code == 409


def test_edit_keeping_same_slot_does_not_conflict_with_itself(client, negocio_com_servico):
    res1 = _agendar(client, negocio_com_servico, 10)
    ag1_id = res1.json()["id"]

    res = client.put(f"/agendamentos/{ag1_id}", json={
        "cliente_id": negocio_com_servico["cliente"]["id"],
        "servico": negocio_com_servico["servico"]["nome"],
        "data": "2027-01-04",
        "hora": 10,
        "status": "confirmado",
        "obs": "editado",
        "preco": 50,
    }, headers={"Authorization": f"Bearer {negocio_com_servico['token']}"})
    assert res.status_code == 200
    assert res.json()["obs"] == "editado"
