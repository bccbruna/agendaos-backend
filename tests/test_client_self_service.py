"""
Regression tests for client self-service cancellation - the security
guard must prevent cancelling someone else's appointment just by
guessing the (sequential, easily enumerable) appointment id.
"""
import pytest


@pytest.fixture
def agendamento_criado(client, signup):
    dono = signup()
    res = client.post("/servicos", json={"nome": "Corte", "duracao": 30, "preco": 40},
                       headers={"Authorization": f"Bearer {dono['token']}"})
    servico = res.json()

    res = client.post(f"/clientes?slug={dono['slug']}", json={
        "nome": "Cliente", "telefone": "11955556666", "email": "", "tipo": "cliente",
    })
    cliente = res.json()

    res = client.post(f"/agendamentos?slug={dono['slug']}", json={
        "cliente_id": cliente["id"], "servico": servico["nome"],
        "data": "2027-02-01", "hora": 9, "status": "pending", "obs": "", "preco": 40,
    })
    agendamento = res.json()

    return {**dono, "cliente": cliente, "agendamento": agendamento}


def test_client_can_find_own_upcoming_appointments(client, agendamento_criado):
    res = client.get(
        f"/meus-agendamentos?telefone={agendamento_criado['cliente']['telefone']}&slug={agendamento_criado['slug']}"
    )
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_wrong_phone_number_sees_no_appointments(client, agendamento_criado):
    res = client.get(f"/meus-agendamentos?telefone=11900000000&slug={agendamento_criado['slug']}")
    assert res.json() == []


def test_cancelling_with_wrong_phone_is_rejected(client, agendamento_criado):
    ag_id = agendamento_criado["agendamento"]["id"]
    res = client.put(
        f"/agendamentos/{ag_id}/cancelar-cliente?telefone=11900000000&slug={agendamento_criado['slug']}"
    )
    assert res.status_code == 403


def test_cancelling_with_correct_phone_succeeds(client, agendamento_criado):
    ag_id = agendamento_criado["agendamento"]["id"]
    telefone = agendamento_criado["cliente"]["telefone"]
    res = client.put(
        f"/agendamentos/{ag_id}/cancelar-cliente?telefone={telefone}&slug={agendamento_criado['slug']}"
    )
    assert res.status_code == 200

    # não deve mais aparecer na lista de agendamentos futuros
    res2 = client.get(f"/meus-agendamentos?telefone={telefone}&slug={agendamento_criado['slug']}")
    assert res2.json() == []
