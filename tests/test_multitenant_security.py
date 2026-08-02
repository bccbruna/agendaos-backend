"""
Regression tests for the IDOR fix: public endpoints must resolve the
tenant via `slug` (looked up server-side), never trust a raw `dono_id`
sent by the client.
"""


def test_public_endpoint_rejects_raw_dono_id(client, signup):
    dono = signup()
    client.post("/servicos", json={"nome": "Corte", "duracao": 30, "preco": 40},
                headers={"Authorization": f"Bearer {dono['token']}"})

    # Sem slug e sem token -> deve recusar, mesmo sabendo o dono_id certo
    res = client.get(f"/servicos?dono_id={dono['dono_id']}")
    assert res.status_code == 400


def test_public_endpoint_accepts_valid_slug(client, signup):
    dono = signup()
    client.post("/servicos", json={"nome": "Corte", "duracao": 30, "preco": 40},
                headers={"Authorization": f"Bearer {dono['token']}"})

    res = client.get(f"/servicos?slug={dono['slug']}")
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_cannot_create_client_in_another_tenant_via_dono_id(client, signup):
    signup()  # vítima, nem precisa ser usada diretamente
    res = client.post("/clientes?dono_id=999999", json={
        "nome": "Invasor", "telefone": "11999999999", "email": "", "tipo": "cliente",
    })
    assert res.status_code == 400


def test_authenticated_admin_endpoints_still_work_without_slug(client, signup):
    dono = signup()
    res = client.get("/servicos", headers={"Authorization": f"Bearer {dono['token']}"})
    assert res.status_code == 200


def test_dono_cannot_see_another_dono_clientes(client, signup):
    dono_a = signup()
    dono_b = signup()

    client.post(f"/clientes?slug={dono_a['slug']}", json={
        "nome": "Cliente A", "telefone": "11911112222", "email": "", "tipo": "cliente",
    })

    res = client.get("/clientes", headers={"Authorization": f"Bearer {dono_b['token']}"})
    assert res.status_code == 200
    assert res.json() == []
