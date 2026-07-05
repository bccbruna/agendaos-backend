from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, get_db, Cliente, Agendamento, Usuario, Servico
from pydantic import BaseModel
from typing import Optional

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AgendaOS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# ── SCHEMAS ───────────────────────────────────────────────────
class ClienteSchema(BaseModel):
    nome:     str
    telefone: str
    email:    Optional[str] = ""
    tipo:     Optional[str] = "salon"

class AgendamentoSchema(BaseModel):
    cliente_id: int
    servico:    str
    data:       str
    hora:       int
    status:     Optional[str] = "confirmado"
    obs:        Optional[str] = ""
    preco:      Optional[float] = 0.0

# ── CLIENTES ──────────────────────────────────────────────────
@app.get("/clientes")
def listar_clientes(db: Session = Depends(get_db)):
    return db.query(Cliente).all()

@app.post("/clientes")
def criar_cliente(c: ClienteSchema, db: Session = Depends(get_db)):
    cliente = Cliente(**c.model_dump())
    db.add(cliente)
    db.commit()
    db.refresh(cliente)
    return cliente

@app.delete("/clientes/{id}")
def deletar_cliente(id: int, db: Session = Depends(get_db)):
    cliente = db.query(Cliente).filter(Cliente.id == id).first()
    db.delete(cliente)
    db.commit()
    return {"ok": True}

# ── AGENDAMENTOS ──────────────────────────────────────────────
@app.get("/agendamentos")
def listar_agendamentos(db: Session = Depends(get_db)):
    return db.query(Agendamento).all()

@app.post("/agendamentos")
def criar_agendamento(a: AgendamentoSchema, db: Session = Depends(get_db)):
    agendamento = Agendamento(**a.model_dump())
    db.add(agendamento)
    db.commit()
    db.refresh(agendamento)
    return agendamento

@app.put("/agendamentos/{id}/status")
def atualizar_status(id: int, status: str, db: Session = Depends(get_db)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    ag.status = status
    db.commit()
    return ag

@app.delete("/agendamentos/{id}")
def deletar_agendamento(id: int, db: Session = Depends(get_db)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    db.delete(ag)
    db.commit()
    return {"ok": True}
# ── AGENDAMENTOS ──────────────────────────────────────────────
@app.get("/agendamentos")
def listar_agendamentos(db: Session = Depends(get_db)):
    return db.query(Agendamento).all()

@app.post("/agendamentos")
def criar_agendamento(a: AgendamentoSchema, db: Session = Depends(get_db)):
    agendamento = Agendamento(**a.model_dump())
    db.add(agendamento)
    db.commit()
    db.refresh(agendamento)
    return agendamento

@app.put("/agendamentos/{id}/status")
def atualizar_status(id: int, status: str, db: Session = Depends(get_db)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    ag.status = status
    db.commit()
    return ag

@app.delete("/agendamentos/{id}")
def deletar_agendamento(id: int, db: Session = Depends(get_db)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    db.delete(ag)
    db.commit()
    return {"ok": True}
# ── SCHEMAS DE LOGIN ──────────────────────
class LoginSchema(BaseModel):
    email: str
    senha: str

class CriarUsuarioSchema(BaseModel):
    nome_negocio: str
    email: str
    senha: str

class TrocarSenhaSchema(BaseModel):
    email: str
    senha_atual: str
    senha_nova: str


# ── ROTAS DE LOGIN ────────────────────────
@app.post("/usuarios")
def criar_usuario(u: CriarUsuarioSchema, db: Session = Depends(get_db)):
    novo = Usuario(
        nome_negocio=u.nome_negocio,
        email=u.email,
        senha=u.senha,
        primeiro_acesso=True
    )
    db.add(novo)
    db.commit()
    db.refresh(novo)
    return {"ok": True, "id": novo.id}


@app.post("/login")
def login(dados: LoginSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario or usuario.senha != dados.senha:
        return {"ok": False, "erro": "Email ou senha incorretos"}
    
    return {
        "ok": True,
        "primeiro_acesso": usuario.primeiro_acesso,
        "nome_negocio": usuario.nome_negocio,
        "email": usuario.email
    }


@app.post("/trocar-senha")
def trocar_senha(dados: TrocarSenhaSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario or usuario.senha != dados.senha_atual:
        return {"ok": False, "erro": "Senha atual incorreta"}
    
    usuario.senha = dados.senha_nova
    usuario.primeiro_acesso = False
    db.commit()
    return {"ok": True}
@app.get("/servicos-publicos")
def servicos_publicos(db: Session = Depends(get_db)):
    from database import Agendamento
    # Por enquanto retorna lista fixa — depois conecta com tabela de serviços
    return [
        {"id":1,  "name":"Corte Masculino",     "duration":30,  "price":45},
        {"id":2,  "name":"Barba",               "duration":30,  "price":35},
        {"id":3,  "name":"Corte + Barba",       "duration":60,  "price":75},
        {"id":4,  "name":"Sobrancelha",         "duration":20,  "price":25},
        {"id":5,  "name":"Corte Feminino",      "duration":60,  "price":80},
        {"id":6,  "name":"Escova Progressiva",  "duration":180, "price":350},
    ]
# ── SERVIÇOS ──────────────────────────────────────────────────
class ServicoSchema(BaseModel):
    nome: str
    duracao: int
    preco: float
    categoria: Optional[str] = "barber"

@app.get("/servicos")
def listar_servicos(db: Session = Depends(get_db)):
    return db.query(Servico).all()

@app.post("/servicos")
def criar_servico(s: ServicoSchema, db: Session = Depends(get_db)):
    servico = Servico(**s.model_dump())
    db.add(servico)
    db.commit()
    db.refresh(servico)
    return servico

@app.put("/servicos/{id}")
def atualizar_servico(id: int, s: ServicoSchema, db: Session = Depends(get_db)):
    servico = db.query(Servico).filter(Servico.id == id).first()
    for k, v in s.model_dump().items():
        setattr(servico, k, v)
    db.commit()
    return servico

@app.delete("/servicos/{id}")
def deletar_servico(id: int, db: Session = Depends(get_db)):
    servico = db.query(Servico).filter(Servico.id == id).first()
    db.delete(servico)
    db.commit()
    return {"ok": True}
@app.get("/")
def root():
    return {"status": "AgendaOS API rodando!"}