from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, get_db, Cliente, Agendamento, Usuario, Servico
from pydantic import BaseModel
from typing import Optional
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta

# ── BCRYPT ────────────────────────────────────────────────────
def hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

def verificar_senha(senha: str, hash: str) -> bool:
    return bcrypt.checkpw(senha.encode(), hash.encode())

# ── JWT ───────────────────────────────────────────────────────
SECRET_KEY = "agendaos-secret-key-2024-mude-em-producao"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

def criar_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token inválido")
    token = authorization.split(" ")[1]
    payload = verificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token expirado ou inválido")
    return payload

# ── APP ───────────────────────────────────────────────────────
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

class ServicoSchema(BaseModel):
    nome: str
    duracao: int
    preco: float
    categoria: Optional[str] = "barber"

@app.get("/horarios-disponiveis")
def horarios_disponiveis(data: str, servico_id: int, db: Session = Depends(get_db)):
    servico = db.query(Servico).filter(Servico.id == servico_id).first()
    if not servico:
        return []
    
    duracao_slots = (servico.duracao + 29) // 30  # quantos slots de 30min ocupa
    agendamentos = db.query(Agendamento).filter(
        Agendamento.data == data,
        Agendamento.status != "cancelled"
    ).all()
    
    # Monta lista de slots ocupados (cada hora tem 2 slots: :00 e :30)
    slots_ocupados = set()
    for ag in agendamentos:
        s = db.query(Servico).filter(Servico.nome == ag.servico).first()
        dur = s.duracao if s else 30
        n_slots = (dur + 29) // 30
        hora = int(ag.hora)
        minuto = 0
        for i in range(n_slots):
            slots_ocupados.add((hora, minuto))
            minuto += 30
            if minuto >= 60:
                minuto = 0
                hora += 1
    
    # Gera horários disponíveis das 8h às 18h em slots de 30min
    horarios = []
    for h in range(8, 19):
        for m in [0, 30]:
            # Verifica se todos os slots necessários estão livres
            disponivel = True
            hora_check = h
            min_check = m
            for i in range(duracao_slots):
                if (hora_check, min_check) in slots_ocupados:
                    disponivel = False
                    break
                min_check += 30
                if min_check >= 60:
                    min_check = 0
                    hora_check += 1
            
            if disponivel and (h < 18 or (h == 18 and m == 0)):
                horarios.append(f"{h:02d}:{m:02d}")
    
    return horarios

# ── CLIENTES ──────────────────────────────────────────────────
@app.get("/clientes")
def listar_clientes(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(Cliente).all()

@app.get("/clientes/buscar")
def buscar_cliente_por_telefone(telefone: str, db: Session = Depends(get_db)):
    cliente = db.query(Cliente).filter(Cliente.telefone == telefone).first()
    return cliente

@app.post("/clientes")
def criar_cliente(c: ClienteSchema, db: Session = Depends(get_db)):
    cliente = Cliente(**c.model_dump())
    db.add(cliente)
    db.commit()
    db.refresh(cliente)
    return cliente

@app.delete("/clientes/{id}")
def deletar_cliente(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    db.query(Agendamento).filter(Agendamento.cliente_id == id).delete()
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
def atualizar_status(id: int, status: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    ag.status = status
    db.commit()
    return ag

@app.delete("/agendamentos/{id}")
def deletar_agendamento(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    ag = db.query(Agendamento).filter(Agendamento.id == id).first()
    db.delete(ag)
    db.commit()
    return {"ok": True}

# ── LOGIN ─────────────────────────────────────────────────────
@app.post("/usuarios")
def criar_usuario(u: CriarUsuarioSchema, db: Session = Depends(get_db)):
    novo = Usuario(
        nome_negocio=u.nome_negocio,
        email=u.email,
        senha=hash_senha(u.senha),
        primeiro_acesso=True
    )
    db.add(novo)
    db.commit()
    db.refresh(novo)
    return {"ok": True, "id": novo.id}

@app.post("/login")
def login(dados: LoginSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario or not verificar_senha(dados.senha, usuario.senha):
        return {"ok": False, "erro": "Email ou senha incorretos"}
    token = criar_token({"sub": usuario.email})
    return {
        "ok": True,
        "token": token,
        "primeiro_acesso": usuario.primeiro_acesso,
        "nome_negocio": usuario.nome_negocio,
        "email": usuario.email
    }

@app.post("/trocar-senha")
def trocar_senha(dados: TrocarSenhaSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario:
        return {"ok": False, "erro": "Usuário não encontrado"}
    if not usuario.primeiro_acesso:
        if not verificar_senha(dados.senha_atual, usuario.senha):
            return {"ok": False, "erro": "Senha atual incorreta"}
    usuario.senha = hash_senha(dados.senha_nova)
    usuario.primeiro_acesso = False
    db.commit()
    return {"ok": True}

# ── SERVIÇOS ──────────────────────────────────────────────────
@app.get("/servicos")
def listar_servicos(db: Session = Depends(get_db)):
    return db.query(Servico).all()

@app.post("/servicos")
def criar_servico(s: ServicoSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = Servico(**s.model_dump())
    db.add(servico)
    db.commit()
    db.refresh(servico)
    return servico

@app.put("/servicos/{id}")
def atualizar_servico(id: int, s: ServicoSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = db.query(Servico).filter(Servico.id == id).first()
    for k, v in s.model_dump().items():
        setattr(servico, k, v)
    db.commit()
    return servico

@app.delete("/servicos/{id}")
def deletar_servico(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = db.query(Servico).filter(Servico.id == id).first()
    db.delete(servico)
    db.commit()
    return {"ok": True}

@app.get("/")
def root():
    return {"status": "AgendaOS API rodando!"}