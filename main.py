from fastapi import FastAPI, Depends, Header, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import engine, Base, get_db, Cliente, Agendamento, Usuario, Servico
from pydantic import BaseModel
from typing import Optional
import bcrypt
import os
import secrets
import requests
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

# ── EMAIL (recuperação de senha) ───────────────────────────────
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
EMAIL_REMETENTE = os.environ.get("EMAIL_REMETENTE", "naoresponda.agendaos@gmail.com")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://agendaos-frontend.vercel.app")

def enviar_email_recuperacao(destinatario: str, token: str):
    link = f"{FRONTEND_URL}/redefinir-senha?token={token}"
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; background:#08090F; padding:32px; color:#F0F0F8;">
    <div style="max-width:420px; margin:0 auto; background:#131620; border-radius:16px; padding:32px; border:1px solid rgba(255,255,255,0.07);">
      <h2 style="margin:0 0 16px; font-size:20px;">Agenda<span style="color:#A855F7;">OS</span></h2>
      <p style="font-size:14px; line-height:1.6; color:rgba(240,240,248,0.7);">Olá!</p>
      <p style="font-size:14px; line-height:1.6; color:rgba(240,240,248,0.7);">
        Recebemos um pedido para redefinir sua senha. Clique no botão abaixo para criar uma nova senha (válido por 1 hora):
      </p>
      <p style="text-align:center; margin:28px 0;">
        <a href="{link}" style="background:linear-gradient(135deg,#A855F7,#7C3AED); color:#fff; padding:12px 28px;
          border-radius:10px; text-decoration:none; font-weight:bold; font-size:14px; display:inline-block;">
          Redefinir minha senha
        </a>
      </p>
      <p style="font-size:12px; color:rgba(240,240,248,0.44); word-break:break-all;">
        Ou copie e cole este link no navegador:<br>{link}
      </p>
      <p style="font-size:12px; color:rgba(240,240,248,0.44); margin-top:20px;">
        Se você não pediu isso, pode ignorar este email.
      </p>
    </div>
  </body>
</html>
"""
    texto = (
        "Olá!\n\n"
        "Recebemos um pedido para redefinir sua senha no AgendaOS.\n\n"
        f"Clique no link abaixo para criar uma nova senha (válido por 1 hora):\n{link}\n\n"
        "Se você não pediu isso, pode ignorar este email."
    )
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "personalizations": [{"to": [{"email": destinatario}]}],
            "from": {"email": EMAIL_REMETENTE, "name": "AgendaOS"},
            "subject": "Recuperação de senha - AgendaOS",
            "content": [
                {"type": "text/plain", "value": texto},
                {"type": "text/html", "value": html},
            ],
        },
        timeout=10,
    )
    resp.raise_for_status()

# ── APP ───────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# create_all não altera tabelas já existentes; garante as colunas de reset em produção
def garantir_colunas_reset_senha():
    with engine.connect() as conn:
        for coluna, tipo in [("reset_token", "VARCHAR(255)"), ("reset_token_expira", "DATETIME")]:
            try:
                conn.execute(text(f"ALTER TABLE usuarios ADD COLUMN {coluna} {tipo} NULL"))
                conn.commit()
            except Exception:
                pass  # coluna já existe

garantir_colunas_reset_senha()

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

class EsqueciSenhaSchema(BaseModel):
    email: str

class RedefinirSenhaSchema(BaseModel):
    token: str
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

def enviar_email_recuperacao_seguro(destinatario: str, token: str):
    try:
        enviar_email_recuperacao(destinatario, token)
    except Exception as e:
        print("Erro ao enviar email de recuperação:", e)

@app.post("/esqueci-senha")
def esqueci_senha(dados: EsqueciSenhaSchema, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if usuario:
        token = secrets.token_urlsafe(32)
        usuario.reset_token = token
        usuario.reset_token_expira = datetime.now() + timedelta(hours=1)
        db.commit()
        background_tasks.add_task(enviar_email_recuperacao_seguro, usuario.email, token)
    # Sempre retorna ok, mesmo se o email não existir (evita revelar quais emails estão cadastrados)
    return {"ok": True}

@app.post("/redefinir-senha")
def redefinir_senha(dados: RedefinirSenhaSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.reset_token == dados.token).first()
    if not usuario or not usuario.reset_token_expira or usuario.reset_token_expira < datetime.now():
        return {"ok": False, "erro": "Link inválido ou expirado"}
    usuario.senha = hash_senha(dados.senha_nova)
    usuario.reset_token = None
    usuario.reset_token_expira = None
    usuario.primeiro_acesso = False
    db.commit()
    return {"ok": True}

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