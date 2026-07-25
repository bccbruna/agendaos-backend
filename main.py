from fastapi import FastAPI, Depends, Header, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import engine, Base, get_db, Cliente, Agendamento, Usuario, Servico, Profissional
from pydantic import BaseModel, EmailStr
from typing import Optional
import bcrypt
import os
import re
import unicodedata
import secrets
import requests
from jose import JWTError, jwt
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

def get_client_ip(request: Request) -> str:
    # Atrás do proxy do Railway, request.client.host é o IP interno do proxy
    # (muda a cada requisição) e não o IP real do usuário - por isso lemos
    # o cabeçalho X-Forwarded-For, que o proxy preenche com o IP original.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=get_client_ip)

# ── BCRYPT ────────────────────────────────────────────────────
def hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

def verificar_senha(senha: str, hash: str) -> bool:
    return bcrypt.checkpw(senha.encode(), hash.encode())

# ── JWT ───────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Variável de ambiente SECRET_KEY não configurada.")
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

# ── MULTI-TENANT (dono_id) ─────────────────────────────────────
def gerar_slug(nome: str, db: Session) -> str:
    texto = unicodedata.normalize("NFKD", nome or "").encode("ascii", "ignore").decode("ascii")
    texto = re.sub(r"[^a-zA-Z0-9]+", "-", texto).strip("-").lower()
    if not texto:
        texto = "negocio"
    slug = texto
    contador = 2
    while db.query(Usuario).filter(Usuario.slug == slug).first():
        slug = f"{texto}-{contador}"
        contador += 1
    return slug

def resolver_dono_id(authorization: Optional[str], dono_id: Optional[int] = None) -> Optional[int]:
    if authorization and authorization.startswith("Bearer "):
        payload = verificar_token(authorization.split(" ")[1])
        if payload and payload.get("dono_id"):
            return payload["dono_id"]
    return dono_id

def exigir_dono_id(authorization: Optional[str], dono_id: Optional[int] = None) -> int:
    resolvido = resolver_dono_id(authorization, dono_id)
    if not resolvido:
        raise HTTPException(status_code=400, detail="Autenticação ou dono_id obrigatório")
    return resolvido

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

def _formatar_data_br(data: str) -> str:
    try:
        return "/".join(data.split("-")[::-1])
    except Exception:
        return data

def _formatar_preco_br(preco: float) -> str:
    return f"{preco:.2f}".replace(".", ",")

def enviar_email_confirmacao_cliente(destinatario: str, nome_cliente: str, nome_negocio: str, servico: str, data: str, hora: int, preco: float):
    data_br = _formatar_data_br(data)
    hora_fmt = f"{hora:02d}:00"
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; background:#08090F; padding:32px; color:#F0F0F8;">
    <div style="max-width:420px; margin:0 auto; background:#131620; border-radius:16px; padding:32px; border:1px solid rgba(255,255,255,0.07);">
      <h2 style="margin:0 0 16px; font-size:20px;">Agenda<span style="color:#A855F7;">OS</span></h2>
      <p style="font-size:14px; line-height:1.6; color:rgba(240,240,248,0.7);">Olá, {nome_cliente}!</p>
      <p style="font-size:14px; line-height:1.6; color:rgba(240,240,248,0.7);">
        Seu agendamento com <strong style="color:#F0F0F8;">{nome_negocio}</strong> foi recebido:
      </p>
      <div style="background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.2); border-radius:10px; padding:16px; margin:20px 0; font-size:13px; color:rgba(240,240,248,0.85);">
        📋 <strong style="color:#F0F0F8;">{servico}</strong><br>
        📅 {data_br} às {hora_fmt}<br>
        💰 R$ {_formatar_preco_br(preco)}
      </div>
      <p style="font-size:12px; color:rgba(240,240,248,0.44); margin-top:20px;">
        Qualquer dúvida, entre em contato direto com {nome_negocio}.
      </p>
    </div>
  </body>
</html>
"""
    texto = (
        f"Olá, {nome_cliente}!\n\n"
        f"Seu agendamento com {nome_negocio} foi recebido:\n"
        f"{servico} - {data_br} às {hora_fmt} - R$ {_formatar_preco_br(preco)}\n\n"
        f"Qualquer dúvida, entre em contato direto com {nome_negocio}."
    )
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "personalizations": [{"to": [{"email": destinatario}]}],
            "from": {"email": EMAIL_REMETENTE, "name": nome_negocio or "AgendaOS"},
            "subject": f"Agendamento confirmado - {nome_negocio}",
            "content": [
                {"type": "text/plain", "value": texto},
                {"type": "text/html", "value": html},
            ],
        },
        timeout=10,
    )
    resp.raise_for_status()

def enviar_email_novo_agendamento_dono(destinatario: str, nome_negocio: str, nome_cliente: str, telefone_cliente: str, servico: str, data: str, hora: int, preco: float):
    data_br = _formatar_data_br(data)
    hora_fmt = f"{hora:02d}:00"
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; background:#08090F; padding:32px; color:#F0F0F8;">
    <div style="max-width:420px; margin:0 auto; background:#131620; border-radius:16px; padding:32px; border:1px solid rgba(255,255,255,0.07);">
      <h2 style="margin:0 0 16px; font-size:20px;">Agenda<span style="color:#A855F7;">OS</span></h2>
      <p style="font-size:14px; line-height:1.6; color:rgba(240,240,248,0.7);">Você recebeu um novo agendamento:</p>
      <div style="background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.2); border-radius:10px; padding:16px; margin:20px 0; font-size:13px; color:rgba(240,240,248,0.85);">
        👤 <strong style="color:#F0F0F8;">{nome_cliente}</strong> · 📱 {telefone_cliente}<br>
        📋 {servico}<br>
        📅 {data_br} às {hora_fmt}<br>
        💰 R$ {_formatar_preco_br(preco)}
      </div>
      <p style="font-size:12px; color:rgba(240,240,248,0.44); margin-top:20px;">
        Acesse o painel do AgendaOS para confirmar ou recusar.
      </p>
    </div>
  </body>
</html>
"""
    texto = (
        f"Novo agendamento em {nome_negocio}:\n"
        f"{nome_cliente} ({telefone_cliente})\n"
        f"{servico} - {data_br} às {hora_fmt} - R$ {_formatar_preco_br(preco)}\n\n"
        "Acesse o painel do AgendaOS para confirmar ou recusar."
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
            "subject": f"Novo agendamento - {nome_cliente}",
            "content": [
                {"type": "text/plain", "value": texto},
                {"type": "text/html", "value": html},
            ],
        },
        timeout=10,
    )
    resp.raise_for_status()

def enviar_email_confirmacao_cliente_seguro(destinatario: str, nome_cliente: str, nome_negocio: str, servico: str, data: str, hora: int, preco: float):
    try:
        enviar_email_confirmacao_cliente(destinatario, nome_cliente, nome_negocio, servico, data, hora, preco)
        print("Email de confirmação enviado para", destinatario, flush=True)
    except Exception as e:
        print("Erro ao enviar email de confirmação para cliente:", e, flush=True)

def enviar_email_novo_agendamento_dono_seguro(destinatario: str, nome_negocio: str, nome_cliente: str, telefone_cliente: str, servico: str, data: str, hora: int, preco: float):
    try:
        enviar_email_novo_agendamento_dono(destinatario, nome_negocio, nome_cliente, telefone_cliente, servico, data, hora, preco)
        print("Email de novo agendamento enviado para", destinatario, flush=True)
    except Exception as e:
        print("Erro ao enviar email de novo agendamento para dono:", e, flush=True)

# ── APP ───────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# create_all não altera tabelas já existentes; garante as colunas novas em produção
def garantir_coluna(tabela: str, coluna: str, tipo: str):
    with engine.connect() as conn:
        try:
            conn.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {tipo} NULL"))
            conn.commit()
        except Exception:
            pass  # coluna já existe

garantir_coluna("usuarios", "reset_token", "VARCHAR(255)")
garantir_coluna("usuarios", "reset_token_expira", "DATETIME")
garantir_coluna("agendamentos", "profissional_id", "INTEGER")
garantir_coluna("usuarios", "slug", "VARCHAR(120)")
garantir_coluna("clientes", "dono_id", "INTEGER")
garantir_coluna("agendamentos", "dono_id", "INTEGER")
garantir_coluna("servicos", "dono_id", "INTEGER")
garantir_coluna("profissionais", "dono_id", "INTEGER")
garantir_coluna("usuarios", "horario_abertura", "VARCHAR(5)")
garantir_coluna("usuarios", "horario_fechamento", "VARCHAR(5)")
garantir_coluna("usuarios", "dias_funcionamento", "VARCHAR(20)")

# ── HORÁRIO DE FUNCIONAMENTO (com valores padrão pra quem ainda não configurou) ──
HORARIO_ABERTURA_PADRAO = "08:00"
HORARIO_FECHAMENTO_PADRAO = "18:00"
DIAS_FUNCIONAMENTO_PADRAO = "1,2,3,4,5,6"  # 0=domingo...6=sábado (fechado aos domingos por padrão)

def config_horario(usuario: Usuario):
    abertura = usuario.horario_abertura or HORARIO_ABERTURA_PADRAO
    fechamento = usuario.horario_fechamento or HORARIO_FECHAMENTO_PADRAO
    dias = usuario.dias_funcionamento or DIAS_FUNCIONAMENTO_PADRAO
    return abertura, fechamento, dias

app = FastAPI(title="AgendaOS API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
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
    profissional_id: Optional[int] = None
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
    email: EmailStr
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

class ProfissionalSchema(BaseModel):
    nome: str
    especialidade: Optional[str] = ""
    ativo: Optional[bool] = True

class ConfiguracoesSchema(BaseModel):
    horario_abertura: str
    horario_fechamento: str
    dias_funcionamento: str  # ex: "1,2,3,4,5,6" (0=domingo...6=sabado)

@app.get("/horarios-disponiveis")
def horarios_disponiveis(data: str, servico_id: int, profissional_id: Optional[int] = None,
                          dono_id: Optional[int] = None, authorization: Optional[str] = Header(None),
                          db: Session = Depends(get_db)):
    dono_id = exigir_dono_id(authorization, dono_id)
    servico = db.query(Servico).filter(Servico.id == servico_id, Servico.dono_id == dono_id).first()
    if not servico:
        return []

    usuario = db.query(Usuario).filter(Usuario.id == dono_id).first()
    abertura, fechamento, dias = config_horario(usuario)

    # Dia da semana no padrão 0=domingo...6=sabado (igual ao getDay() do JS)
    data_obj = datetime.strptime(data, "%Y-%m-%d")
    dia_semana = (data_obj.weekday() + 1) % 7
    if str(dia_semana) not in dias.split(","):
        return []  # negócio fechado nesse dia

    hora_abertura, min_abertura = (int(x) for x in abertura.split(":"))
    hora_fechamento, min_fechamento = (int(x) for x in fechamento.split(":"))

    duracao_slots = (servico.duracao + 29) // 30  # quantos slots de 30min ocupa
    query = db.query(Agendamento).filter(
        Agendamento.data == data,
        Agendamento.dono_id == dono_id,
        Agendamento.status != "cancelled"
    )
    if profissional_id:
        query = query.filter(Agendamento.profissional_id == profissional_id)
    agendamentos = query.all()
    
    # Monta lista de slots ocupados (cada hora tem 2 slots: :00 e :30)
    slots_ocupados = set()
    for ag in agendamentos:
        s = db.query(Servico).filter(Servico.nome == ag.servico, Servico.dono_id == dono_id).first()
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
    
    # Gera horários disponíveis dentro do expediente configurado, em slots de 30min
    horarios = []
    h, m = hora_abertura, min_abertura
    while (h, m) < (hora_fechamento, min_fechamento):
        disponivel = True
        hora_check, min_check = h, m
        for i in range(duracao_slots):
            if (hora_check, min_check) in slots_ocupados:
                disponivel = False
                break
            min_check += 30
            if min_check >= 60:
                min_check = 0
                hora_check += 1
        # o servico nao pode terminar depois do horario de fechamento
        if (hora_check, min_check) > (hora_fechamento, min_fechamento):
            disponivel = False

        if disponivel:
            horarios.append(f"{h:02d}:{m:02d}")

        m += 30
        if m >= 60:
            m = 0
            h += 1

    return horarios

# ── CLIENTES ──────────────────────────────────────────────────
@app.get("/clientes")
def listar_clientes(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(Cliente).filter(Cliente.dono_id == user["dono_id"]).all()

@app.get("/clientes/buscar")
def buscar_cliente_por_telefone(telefone: str, dono_id: int, db: Session = Depends(get_db)):
    cliente = db.query(Cliente).filter(Cliente.telefone == telefone, Cliente.dono_id == dono_id).first()
    return cliente

@app.post("/clientes")
def criar_cliente(c: ClienteSchema, dono_id: Optional[int] = None, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    dono_id = exigir_dono_id(authorization, dono_id)
    cliente = Cliente(**c.model_dump(), dono_id=dono_id)
    db.add(cliente)
    db.commit()
    db.refresh(cliente)
    return cliente

@app.delete("/clientes/{id}")
def deletar_cliente(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    cliente = db.query(Cliente).filter(Cliente.id == id, Cliente.dono_id == user["dono_id"]).first()
    if not cliente:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    db.query(Agendamento).filter(Agendamento.cliente_id == id).delete()
    db.delete(cliente)
    db.commit()
    return {"ok": True}

# ── AGENDAMENTOS ──────────────────────────────────────────────
@app.get("/agendamentos")
def listar_agendamentos(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(Agendamento).filter(Agendamento.dono_id == user["dono_id"]).all()

@app.post("/agendamentos")
def criar_agendamento(a: AgendamentoSchema, background_tasks: BackgroundTasks, dono_id: Optional[int] = None, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    dono_id = exigir_dono_id(authorization, dono_id)
    agendamento = Agendamento(**a.model_dump(), dono_id=dono_id)
    db.add(agendamento)
    db.commit()
    db.refresh(agendamento)

    cliente = db.query(Cliente).filter(Cliente.id == a.cliente_id).first()
    usuario = db.query(Usuario).filter(Usuario.id == dono_id).first()
    if usuario:
        nome_negocio = usuario.nome_negocio or "AgendaOS"
        if cliente and cliente.email:
            background_tasks.add_task(
                enviar_email_confirmacao_cliente_seguro,
                cliente.email, cliente.nome or "cliente", nome_negocio,
                a.servico, a.data, a.hora, a.preco or 0.0,
            )
        if usuario.email:
            background_tasks.add_task(
                enviar_email_novo_agendamento_dono_seguro,
                usuario.email, nome_negocio, cliente.nome if cliente else "cliente",
                cliente.telefone if cliente else "", a.servico, a.data, a.hora, a.preco or 0.0,
            )

    return agendamento

@app.put("/agendamentos/{id}/status")
def atualizar_status(id: int, status: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    ag = db.query(Agendamento).filter(Agendamento.id == id, Agendamento.dono_id == user["dono_id"]).first()
    if not ag:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")
    ag.status = status
    db.commit()
    return ag

@app.delete("/agendamentos/{id}")
def deletar_agendamento(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    ag = db.query(Agendamento).filter(Agendamento.id == id, Agendamento.dono_id == user["dono_id"]).first()
    if not ag:
        raise HTTPException(status_code=404, detail="Agendamento não encontrado")
    db.delete(ag)
    db.commit()
    return {"ok": True}

# ── LOGIN ─────────────────────────────────────────────────────
@app.post("/usuarios")
@limiter.limit("5/hour")
def criar_usuario(request: Request, u: CriarUsuarioSchema, db: Session = Depends(get_db)):
    if len(u.senha) < 6:
        return {"ok": False, "erro": "A senha deve ter pelo menos 6 caracteres."}
    if not u.nome_negocio.strip():
        return {"ok": False, "erro": "Informe o nome do negócio."}
    existente = db.query(Usuario).filter(Usuario.email == u.email).first()
    if existente:
        return {"ok": False, "erro": "Já existe uma conta com esse email."}
    slug = gerar_slug(u.nome_negocio, db)
    novo = Usuario(
        nome_negocio=u.nome_negocio,
        slug=slug,
        email=u.email,
        senha=hash_senha(u.senha),
        primeiro_acesso=False
    )
    db.add(novo)
    db.commit()
    db.refresh(novo)
    token = criar_token({"sub": novo.email, "dono_id": novo.id})
    return {
        "ok": True,
        "token": token,
        "id": novo.id,
        "slug": novo.slug,
        "nome_negocio": novo.nome_negocio,
        "email": novo.email,
        "primeiro_acesso": novo.primeiro_acesso,
    }

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, dados: LoginSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == dados.email).first()
    if not usuario or not verificar_senha(dados.senha, usuario.senha):
        return {"ok": False, "erro": "Email ou senha incorretos"}
    token = criar_token({"sub": usuario.email, "dono_id": usuario.id})
    return {
        "ok": True,
        "token": token,
        "primeiro_acesso": usuario.primeiro_acesso,
        "nome_negocio": usuario.nome_negocio,
        "email": usuario.email,
        "slug": usuario.slug,
    }

@app.get("/negocio/{slug}")
def obter_negocio_por_slug(slug: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.slug == slug).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Negócio não encontrado")
    abertura, fechamento, dias = config_horario(usuario)
    return {
        "id": usuario.id,
        "nome_negocio": usuario.nome_negocio,
        "horario_abertura": abertura,
        "horario_fechamento": fechamento,
        "dias_funcionamento": dias,
    }

# ── CONFIGURAÇÕES (horário de funcionamento) ───────────────────
@app.get("/configuracoes")
def obter_configuracoes(db: Session = Depends(get_db), user=Depends(get_current_user)):
    usuario = db.query(Usuario).filter(Usuario.id == user["dono_id"]).first()
    abertura, fechamento, dias = config_horario(usuario)
    return {"horario_abertura": abertura, "horario_fechamento": fechamento, "dias_funcionamento": dias}

@app.put("/configuracoes")
def atualizar_configuracoes(c: ConfiguracoesSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    for valor, nome in [(c.horario_abertura, "abertura"), (c.horario_fechamento, "fechamento")]:
        if not re.match(r"^\d{2}:\d{2}$", valor):
            return {"ok": False, "erro": f"Horário de {nome} inválido (use HH:MM)."}
    if c.horario_abertura >= c.horario_fechamento:
        return {"ok": False, "erro": "O horário de abertura precisa ser antes do fechamento."}
    dias_validos = {"0", "1", "2", "3", "4", "5", "6"}
    dias_informados = [d.strip() for d in c.dias_funcionamento.split(",") if d.strip()]
    if not dias_informados or not set(dias_informados).issubset(dias_validos):
        return {"ok": False, "erro": "Selecione ao menos um dia de funcionamento válido."}

    usuario = db.query(Usuario).filter(Usuario.id == user["dono_id"]).first()
    usuario.horario_abertura = c.horario_abertura
    usuario.horario_fechamento = c.horario_fechamento
    usuario.dias_funcionamento = ",".join(dias_informados)
    db.commit()
    return {"ok": True}

def enviar_email_recuperacao_seguro(destinatario: str, token: str):
    try:
        enviar_email_recuperacao(destinatario, token)
        print("Email de recuperação enviado para", destinatario, flush=True)
    except Exception as e:
        print("Erro ao enviar email de recuperação:", e, flush=True)

@app.post("/esqueci-senha")
@limiter.limit("3/hour")
def esqueci_senha(request: Request, dados: EsqueciSenhaSchema, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
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
@limiter.limit("10/minute")
def redefinir_senha(request: Request, dados: RedefinirSenhaSchema, db: Session = Depends(get_db)):
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
@limiter.limit("5/minute")
def trocar_senha(request: Request, dados: TrocarSenhaSchema, db: Session = Depends(get_db)):
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
def listar_servicos(dono_id: Optional[int] = None, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    dono_id = exigir_dono_id(authorization, dono_id)
    return db.query(Servico).filter(Servico.dono_id == dono_id).all()

@app.post("/servicos")
def criar_servico(s: ServicoSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = Servico(**s.model_dump(), dono_id=user["dono_id"])
    db.add(servico)
    db.commit()
    db.refresh(servico)
    return servico

@app.put("/servicos/{id}")
def atualizar_servico(id: int, s: ServicoSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = db.query(Servico).filter(Servico.id == id, Servico.dono_id == user["dono_id"]).first()
    if not servico:
        raise HTTPException(status_code=404, detail="Serviço não encontrado")
    for k, v in s.model_dump().items():
        setattr(servico, k, v)
    db.commit()
    return servico

@app.delete("/servicos/{id}")
def deletar_servico(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    servico = db.query(Servico).filter(Servico.id == id, Servico.dono_id == user["dono_id"]).first()
    if not servico:
        raise HTTPException(status_code=404, detail="Serviço não encontrado")
    db.delete(servico)
    db.commit()
    return {"ok": True}

# ── PROFISSIONAIS ─────────────────────────────────────────────
@app.get("/profissionais")
def listar_profissionais(dono_id: Optional[int] = None, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    dono_id = exigir_dono_id(authorization, dono_id)
    return db.query(Profissional).filter(Profissional.ativo == True, Profissional.dono_id == dono_id).all()

@app.post("/profissionais")
def criar_profissional(p: ProfissionalSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    profissional = Profissional(**p.model_dump(), dono_id=user["dono_id"])
    db.add(profissional)
    db.commit()
    db.refresh(profissional)
    return profissional

@app.put("/profissionais/{id}")
def atualizar_profissional(id: int, p: ProfissionalSchema, db: Session = Depends(get_db), user=Depends(get_current_user)):
    profissional = db.query(Profissional).filter(Profissional.id == id, Profissional.dono_id == user["dono_id"]).first()
    if not profissional:
        raise HTTPException(status_code=404, detail="Profissional não encontrado")
    for k, v in p.model_dump().items():
        setattr(profissional, k, v)
    db.commit()
    return profissional

@app.delete("/profissionais/{id}")
def deletar_profissional(id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    profissional = db.query(Profissional).filter(Profissional.id == id, Profissional.dono_id == user["dono_id"]).first()
    if not profissional:
        raise HTTPException(status_code=404, detail="Profissional não encontrado")
    db.delete(profissional)
    db.commit()
    return {"ok": True}

@app.get("/")
def root():
    return {"status": "AgendaOS API rodando!"}