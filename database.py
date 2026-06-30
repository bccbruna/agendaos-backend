from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()

host     = os.getenv("DB_HOST")
user     = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
name     = os.getenv("DB_NAME")

URL = f"mysql+pymysql://{user}:{password}@{host}/{name}"

engine       = create_engine(URL)
SessionLocal = sessionmaker(bind=engine)
Base         = declarative_base()

# ── TABELAS ──────────────────────────────────────────────────
class Cliente(Base):
    __tablename__ = "clientes"
    id         = Column(Integer, primary_key=True, index=True)
    nome       = Column(String(100))
    telefone   = Column(String(20))
    email      = Column(String(100))
    tipo       = Column(String(50))
    criado_em  = Column(DateTime, default=datetime.now)
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nome_negocio = Column(String(100))
    email = Column(String(100), unique=True)
    senha = Column(String(255))
    primeiro_acesso = Column(Boolean, default=True)
    criado_em = Column(DateTime, default=datetime.now)
class Agendamento(Base):
    __tablename__ = "agendamentos"
    id         = Column(Integer, primary_key=True, index=True)
    cliente_id = Column(Integer)
    servico    = Column(String(100))
    data       = Column(String(20))
    hora       = Column(Integer)
    status     = Column(String(20), default="confirmado")
    obs        = Column(String(200))
    preco      = Column(Float)
    criado_em  = Column(DateTime, default=datetime.now)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()