import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime

# Railway fornece variáveis MYSQL* nativamente.
# Lemos essas primeiro; se não existirem, usamos as DB_* (desenvolvimento local).
host     = os.environ.get("MYSQLHOST")     or os.environ.get("DB_HOST", "localhost")
user     = os.environ.get("MYSQLUSER")     or os.environ.get("DB_USER", "root")
password = os.environ.get("MYSQLPASSWORD") or os.environ.get("DB_PASSWORD", "")
db       = os.environ.get("MYSQLDATABASE") or os.environ.get("DB_NAME", "railway")
port     = os.environ.get("MYSQLPORT")     or os.environ.get("DB_PORT", "3306")
if not port or str(port).startswith("$"):
    port = "3306"

URL = f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}"

engine       = create_engine(URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

def get_db():
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

class Cliente(Base):
    __tablename__ = "clientes"
    id        = Column(Integer, primary_key=True, index=True)
    nome      = Column(String(100))
    telefone  = Column(String(20))
    email     = Column(String(100))
    tipo      = Column(String(50))
    criado_em = Column(DateTime, default=datetime.now)

class Agendamento(Base):
    __tablename__ = "agendamentos"
    id         = Column(Integer, primary_key=True, index=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id"))
    servico    = Column(String(100))
    data       = Column(String(20))
    hora       = Column(String(10))
    status     = Column(String(20), default="pending")
    obs        = Column(String(500))
    preco      = Column(Float)
    criado_em  = Column(DateTime, default=datetime.now)

class Usuario(Base):
    __tablename__ = "usuarios"
    id            = Column(Integer, primary_key=True, index=True)
    nome_negocio  = Column(String(100))
    email         = Column(String(100), unique=True)
    senha         = Column(String(255))
    primeiro_acesso = Column(Boolean, default=True)
    criado_em     = Column(DateTime, default=datetime.now)