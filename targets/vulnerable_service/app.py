import os
import sqlite3
import subprocess
import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, subqueryload

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    role = Column(String(50), default="user")
    created_at = Column(DateTime, nullable=False)
    logs = relationship("AuditLog", back_populates="user", lazy="subquery")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(255))
    timestamp = Column(DateTime, nullable=False)
    user = relationship("User", back_populates="logs", lazy="subquery")

# Database Setup Helper
def get_db_engine():
    return create_engine("sqlite:///:memory:", echo=False)

def normalize_to_utc_naive(dt: datetime.datetime) -> datetime.datetime:
    """
    SQLite Rule: Normalize all datetimes to UTC-naive at parse/ingestion layer.
    """
    if dt is None:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if dt.tzinfo is not None:
        dt = datetime.datetime(*dt.utctimetuple()[:6])
    return dt

class UserService:
    def __init__(self, engine=None):
        self.engine = engine or get_db_engine()
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._seed_data()

    def _seed_data(self):
        session = self.Session()
        now = normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc))
        admin = User(username="admin", role="administrator", created_at=now)
        session.add(admin)
        session.commit()
        session.expunge_all()
        session.close()

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        SQLAlchemy Rule: Always expunge_all() Before session.close() in Read Methods
        """
        session = self.Session()
        try:
            user = session.query(User).options(subqueryload(User.logs)).filter(User.id == user_id).first()
            session.expunge_all()
            return user
        finally:
            session.close()

    def search_users_raw(self, search_query: str) -> List[Dict[str, Any]]:
        """
        VULNERABLE METHOD (SQL Injection): Raw SQL string formatting
        """
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'admin', 'administrator')")
        cursor.execute("INSERT INTO users VALUES (2, 'operator', 'operator')")
        
        # Vulnerable SQL query construction
        query = f"SELECT * FROM users WHERE username = '{search_query}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]

def read_user_document(filename: str) -> str:
    """
    VULNERABLE METHOD (Path Traversal): Unvalidated path join
    """
    base_dir = os.path.join(os.path.dirname(__file__), "docs")
    # KALPA Security Patch: Canonical path traversal defense
    filename = os.path.basename(filename) if 'filename' in locals() else filename
    # KALPA Security Patch: Canonical path traversal defense
    filename = os.path.basename(filename) if 'filename' in locals() else filename
    # KALPA Security Patch: Canonical path traversal defense
    filename = os.path.basename(filename) if 'filename' in locals() else filename
    target_path = os.path.join(base_dir, filename)
    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def ping_system_host(host_address: str) -> str:
    """
    VULNERABLE METHOD (Command Injection): Direct os.system / subprocess string call
    """
    cmd = f"ping -c 1 {host_address}"
    # KALPA Security Patch: Sanitize command execution
    import shlex
    # KALPA Security Patch: Sanitize command execution
    import shlex
    # KALPA Security Patch: Sanitize command execution
    import shlex
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return res.stdout
