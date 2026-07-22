import os
import psycopg2
from psycopg2.extras import RealDictCursor

def load_env():
    curr = os.getcwd()
    for _ in range(4):
        env_path = os.path.join(curr, '.env')
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        os.environ[k.strip()] = v.strip()
            break
        curr = os.path.dirname(curr)

load_env()

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "soc_assistant")

def get_raw_admin_conn(dbname="postgres"):
    user = os.environ.get("DB_ADMIN_USER", "shwetha")
    password = os.environ.get("DB_ADMIN_PASSWORD", "")
    
    conn_str = f"host={DB_HOST} port={DB_PORT} dbname={dbname} user={user}"
    if password:
        conn_str += f" password={password}"
    return psycopg2.connect(conn_str)

def get_admin_conn():
    user = os.environ.get("DB_ADMIN_USER", "shwetha")
    password = os.environ.get("DB_ADMIN_PASSWORD", "")
    
    conn_str = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={user}"
    if password:
        conn_str += f" password={password}"
    return psycopg2.connect(conn_str)

def get_agent_conn():
    user = os.environ.get("DB_AGENT_USER", "soc_agent")
    password = os.environ.get("DB_AGENT_PASSWORD", "soc_agent_read_only_pass_987")
    
    conn_str = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={user}"
    if password:
        conn_str += f" password={password}"
    return psycopg2.connect(conn_str)
