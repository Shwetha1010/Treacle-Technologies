import os
import sys
import json
import datetime
import argparse
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values

# Add project root to sys.path so we can import database client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.database.client import get_raw_admin_conn, get_admin_conn, load_env

def create_database():
    load_env()
    db_name = os.environ.get("DB_NAME", "soc_assistant")
    
    # Connect to default postgres database to check and create the new database
    conn = get_raw_admin_conn(dbname="postgres")
    conn.autocommit = True
    cur = conn.cursor()
    
    cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s;", (db_name,))
    exists = cur.fetchone()
    if not exists:
        print(f"Creating database '{db_name}'...")
        cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
    else:
        print(f"Database '{db_name}' already exists.")
        
    cur.close()
    conn.close()

def setup_schemas_and_roles():
    conn = get_admin_conn()
    conn.autocommit = True
    cur = conn.cursor()
    
    # 1. Create Users table
    print("Creating 'users' table...")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'analyst',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Create log tables
    log_tables = [
        "ftp_logs", "https_logs", "octopus_logs", "rdp_logs", "sqli_logs", "ssh_logs", "binaries_analytics"
    ]
    
    for table in log_tables:
        print(f"Creating '{table}' table...")
        cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id SERIAL PRIMARY KEY,
            attacker_ip VARCHAR(45),
            username VARCHAR(255),
            timestamp TIMESTAMP WITH TIME ZONE,
            protocol VARCHAR(50),
            data JSONB NOT NULL
        );
        """)
        # Create indexes for high performance
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_attacker_ip ON {table} (attacker_ip);")
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_username ON {table} (username);")
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_timestamp ON {table} (timestamp);")
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_protocol ON {table} (protocol);")
        
    # 3. Create read-only agent user and grant privileges
    agent_user = os.environ.get("DB_AGENT_USER", "soc_agent")
    agent_pass = os.environ.get("DB_AGENT_PASSWORD", "soc_agent_read_only_pass_987")
    
    # Check if agent user exists
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s;", (agent_user,))
    user_exists = cur.fetchone()
    if not user_exists:
        print(f"Creating read-only agent user '{agent_user}'...")
        cur.execute(sql.SQL("CREATE USER {} WITH PASSWORD %s;").format(sql.Identifier(agent_user)), (agent_pass,))
    else:
        print(f"Read-only agent user '{agent_user}' already exists. Updating password...")
        cur.execute(sql.SQL("ALTER USER {} WITH PASSWORD %s;").format(sql.Identifier(agent_user)), (agent_pass,))
        
    db_name = os.environ.get("DB_NAME", "soc_assistant")
    
    # Grant read-only access
    cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(db_name), sql.Identifier(agent_user)))
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(agent_user)))
    cur.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(agent_user)))
    cur.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {}").format(sql.Identifier(agent_user)))
    
    print("Database schemas and roles configured successfully.")
    cur.close()
    conn.close()

def parse_iso_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        # Standard ISO string parse, replace Z with +00:00
        cleaned = ts_str.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(cleaned)
    except Exception:
        # Fallback manual parsing if format varies slightly
        for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.datetime.strptime(cleaned, fmt)
            except Exception:
                continue
        return None

def extract_record_fields(filename, record):
    # Helper to extract IP, username, timestamp, and protocol based on log schema
    attacker_ip = None
    username = None
    timestamp = None
    protocol = None
    
    # 1. Extract IP
    if "src_ip" in record:
        # binaries_analytics uses src_ip
        attacker_ip = record.get("src_ip")
    elif "public" in record and isinstance(record["public"], dict) and "source" in record["public"] and isinstance(record["public"]["source"], dict):
        attacker_ip = record["public"]["source"].get("ip")
    elif "private" in record and isinstance(record["private"], dict) and "source" in record["private"] and isinstance(record["private"]["source"], dict):
        attacker_ip = record["private"]["source"].get("ip")
    
    if not attacker_ip or attacker_ip == "N/A":
        # Fallback to check other fields
        attacker_ip = record.get("ip")
        
    # Clean IP if it is list or not string
    if isinstance(attacker_ip, list) and attacker_ip:
        attacker_ip = attacker_ip[0]
    if attacker_ip:
        attacker_ip = str(attacker_ip).strip()
        
    # 2. Extract Username
    if "username" in record:
        username = record.get("username")
    if username == "N/A" or not username:
        username = None
        
    # 3. Extract Timestamp
    ts_field = record.get("timestamp")
    if isinstance(ts_field, dict) and "$date" in ts_field:
        timestamp = parse_iso_timestamp(ts_field["$date"])
    elif isinstance(ts_field, str):
        timestamp = parse_iso_timestamp(ts_field)
        
    # 4. Extract Protocol
    protocol = record.get("protocol")
    if not protocol:
        if "ftp" in filename:
            protocol = "FTP"
        elif "https" in filename:
            protocol = "HTTPS"
        elif "octopus" in filename:
            protocol = "OCTOPUS"
        elif "rdp" in filename:
            protocol = "RDP"
        elif "sqli" in filename:
            protocol = "HTTPS"
        elif "ssh" in filename:
            protocol = "SSH"
            
    if protocol:
        protocol = str(protocol).upper()
        
    return attacker_ip, username, timestamp, protocol

def import_file(filepath, table_name):
    print(f"Importing {filepath} into table '{table_name}'...")
    if not os.path.exists(filepath):
        print(f"Error: File {filepath} not found.")
        return 0
        
    conn = get_admin_conn()
    cur = conn.cursor()
    
    # Read the data file and sanitize null bytes
    records = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Replace escaped null and raw null characters
            content = content.replace('\\u0000', '')
            content = content.replace('\u0000', '')
            
            if content.strip().startswith('['):
                # JSON list format
                records = json.loads(content)
            else:
                # Line-delimited JSON
                for line_num, line in enumerate(content.splitlines(), 1):
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except Exception as e:
                            # Print warning and continue
                            print(f"Skipping corrupt line {line_num} in {os.path.basename(filepath)}: {e}")
    except Exception as e:
        print(f"Failed to read file {filepath}: {e}")
        cur.close()
        conn.close()
        return 0
        
    success_count = 0
    batch_data = []
    
    for idx, record in enumerate(records):
        try:
            attacker_ip, username, timestamp, protocol = extract_record_fields(table_name, record)
            # Store the data as JSON dump
            data_json = json.dumps(record)
            batch_data.append((attacker_ip, username, timestamp, protocol, data_json))
            success_count += 1
        except Exception as e:
            print(f"Skipping corrupt record at index {idx} in {os.path.basename(filepath)}: {e}")
            
    # Insert batch data in database using fast execute_values
    if batch_data:
        try:
            # Clear old records to prevent duplicates on script re-run
            cur.execute(f"TRUNCATE TABLE {table_name} RESTART IDENTITY CASCADE;")
            insert_query = f"INSERT INTO {table_name} (attacker_ip, username, timestamp, protocol, data) VALUES %s"
            # execute_values runs extreme fast
            execute_values(cur, insert_query, batch_data)
            conn.commit()
            print(f"Successfully imported {success_count} records into '{table_name}'.")
        except Exception as e:
            conn.rollback()
            print(f"Failed to write batch data to '{table_name}': {e}")
            success_count = 0
            
    cur.close()
    conn.close()
    return success_count

def main():
    parser = argparse.ArgumentParser(description="Import SOC Deception Data into PostgreSQL")
    parser.add_argument("--data-dir", default="./data", help="Path to data directory containing JSON files")
    args = parser.parse_args()
    
    # 1. Create database and setup structure
    try:
        create_database()
        setup_schemas_and_roles()
    except Exception as e:
        print(f"Database setup failed: {e}")
        sys.exit(1)
        
    # Mappings of filenames to target table names
    file_mappings = {
        "logs.ftp_logs.json": "ftp_logs",
        "logs.https_logs.json": "https_logs",
        "logs.octopus_logs.json": "octopus_logs",
        "logs.rdp_logs.json": "rdp_logs",
        "logs.sqli_logs.json": "sqli_logs",
        "logs.ssh_logs.json": "ssh_logs",
        "system.binaries_analytics.json": "binaries_analytics"
    }
    
    total_imported = 0
    for filename, table_name in file_mappings.items():
        filepath = os.path.join(args.data_dir, filename)
        count = import_file(filepath, table_name)
        total_imported += count
        
    print(f"\nData import complete. Total records imported: {total_imported}")

if __name__ == "__main__":
    main()
