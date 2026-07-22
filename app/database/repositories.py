import datetime
import json
from app.database.client import get_agent_conn, get_admin_conn

# ----------------- User Management (requires admin connection for writes) -----------------

def get_user_by_username(username: str):
    conn = get_admin_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s;", (username,))
        row = cur.fetchone()
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "password_hash": row[2],
                "role": row[3]
            }
        return None
    finally:
        cur.close()
        conn.close()

def register_user(username: str, password_hash: str, role: str = "analyst"):
    conn = get_admin_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id;",
            (username, password_hash, role)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        return user_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


# ----------------- Deception Logs Queries (uses read-only agent connection) -----------------

LOG_TABLES = ["ftp_logs", "https_logs", "octopus_logs", "rdp_logs", "sqli_logs", "ssh_logs"]

def get_top_attackers(limit: int = 5, protocol: str = None, start_time: datetime.datetime = None, end_time: datetime.datetime = None):
    conn = get_agent_conn()
    cur = conn.cursor()
    try:
        # Determine tables to query
        tables = LOG_TABLES
        if protocol:
            p_lower = protocol.lower()
            if p_lower == "ftp":
                tables = ["ftp_logs"]
            elif p_lower in ("http", "https"):
                tables = ["https_logs", "sqli_logs"]
            elif p_lower == "octopus":
                tables = ["octopus_logs"]
            elif p_lower == "rdp":
                tables = ["rdp_logs"]
            elif p_lower == "sqli":
                tables = ["sqli_logs"]
            elif p_lower == "ssh":
                tables = ["ssh_logs"]
        
        # Build union query
        queries = []
        params = []
        for table in tables:
            q = f"SELECT attacker_ip, timestamp FROM {table} WHERE attacker_ip IS NOT NULL AND attacker_ip != 'N/A'"
            conditions = []
            if start_time:
                conditions.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                conditions.append("timestamp <= %s")
                params.append(end_time)
            
            if conditions:
                q += " AND " + " AND ".join(conditions)
            queries.append(q)
            
        union_query = " UNION ALL ".join(queries)
        final_query = f"""
            WITH all_events AS ({union_query})
            SELECT attacker_ip, COUNT(*) as event_count
            FROM all_events
            GROUP BY attacker_ip
            ORDER BY event_count DESC
            LIMIT %s;
        """
        params.append(limit)
        
        cur.execute(final_query, tuple(params))
        rows = cur.fetchall()
        
        return [{"source_ip": r[0], "event_count": r[1]} for r in rows]
    finally:
        cur.close()
        conn.close()

def investigate_ip(ip: str):
    conn = get_agent_conn()
    cur = conn.cursor()
    try:
        overall_count = 0
        first_seen = None
        last_seen = None
        tables_involved = []
        protocols_involved = set()
        usernames = set()
        paths_visited = set()
        commands_executed = set()
        payloads_seen = []
        
        for table in LOG_TABLES:
            # Basic aggregate check on this table
            query = f"""
                SELECT COUNT(*), MIN(timestamp), MAX(timestamp) 
                FROM {table} 
                WHERE attacker_ip = %s;
            """
            cur.execute(query, (ip,))
            count, t_min, t_max = cur.fetchone()
            
            if count and count > 0:
                overall_count += count
                tables_involved.append(table)
                
                if first_seen is None or (t_min and t_min < first_seen):
                    first_seen = t_min
                if last_seen is None or (t_max and t_max > last_seen):
                    last_seen = t_max
                
                # Retrieve specific fields (usernames, protocol, data payload etc.)
                detail_query = f"SELECT username, protocol, data FROM {table} WHERE attacker_ip = %s LIMIT 50;"
                cur.execute(detail_query, (ip,))
                rows = cur.fetchall()
                
                for username, protocol, raw_data in rows:
                    if username and username != "N/A":
                        usernames.add(username)
                    if protocol:
                        protocols_involved.add(protocol.upper())
                        
                    # Extract specifics based on data payload
                    if raw_data:
                        if "http_request" in raw_data:
                            paths_visited.add(raw_data.get("http_request"))
                        if "command" in raw_data and raw_data.get("command"):
                            commands_executed.add(raw_data.get("command"))
                        if "payload" in raw_data and raw_data.get("payload"):
                            payloads_seen.append(raw_data.get("payload"))
                            
        # Now query binaries_analytics table as well
        cur.execute("SELECT COUNT(*), MIN(timestamp::timestamp), MAX(timestamp::timestamp) FROM binaries_analytics WHERE attacker_ip = %s OR data->>'src_ip' = %s;", (ip, ip))
        bin_count, bin_min, bin_max = cur.fetchone()
        
        associated_binaries = []
        if bin_count and bin_count > 0:
            overall_count += bin_count
            tables_involved.append("binaries_analytics")
            protocols_involved.add("MALWARE_DOWNLOAD")
            
            if first_seen is None or (bin_min and bin_min < first_seen):
                first_seen = bin_min
            if last_seen is None or (bin_max and bin_max > last_seen):
                last_seen = bin_max
                
            cur.execute("SELECT md5_hash, filename, url, data FROM binaries_analytics WHERE attacker_ip = %s OR data->>'src_ip' = %s LIMIT 10;", (ip, ip))
            bin_rows = cur.fetchall()
            for md5, fname, url, raw_data in bin_rows:
                verdicts = []
                if raw_data and "file_details" in raw_data and "data" in raw_data["file_details"]:
                    verdicts = raw_data["file_details"]["data"].get("verdicts", [])
                associated_binaries.append({
                    "md5_hash": md5,
                    "filename": fname or "unknown",
                    "download_url": url or "unknown",
                    "verdicts": verdicts
                })
        
        return {
            "source_ip": ip,
            "event_count": overall_count,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "tables_involved": tables_involved,
            "protocols_involved": list(protocols_involved),
            "usernames": list(usernames),
            "paths_visited": list(paths_visited)[:10],
            "commands_executed": list(commands_executed)[:10],
            "payloads_seen": payloads_seen[:5],
            "associated_binaries": associated_binaries
        }
    finally:
        cur.close()
        conn.close()

def get_protocol_summary():
    conn = get_agent_conn()
    cur = conn.cursor()
    try:
        queries = []
        for table in LOG_TABLES:
            queries.append(f"SELECT UPPER(protocol) as proto, COUNT(*) as count FROM {table} GROUP BY protocol")
        
        # Add binaries analytics summary
        queries.append("SELECT 'MALWARE_DOWNLOAD' as proto, COUNT(*) as count FROM binaries_analytics")
        
        union_query = " UNION ALL ".join(queries)
        final_query = f"""
            WITH proto_counts AS ({union_query})
            SELECT proto, SUM(count) as total_count
            FROM proto_counts
            WHERE proto IS NOT NULL AND proto != ''
            GROUP BY proto
            ORDER BY total_count DESC;
        """
        cur.execute(final_query)
        rows = cur.fetchall()
        return [{"protocol": r[0], "event_count": int(r[1])} for r in rows]
    finally:
        cur.close()
        conn.close()

def search_security_events(ip: str = None, username: str = None, protocol: str = None, table_name: str = None, start_time: datetime.datetime = None, end_time: datetime.datetime = None, limit: int = 50):
    conn = get_agent_conn()
    cur = conn.cursor()
    try:
        # Determine target tables
        target_tables = LOG_TABLES
        if table_name:
            t_lower = table_name.lower()
            if t_lower in LOG_TABLES:
                target_tables = [t_lower]
            elif t_lower + "_logs" in LOG_TABLES:
                target_tables = [t_lower + "_logs"]
        elif protocol:
            p_lower = protocol.lower()
            if p_lower == "ftp":
                target_tables = ["ftp_logs"]
            elif p_lower in ("http", "https"):
                target_tables = ["https_logs", "sqli_logs"]
            elif p_lower == "octopus":
                target_tables = ["octopus_logs"]
            elif p_lower == "rdp":
                target_tables = ["rdp_logs"]
            elif p_lower == "sqli":
                target_tables = ["sqli_logs"]
            elif p_lower == "ssh":
                target_tables = ["ssh_logs"]

        queries = []
        params = []
        
        for table in target_tables:
            q = f"SELECT '{table}' as source_table, attacker_ip, username, timestamp, protocol, data FROM {table} WHERE 1=1"
            conditions = []
            if ip:
                conditions.append("attacker_ip = %s")
                params.append(ip)
            if username:
                conditions.append("username = %s")
                params.append(username)
            if protocol:
                conditions.append("UPPER(protocol) = %s")
                params.append(protocol.upper())
            if start_time:
                conditions.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                conditions.append("timestamp <= %s")
                params.append(end_time)
                
            if conditions:
                q += " AND " + " AND ".join(conditions)
            queries.append(q)
            
        union_query = " UNION ALL ".join(queries)
        final_query = f"{union_query} ORDER BY timestamp DESC LIMIT %s;"
        params.append(limit)
        
        cur.execute(final_query, tuple(params))
        rows = cur.fetchall()
        
        results = []
        for row in rows:
            results.append({
                "source_table": row[0],
                "attacker_ip": row[1],
                "username": row[2],
                "timestamp": row[3].isoformat() if row[3] else None,
                "protocol": row[4],
                "details": row[5]
            })
        return results
    finally:
        cur.close()
        conn.close()

def search_binaries_analytics(query_str: str = None, ip: str = None, md5: str = None, filename: str = None, url: str = None, limit: int = 20):
    conn = get_agent_conn()
    cur = conn.cursor()
    try:
        q = "SELECT attacker_ip, username, timestamp, protocol, md5_hash, filename, url, data FROM binaries_analytics WHERE 1=1"
        conditions = []
        params = []
        
        if ip:
            conditions.append("(attacker_ip = %s OR data->>'src_ip' = %s)")
            params.append(ip)
            params.append(ip)
        if md5:
            conditions.append("md5_hash = %s")
            params.append(md5)
        if filename:
            conditions.append("filename ILIKE %s")
            params.append(f"%{filename}%")
        if url:
            conditions.append("url ILIKE %s")
            params.append(f"%{url}%")
        if query_str:
            conditions.append("(filename ILIKE %s OR md5_hash = %s OR url ILIKE %s)")
            params.append(f"%{query_str}%")
            params.append(query_str)
            params.append(f"%{query_str}%")
            
        if conditions:
            q += " AND " + " AND ".join(conditions)
            
        q += " LIMIT %s;"
        params.append(limit)
        
        cur.execute(q, tuple(params))
        rows = cur.fetchall()
        
        results = []
        for row in rows:
            results.append({
                "attacker_ip": row[0],
                "username": row[1],
                "timestamp": row[2],
                "protocol": row[3],
                "md5_hash": row[4],
                "filename": row[5],
                "url": row[6],
                "details": row[7]
            })
        return results
    finally:
        cur.close()
        conn.close()
