import os
import json
import requests
from app.agents import intent_classifier
from app.tools import top_attackers, ip_investigation, protocol_summary, event_search, binary_search

def get_groq_key():
    return os.environ.get("GROQ_API_KEY", "")

def generate_analyst_summary(query: str, tools_used: list, retrieved_data: dict) -> str:
    api_key = get_groq_key()
    if not api_key:
        return "Data retrieved successfully. (LLM summary unavailable because GROQ_API_KEY is not configured)."
        
    system_prompt = """You are a Senior Security Operations Center (SOC) Analyst. Your job is to write a brief (2-3 sentences), professional, evidence-based analyst summary of the retrieved security events. 
- You must ONLY use the provided data.
- Do NOT make up details or paint interpretations not supported by the evidence.
- State clearly if certain fields are missing or if the data doesn't answer the user's question.
- Do NOT expose any internal LLM thoughts or reasoning process. Just write the direct summary."""

    user_content = f"User Query: {query}\nTools Executed: {tools_used}\nRetrieved Data:\n{json.dumps(retrieved_data, indent=2)[:3000]}"
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        "temperature": 0.2
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return f"Data retrieved successfully. (Summary API returned status {response.status_code})"
    except Exception as e:
        return f"Data retrieved successfully. (Summary generation failed: {e})"

SESSION_MEMORIES = {}

def run_query(query: str, username: str = None) -> dict:
    q_lower = query.lower()
    
    # 1. Classify intent
    classification = intent_classifier.classify(query)
    intent = classification.get("intent", "unknown")
    params = classification.get("parameters", {})
    
    # Resolve referenced IP from conversation memory if not present in query
    ip_from_memory = False
    resolved_ip = params.get("ip") or intent_classifier.extract_ip(query)
    if not resolved_ip and username and username in SESSION_MEMORIES:
        referenced_words = ["its", "this ip", "that ip", "the ip", "the attacker", "show only",
                            "his", "her", "their", "same ip", "that attacker"]
        if any(w in q_lower for w in referenced_words):
            resolved_ip = SESSION_MEMORIES[username].get("last_ip")
            if resolved_ip:
                params["ip"] = resolved_ip
                ip_from_memory = True

    # If the IP was resolved from memory but the classified intent does NOT use an IP
    # (e.g. LLM misclassified "show its SSH activity" as get_protocol_summary),
    # override intent to search_security_events so the remembered IP is actually applied.
    NON_IP_INTENTS = ("get_protocol_summary", "get_top_attackers", "unknown")
    if ip_from_memory and intent in NON_IP_INTENTS:
        intent = "search_security_events"
        # Extract any protocol keyword the user mentioned in the follow-up query
        PROTOCOL_KEYWORDS = {
            "ssh": "SSH", "ftp": "FTP", "http": "HTTP", "https": "HTTPS",
            "rdp": "RDP", "sqli": "SQLI", "sql": "SQLI", "smb": "SMB",
            "octopus": "OCTOPUS", "sip": "SIPSESSION", "mysql": "MYSQLD",
            "mqtt": "MQTTD", "ppp": "PPTPD", "httpd": "HTTPD"
        }
        for kw, proto in PROTOCOL_KEYWORDS.items():
            if kw in q_lower:
                params["protocol"] = proto
                break
                    
    # 2. Check for destructive attempts
    if intent == "destructive" or "delete" in q_lower or "drop table" in q_lower or "truncate" in q_lower:
        return {
            "status": "rejected",
            "reason": "The assistant has read-only access and cannot perform destructive operations.",
            "tools_used": [],
            "tools_executed": [],
            "data": {},
            "summary": "Request rejected due to violation of read-only access policy.",
            "limitations": []
        }
        
    # 3. Check for multi-step workflow
    # Query: "Identify the most active attacker and investigate that IP address"
    is_multistep = False
    if "most active attacker" in q_lower and ("investigate" in q_lower or "check" in q_lower or "analyze" in q_lower):
        is_multistep = True
    elif intent == "investigate_ip" and not params.get("ip") and "most active" in q_lower:
        is_multistep = True
        
    if is_multistep:
        # Step 1: Run top_attackers
        top_res = top_attackers.execute(limit=1)
        if top_res.get("status") != "success" or not top_res.get("data"):
            return {
                "status": "success",
                "intent": "investigate_ip",
                "tools_used": ["get_top_attackers"],
                "data": {},
                "summary": "Could not identify the most active attacker from the database.",
                "limitations": ["Database query failed or database is empty."]
            }
            
        top_ip = top_res["data"][0].get("source_ip")
        if not top_ip:
            return {
                "status": "success",
                "intent": "investigate_ip",
                "tools_used": ["get_top_attackers"],
                "data": {},
                "summary": "Could not extract the most active attacker IP.",
                "limitations": ["No IP found in attacker counts result."]
            }
            
        # Step 2: Run investigate_ip
        inv_res = ip_investigation.execute(ip=top_ip)
        
        combined_data = {
            "top_attacker_discovery": top_res["data"],
            "ip_investigation": inv_res.get("data", {})
        }
        
        summary = generate_analyst_summary(query, ["get_top_attackers", "investigate_ip"], combined_data)
        
        if username and top_ip:
            SESSION_MEMORIES[username] = {"last_ip": top_ip}
            
        return {
            "status": "success",
            "intent": "investigate_ip",
            "tools_used": ["get_top_attackers", "investigate_ip"],
            "tools_executed": ["get_top_attackers", "investigate_ip"],
            "data": combined_data,
            "summary": summary,
            "limitations": []
        }
        
    # 4. Standard single tool execution
    tools_executed = []
    tool_res = {}
    limitations = []
    
    if intent == "get_top_attackers":
        tools_executed.append("get_top_attackers")
        tool_res = top_attackers.execute(**params)
        
    elif intent == "investigate_ip":
        tools_executed.append("investigate_ip")
        if not params.get("ip"):
            # Try to extract IP manually
            extracted = intent_classifier.extract_ip(query)
            if extracted:
                params["ip"] = extracted
                
        if not params.get("ip"):
            tool_res = {
                "status": "error",
                "message": "Missing IP parameter for investigation."
            }
        else:
            tool_res = ip_investigation.execute(**params)
            
    elif intent == "get_protocol_summary":
        tools_executed.append("get_protocol_summary")
        tool_res = protocol_summary.execute()
        
    elif intent == "search_security_events":
        tools_executed.append("search_security_events")
        # Ensure we only pass valid arguments to search
        search_params = {k: v for k, v in params.items() if k in ("ip", "username", "protocol", "table_name", "start_time", "end_time", "limit")}
        tool_res = event_search.execute(**search_params)
        
    elif intent == "search_binaries_analytics":
        tools_executed.append("search_binaries_analytics")
        # Ensure we only pass valid arguments to binary search
        binary_params = {k: v for k, v in params.items() if k in ("query_str", "ip", "md5", "filename", "url", "limit")}
        tool_res = binary_search.execute(**binary_params)
        
    else:
        # Fallback to search_security_events if we cannot classify it
        tools_executed.append("search_security_events")
        tool_res = event_search.execute(ip=intent_classifier.extract_ip(query))
        limitations.append("Intent classification was unclear; fell back to event search.")

    if tool_res.get("status") == "error":
        return {
            "status": "error",
            "intent": intent,
            "tools_used": tools_executed,
            "tools_executed": tools_executed,
            "data": {},
            "summary": f"Execution failed: {tool_res.get('message')}",
            "limitations": limitations + [tool_res.get("message")]
        }
        
    retrieved = tool_res.get("data", {})
    summary = generate_analyst_summary(query, tools_executed, retrieved)
    
    if username and resolved_ip:
        SESSION_MEMORIES[username] = {"last_ip": resolved_ip}
        
    return {
        "status": "success",
        "intent": intent,
        "tools_used": tools_executed,
        "tools_executed": tools_executed,
        "data": retrieved,
        "summary": summary,
        "limitations": limitations
    }
