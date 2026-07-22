// State management
let authToken = localStorage.getItem('token') || '';
let currentUsername = localStorage.getItem('username') || '';
let currentUserRole = localStorage.getItem('role') || '';

// DOM Elements
const authContainer = document.getElementById('auth-container');
const dashboardContainer = document.getElementById('dashboard-container');
const authForm = document.getElementById('auth-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const authMessage = document.getElementById('auth-message');
const btnLogin = document.getElementById('btn-login');
const btnRegister = document.getElementById('btn-register');
const btnLogout = document.getElementById('btn-logout');

const userDisplayName = document.getElementById('user-display-name');
const userDisplayRole = document.getElementById('user-display-role');
const chatFeed = document.getElementById('chat-feed');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const agentStatus = document.getElementById('agent-status');
const agentStatusText = document.getElementById('agent-status-text');
const protocolStats = document.getElementById('protocol-stats');

// Suggestion click helpers
window.setQuery = function(queryText) {
    chatInput.value = queryText;
    chatInput.focus();
};

// Check if user is already logged in on load
document.addEventListener('DOMContentLoaded', () => {
    if (authToken) {
        showDashboard();
    } else {
        showAuth();
    }
});

// Show login screen
function showAuth() {
    authContainer.classList.remove('hide');
    dashboardContainer.classList.add('hide');
}

// Show dashboard screen
function showDashboard() {
    authContainer.classList.add('hide');
    dashboardContainer.classList.remove('hide');
    userDisplayName.textContent = currentUsername;
    userDisplayRole.textContent = currentUserRole.toUpperCase();
    
    // Clear chat feed on login
    chatFeed.innerHTML = `
        <div class="chat-welcome">
            <div class="icon-wrap"><i class="fa-solid fa-robot"></i></div>
            <h1>Welcome, Security Analyst</h1>
            <p>I am your Agentic AI assistant. Submit natural language queries to investigate deception honeypots, attacker IP addresses, connection logs, or file reputations.</p>
            <div class="welcome-suggestions">
                <div class="suggest-card" onclick="setQuery('Show the top five attacking IP addresses.')">
                    <i class="fa-solid fa-circle-nodes"></i>
                    <h4>Top Attacking IPs</h4>
                    <p>Aggregates and counts attackers across all systems</p>
                </div>
                <div class="suggest-card" onclick="setQuery('Investigate the most active attacker')">
                    <i class="fa-solid fa-magnifying-glass-chart"></i>
                    <h4>Deep IP Investigation</h4>
                    <p>Correlates an IP's timestamps, protocols, credentials, and alerts</p>
                </div>
                <div class="suggest-card" onclick="setQuery('Show SQL injection activity.')">
                    <i class="fa-solid fa-shield-virus"></i>
                    <h4>Exploit Hunting</h4>
                    <p>Searches and parses web-based SQL injection attempts</p>
                </div>
            </div>
        </div>
    `;
    
    fetchDatabaseStats();
}

// Perform register
btnRegister.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) {
        showAuthError("Please fill out both username and password fields.");
        return;
    }
    
    try {
        btnRegister.disabled = true;
        btnRegister.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Registering...';
        
        const response = await fetch('/api/v1/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role: 'analyst' })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Auto login after registration
            await performLogin(username, password);
        } else {
            showAuthError(data.detail || "Registration failed. Username may already exist.");
        }
    } catch (e) {
        showAuthError("Network error. Could not connect to API.");
    } finally {
        btnRegister.disabled = false;
        btnRegister.textContent = 'Register Account';
    }
});

// Perform login submit
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    await performLogin(username, password);
});

async function performLogin(username, password) {
    try {
        btnLogin.disabled = true;
        btnLogin.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Logging in...';
        authMessage.classList.add('hide');
        
        const response = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.access_token;
            currentUsername = data.username;
            currentUserRole = data.role;
            
            localStorage.setItem('token', authToken);
            localStorage.setItem('username', currentUsername);
            localStorage.setItem('role', currentUserRole);
            
            showDashboard();
        } else {
            showAuthError(data.detail || "Login failed. Check credentials.");
        }
    } catch (e) {
        showAuthError("Network error. Could not connect to API.");
    } finally {
        btnLogin.disabled = false;
        btnLogin.textContent = 'Login';
    }
}

function showAuthError(msg) {
    authMessage.textContent = msg;
    authMessage.classList.remove('hide');
}

// Perform logout
btnLogout.addEventListener('click', () => {
    authToken = '';
    currentUsername = '';
    currentUserRole = '';
    localStorage.clear();
    showAuth();
});

// Fetch database distribution stats for sidebar
async function fetchDatabaseStats() {
    if (!authToken) return;
    try {
        const response = await fetch('/api/v1/chat', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ query: 'protocol summary' })
        });
        const res = await response.json();
        
        if (response.ok && res.status === 'success' && Array.isArray(res.data)) {
            renderSidebarStats(res.data);
        } else {
            protocolStats.innerHTML = '<div class="error-msg">Failed to load stats</div>';
        }
    } catch (e) {
        protocolStats.innerHTML = '<div class="error-msg">Connection error</div>';
    }
}

function renderSidebarStats(data) {
    protocolStats.innerHTML = '';
    if (data.length === 0) {
        protocolStats.innerHTML = '<div class="text-muted">No data in DB</div>';
        return;
    }
    
    // Find max for percentages
    const maxVal = Math.max(...data.map(d => d.event_count));
    
    data.forEach(item => {
        const percentage = maxVal > 0 ? (item.event_count / maxVal) * 100 : 0;
        const barGroup = document.createElement('div');
        barGroup.className = 'stat-bar-group';
        barGroup.innerHTML = `
            <div class="stat-bar-label">
                <span>${item.protocol}</span>
                <span>${item.event_count.toLocaleString()}</span>
            </div>
            <div class="stat-bar-track">
                <div class="stat-bar-fill" style="width: ${percentage}%"></div>
            </div>
        `;
        protocolStats.appendChild(barGroup);
    });
}

// Bind Quick Query Tokens click
document.querySelectorAll('.token-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const queryText = btn.getAttribute('data-query');
        chatInput.value = queryText;
        chatForm.dispatchEvent(new Event('submit'));
    });
});

// Submit Query chat
chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = chatInput.value.trim();
    if (!query) return;
    
    chatInput.value = '';
    
    // 1. Append user message
    appendMessage(query, 'user');
    
    // 2. Show agent loader
    showAgentStatus("Orchestrator thinking...");
    
    try {
        const response = await fetch('/api/v1/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ query })
        });
        
        // Update loader status
        showAgentStatus("Processing results...");
        
        const data = await response.json();
        
        if (response.ok) {
            appendMessage(data, 'agent', query);
        } else {
            if (response.status === 401) {
                // Token expired/invalid, logout
                btnLogout.click();
            } else {
                appendMessage({
                    status: 'error',
                    summary: data.detail || "Something went wrong while processing your request."
                }, 'agent', query);
            }
        }
    } catch (err) {
        appendMessage({
            status: 'error',
            summary: "Network error: Connection to the SOC API failed."
        }, 'agent', query);
    } finally {
        hideAgentStatus();
        fetchDatabaseStats(); // Refresh sidebar stats dynamically
    }
});

function showAgentStatus(text) {
    agentStatusText.textContent = text;
    agentStatus.classList.remove('hide');
}

function hideAgentStatus() {
    agentStatus.classList.add('hide');
}

function appendMessage(content, sender, originalQuery = '') {
    // Hide welcome panel if it is visible
    const welcome = document.querySelector('.chat-welcome');
    if (welcome) welcome.remove();
    
    const bubble = document.createElement('div');
    bubble.className = `msg-bubble ${sender}`;
    
    const avatar = document.createElement('div');
    avatar.className = 'msg-avatar';
    avatar.innerHTML = sender === 'user' ? '<i class="fa-solid fa-user"></i>' : '<i class="fa-solid fa-robot"></i>';
    bubble.appendChild(avatar);
    
    const body = document.createElement('div');
    body.className = 'msg-content';
    
    if (sender === 'user') {
        body.innerHTML = `<div class="msg-query-text">${escapeHTML(content)}</div>`;
    } else {
        // Agent response formatting
        renderAgentResponse(body, content, originalQuery);
    }
    
    bubble.appendChild(body);
    chatFeed.appendChild(bubble);
    
    // Scroll to bottom
    chatFeed.scrollTop = chatFeed.scrollHeight;
}

function renderAgentResponse(container, response, originalQuery) {
    // 1. Tool execution sequence pipeline
    if (response.tools_used && response.tools_used.length > 0) {
        const pipeline = document.createElement('div');
        pipeline.className = 'pipeline-flow';
        pipeline.innerHTML = '<span>Executed Pipeline: </span>';
        response.tools_used.forEach((tool, idx) => {
            if (idx > 0) {
                pipeline.innerHTML += '<span class="pipeline-arrow"><i class="fa-solid fa-chevron-right"></i></span>';
            }
            pipeline.innerHTML += `<span class="pipeline-tool">${tool}</span>`;
        });
        container.appendChild(pipeline);
    }
    
    // 2. Reject states
    if (response.status === 'rejected') {
        const rejectCard = document.createElement('div');
        rejectCard.className = 'rejection-card';
        rejectCard.innerHTML = `
            <i class="fa-solid fa-circle-exclamation"></i>
            <div class="rejection-details">
                <h4>Access Rejection</h4>
                <p>${escapeHTML(response.reason)}</p>
            </div>
        `;
        container.appendChild(rejectCard);
        return;
    }
    
    // 3. Error states
    if (response.status === 'error') {
        const errorCard = document.createElement('div');
        errorCard.className = 'rejection-card'; // Reuse styled warning box
        errorCard.innerHTML = `
            <i class="fa-solid fa-circle-xmark" style="color: var(--danger)"></i>
            <div class="rejection-details">
                <h4 style="color: var(--danger)">Query Execution Error</h4>
                <p>${escapeHTML(response.summary)}</p>
            </div>
        `;
        container.appendChild(errorCard);
        return;
    }
    
    // 4. Grounded summary
    if (response.summary) {
        const summary = document.createElement('div');
        summary.className = 'summary-block';
        summary.innerHTML = `<strong>Analyst Summary:</strong> ${escapeHTML(response.summary)}`;
        container.appendChild(summary);
    }
    
    // 5. Structure visual components based on intent
    const intent = response.intent;
    const data = response.data;
    
    if (data) {
        if (intent === 'get_top_attackers' && Array.isArray(data)) {
            renderTopAttackersTable(container, data);
        } else if (intent === 'investigate_ip') {
            renderIPInvestigationDetails(container, data);
        } else if (intent === 'get_protocol_summary' && Array.isArray(data)) {
            renderProtocolSummaryBars(container, data);
        } else if (intent === 'search_security_events' && Array.isArray(data)) {
            renderSecurityEventsTable(container, data);
        } else if (intent === 'search_binaries_analytics' && Array.isArray(data)) {
            renderBinariesSearchCards(container, data);
        }
    }
    
    // 6. Limitations warning
    if (response.limitations && response.limitations.length > 0) {
        const limBox = document.createElement('div');
        limBox.style.marginTop = '12px';
        limBox.style.fontSize = '0.75rem';
        limBox.style.color = 'var(--text-muted)';
        limBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Limitations: ${response.limitations.map(l => escapeHTML(l)).join(', ')}`;
        container.appendChild(limBox);
    }
}

// Render components helper
function renderTopAttackersTable(container, data) {
    if (data.length === 0) {
        container.innerHTML += '<p class="text-muted">No attacker data found.</p>';
        return;
    }
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    
    let rowsHtml = '';
    data.forEach((attacker, idx) => {
        rowsHtml += `
            <tr>
                <td><strong>#${idx + 1}</strong></td>
                <td><code style="font-family: var(--font-mono); color: var(--primary)">${attacker.source_ip}</code></td>
                <td><span class="badge" style="background: rgba(0, 229, 255, 0.1); color: var(--primary)">${attacker.event_count} events</span></td>
                <td>
                    <button class="investigate-shortcut-btn" onclick="triggerIPInvestigation('${attacker.source_ip}')">
                        <i class="fa-solid fa-magnifying-glass"></i> Investigate
                    </button>
                </td>
            </tr>
        `;
    });
    
    wrap.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Attacker IP</th>
                    <th>Count</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                ${rowsHtml}
            </tbody>
        </table>
    `;
    container.appendChild(wrap);
}

function renderIPInvestigationDetails(container, data) {
    // If it's a multi-step wrapped discovery, get the internal ip_investigation dictionary
    let details = data.ip_investigation || data;
    if (!details || Object.keys(details).length === 0 || !details.source_ip) {
        container.innerHTML += '<p class="text-muted">No metadata available for this IP address.</p>';
        return;
    }
    
    const card = document.createElement('div');
    card.style.marginTop = '12px';
    
    // Scorecard blocks
    let scorecards = `
        <div class="scorecard-grid">
            <div class="scorecard-item">
                <span>Total Events</span>
                <h3>${details.event_count || 0}</h3>
            </div>
            <div class="scorecard-item">
                <span>First Seen</span>
                <h4 style="font-size: 0.75rem; margin-top: 6px;">${details.first_seen ? formatDate(details.first_seen) : 'N/A'}</h4>
            </div>
            <div class="scorecard-item">
                <span>Last Seen</span>
                <h4 style="font-size: 0.75rem; margin-top: 6px;">${details.last_seen ? formatDate(details.last_seen) : 'N/A'}</h4>
            </div>
            <div class="scorecard-item large">
                <span>Log Sources Hit</span>
                <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:6px;">
                    ${details.tables_involved.map(t => `<span class="badge" style="background: rgba(100,50,255,0.15); color:var(--secondary); font-family:var(--font-mono);">${t}</span>`).join('')}
                </div>
            </div>
        </div>
    `;
    card.innerHTML = scorecards;
    
    // Usernames / Payloads / Malware sections
    let detailsHtml = '';
    
    // Usernames sub-badge
    if (details.usernames && details.usernames.length > 0) {
        detailsHtml += `
            <div style="margin-bottom: 10px; font-size: 0.85rem;">
                <strong>Observed Usernames:</strong> 
                ${details.usernames.map(u => `<code style="background: rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px;">${escapeHTML(u)}</code>`).join(' ')}
            </div>
        `;
    }
    
    // Paths visited sub-list
    if (details.paths_visited && details.paths_visited.length > 0) {
        detailsHtml += `
            <div class="expander-section">
                <div class="expander-header" onclick="toggleExpander(this)">
                    <span><i class="fa-solid fa-globe"></i> Web Paths / URLs Visited (${details.paths_visited.length})</span>
                    <i class="fa-solid fa-chevron-down"></i>
                </div>
                <div class="expander-content">
                    ${details.paths_visited.map(p => `<div class="payload-item">${escapeHTML(p)}</div>`).join('')}
                </div>
            </div>
        `;
    }
    
    // Payloads / Commands expanders
    if (details.commands_executed && details.commands_executed.length > 0) {
        detailsHtml += `
            <div class="expander-section">
                <div class="expander-header" onclick="toggleExpander(this)">
                    <span><i class="fa-solid fa-terminal"></i> Commands Executed (${details.commands_executed.length})</span>
                    <i class="fa-solid fa-chevron-down"></i>
                </div>
                <div class="expander-content">
                    ${details.commands_executed.map(c => `<div class="payload-item">${escapeHTML(c)}</div>`).join('')}
                </div>
            </div>
        `;
    }
    
    if (details.payloads_seen && details.payloads_seen.length > 0) {
        detailsHtml += `
            <div class="expander-section">
                <div class="expander-header" onclick="toggleExpander(this)">
                    <span><i class="fa-solid fa-code"></i> Shell Payloads / Raw Logs (${details.payloads_seen.length})</span>
                    <i class="fa-solid fa-chevron-down"></i>
                </div>
                <div class="expander-content">
                    ${details.payloads_seen.map(pl => `<div class="payload-item">${escapeHTML(pl)}</div>`).join('')}
                </div>
            </div>
        `;
    }
    
    // Associated malware details
    if (details.associated_binaries && details.associated_binaries.length > 0) {
        let binRows = '';
        details.associated_binaries.forEach(bin => {
            let maliciousBadge = '<span style="color:var(--success)">Clean / Safe</span>';
            // Simple heuristic to determine if verdicts contains malicious flag
            if (bin.verdicts && bin.verdicts.some(v => v.toUpperCase() === 'MALICIOUS')) {
                maliciousBadge = '<span style="color:var(--danger); font-weight:bold;"><i class="fa-solid fa-biohazard"></i> Malicious</span>';
            }
            binRows += `
                <tr>
                    <td><a href="https://www.virustotal.com/gui/file/${bin.md5_hash}" target="_blank" class="hash-link" title="Open in VirusTotal">${bin.md5_hash.substring(0,8)}...</a></td>
                    <td><code style="font-size:0.75rem">${escapeHTML(bin.filename)}</code></td>
                    <td>${maliciousBadge}</td>
                </tr>
            `;
        });
        
        detailsHtml += `
            <div class="expander-section">
                <div class="expander-header" onclick="toggleExpander(this)">
                    <span><i class="fa-solid fa-box-open"></i> Associated Binaries / Malware Logs (${details.associated_binaries.length})</span>
                    <i class="fa-solid fa-chevron-down"></i>
                </div>
                <div class="expander-content">
                    <table class="malware-table">
                        <thead>
                            <tr>
                                <th>MD5 Hash</th>
                                <th>Filename</th>
                                <th>Reputation</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${binRows}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }
    
    card.innerHTML += detailsHtml;
    container.appendChild(card);
}

function renderProtocolSummaryBars(container, data) {
    if (data.length === 0) return;
    const wrap = document.createElement('div');
    wrap.style.marginTop = '12px';
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';
    wrap.style.gap = '10px';
    
    const maxVal = Math.max(...data.map(d => d.event_count));
    
    data.forEach(item => {
        const percentage = maxVal > 0 ? (item.event_count / maxVal) * 100 : 0;
        wrap.innerHTML += `
            <div style="font-size: 0.8rem;">
                <div style="display:flex; justify-content:space-between; margin-bottom:3px;">
                    <strong>${item.protocol}</strong>
                    <span>${item.event_count.toLocaleString()} events</span>
                </div>
                <div style="height:8px; background:rgba(255,255,255,0.05); border-radius:4px; overflow:hidden;">
                    <div style="height:100%; width:${percentage}%; background:linear-gradient(90deg, var(--primary), var(--secondary)); border-radius:4px;"></div>
                </div>
            </div>
        `;
    });
    container.appendChild(wrap);
}

function renderSecurityEventsTable(container, data) {
    if (data.length === 0) {
        container.innerHTML += '<p class="text-muted">No matching security events found.</p>';
        return;
    }
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    
    let rowsHtml = '';
    data.forEach(event => {
        const ip = event.attacker_ip || 'N/A';
        const user = event.username || '-';
        const dateStr = event.timestamp ? formatDate(event.timestamp) : 'N/A';
        rowsHtml += `
            <tr>
                <td><span class="badge" style="background: rgba(255, 255, 255, 0.05); color: var(--text-muted); font-size:0.7rem;">${event.source_table}</span></td>
                <td><code style="color:var(--primary); font-family:var(--font-mono); font-size:0.8rem;">${ip}</code></td>
                <td><code style="font-size:0.8rem;">${escapeHTML(user)}</code></td>
                <td><span style="font-size:0.75rem; color:var(--text-muted);">${dateStr}</span></td>
                <td><span class="badge" style="background: rgba(100,50,255,0.1); color:var(--secondary); font-size:0.7rem;">${event.protocol}</span></td>
            </tr>
        `;
    });
    
    wrap.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Table</th>
                    <th>Source IP</th>
                    <th>Username</th>
                    <th>Timestamp</th>
                    <th>Protocol</th>
                </tr>
            </thead>
            <tbody>
                ${rowsHtml}
            </tbody>
        </table>
    `;
    container.appendChild(wrap);
}

function renderBinariesSearchCards(container, data) {
    if (data.length === 0) {
        container.innerHTML += '<p class="text-muted">No binary analytics records found.</p>';
        return;
    }
    const wrap = document.createElement('div');
    wrap.style.marginTop = '12px';
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';
    wrap.style.gap = '10px';
    
    data.forEach(bin => {
        let isMalicious = false;
        let labels = ['PE File'];
        if (bin.details && bin.details.file_details && bin.details.file_details.data) {
            const attrs = bin.details.file_details.data.attributes || {};
            const verdicts = bin.details.verdicts || [];
            if (verdicts.some(v => v.toUpperCase() === 'MALICIOUS')) {
                isMalicious = true;
            }
        }
        
        wrap.innerHTML += `
            <div style="background:rgba(0,0,0,0.2); border:1px solid ${isMalicious ? 'rgba(255,42,133,0.3)' : 'var(--border-color)'}; padding:14px; border-radius:var(--radius-md);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-family:var(--font-mono); font-weight:600; color:var(--primary); font-size:0.85rem;">MD5: ${bin.md5_hash}</span>
                    <span class="badge" style="background:${isMalicious ? 'rgba(255,42,133,0.15)' : 'rgba(0,229,255,0.1)'}; color:${isMalicious ? 'var(--danger)' : 'var(--primary)'}">
                        ${isMalicious ? '<i class="fa-solid fa-triangle-exclamation"></i> Malicious' : 'Clean / Safe'}
                    </span>
                </div>
                <div style="font-size:0.8rem; line-height:1.5;">
                    <div><strong>Filename:</strong> <code>${escapeHTML(bin.filename || 'unknown')}</code></div>
                    <div><strong>Attacker Source IP:</strong> <code>${bin.attacker_ip || 'unknown'}</code></div>
                    <div><strong>Download URL:</strong> <span class="text-muted" style="word-break:break-all;">${escapeHTML(bin.url || 'N/A')}</span></div>
                </div>
            </div>
        `;
    });
    container.appendChild(wrap);
}

// Global Expander toggler
window.toggleExpander = function(headerEl) {
    const content = headerEl.nextElementSibling;
    const icon = headerEl.querySelector('.fa-chevron-down') || headerEl.querySelector('.fa-chevron-up');
    
    if (content.classList.contains('show')) {
        content.classList.remove('show');
        if (icon) {
            icon.classList.remove('fa-chevron-up');
            icon.classList.add('fa-chevron-down');
        }
    } else {
        content.classList.add('show');
        if (icon) {
            icon.classList.remove('fa-chevron-down');
            icon.classList.add('fa-chevron-up');
        }
    }
};

// Global triggering of IP investigation
window.triggerIPInvestigation = function(ip) {
    chatInput.value = `Investigate IP ${ip}`;
    chatForm.dispatchEvent(new Event('submit'));
};

// Utility function to format timestamp string nicely
function formatDate(isoStr) {
    try {
        const date = new Date(isoStr);
        return date.toLocaleString();
    } catch(e) {
        return isoStr;
    }
}

// Utility function to prevent HTML insertion exploits
function escapeHTML(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
