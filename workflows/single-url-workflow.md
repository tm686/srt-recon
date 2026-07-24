# Single URL Workflow — No Subdomains, Just the App

## Your Real Problem

You're fuzzing directories, finding some paths, then drowning in output
with no clear next step. The issue: directory fuzzing finds SURFACE AREA
but doesn't find BUGS. Bugs live in application LOGIC, not file paths.

After fuzzing you need to shift from "discover more things" to
"understand how this specific application works and where it breaks."

## Phase 1: Understand the Application (15 minutes, not optional)

Before any tool, open the browser and USE the application like a human:

```
1. Browse every visible page
2. Note every form, input field, search box, file upload
3. Note every URL parameter you see
4. Check if there's registration/login (even if you can't auth)
5. Look at the tech stack (Wappalyzer extension or httpx -td)
6. Read the page source — look for comments, hidden forms, JS files
7. Check /robots.txt, /sitemap.xml, /humans.txt
8. Check response headers (Server, X-Powered-By, etc.)
```

Write down what the application DOES. Is it a:
- Corporate website (static, limited attack surface)
- Web application with login (focus on auth bypass, enumeration)
- API backend (focus on broken access control, injection)
- File sharing/management (focus on path traversal, upload bypass)
- E-commerce/payment (focus on business logic, IDOR, price manipulation)

This determines your entire approach.

## Phase 2: Targeted Fuzzing (not just raft-medium)

### Round 1: Quick hits and technology-specific paths
```bash
TARGET="https://example.com"

# Quick hits — these find admin panels, backup files, debug endpoints
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -mc all -fc 404 -ac -t 40 -o quickhits.json -of json

# Technology-specific (pick based on Phase 1):
# Java/Spring
ffuf -u "$TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -mc all -fc 404 -ac
# PHP
ffuf -u "$TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt -mc all -fc 404 -ac
# .NET
ffuf -u "$TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -mc all -fc 404 -ac
# WordPress
ffuf -u "$TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -mc all -fc 404 -ac
```

### Round 2: API discovery (this is where the bugs actually are)
```bash
# API endpoint discovery
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc all -fc 404 -ac

# Common API paths
ffuf -u "$TARGET/api/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -mc all -fc 404 -ac

# Version prefix variations
for prefix in api/v1 api/v2 api/v3 v1 v2; do
  ffuf -u "$TARGET/$prefix/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
    -mc all -fc 404 -ac -s 2>/dev/null | while read line; do
      echo "$prefix/$line"
    done
done

# Check for API documentation (immediate goldmine)
for path in swagger swagger-ui api-docs openapi.json swagger.json \
            docs redoc graphql graphiql api/swagger api/docs \
            _swagger swagger/index.html swagger-ui.html; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$CODE" != "404" ] && echo "$CODE $TARGET/$path"
done
```

### Round 3: Sensitive files and backups
```bash
# Backup and config files (where API keys and creds leak)
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200 -ac \
  -e .bak,.old,.conf,.config,.json,.xml,.yml,.yaml,.env,.sql,.log,.txt,.zip,.tar.gz,.swp,.sav,.orig

# Git/SVN exposure
for path in .git/HEAD .git/config .svn/entries .svn/wc.db; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$CODE" = "200" ] && echo "EXPOSED: $TARGET/$path"
done

# If .git is exposed:
# pip install git-dumper
# git-dumper "$TARGET/.git/" ./dumped_repo
```

### What to DO with fuzzing results

Stop collecting, start investigating. For each interesting find:

```
200 response on /admin, /dashboard, /panel, /manager?
  ACTION: Open it. Try default creds. Check for registration.
          Test 403-bypass techniques if redirected to login.

200 response on .json, .xml, .yaml, .env, .config?
  ACTION: Read the entire file. Search for: password, key, secret,
          token, api_key, database, connection_string, private

200 response on /api/*, /graphql, /swagger?
  ACTION: This is your #1 priority. Map every endpoint.
          Test each for auth bypass (remove cookies, does it work?)
          Test each for IDOR (change IDs in the response)

200 response on /upload, /import, /export, /download?
  ACTION: Test file upload bypass, path traversal in filenames,
          XXE in XML/XLSX uploads, SSRF via URL-based imports

403 response on interesting paths?
  ACTION: Don't skip. Run bypass techniques (see section below).

301/302 redirect on admin paths?
  ACTION: Check where it redirects. Sometimes the redirect itself
          leaks info. Try accessing with different methods (POST).
```

## Phase 3: JavaScript Analysis (this finds hidden endpoints)

JS files contain endpoints the UI doesn't expose. This is how people
find APIs that have broken access control:

```bash
# Crawl for JS files
katana -u "$TARGET" -jc -kf all -d 3 -silent | grep '\.js$' | sort -u > js_files.txt

# Also check page source manually:
curl -s "$TARGET" | grep -oP 'src="[^"]*\.js[^"]*"' | tr -d '"' | sed 's/src=//'

# Extract endpoints from JS
cat js_files.txt | while read url; do
  # Make absolute if relative
  [[ "$url" != http* ]] && url="${TARGET}${url}"
  curl -s "$url" 2>/dev/null
done | grep -oP '["'"'"'](/[a-zA-Z0-9_/\-\.]+)["'"'"']' | tr -d "\"'" | sort -u > js_endpoints.txt

# Now try to hit each discovered endpoint
cat js_endpoints.txt | while read ep; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${ep}" 2>/dev/null)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE ${TARGET}${ep}"
done > hidden_endpoints.txt

# Search JS for secrets directly
cat js_files.txt | while read url; do
  [[ "$url" != http* ]] && url="${TARGET}${url}"
  curl -s "$url" 2>/dev/null
done | grep -iE '(api[_-]?key|apikey|secret|token|password|auth|bearer|private[_-]?key|access[_-]?key|aws|firebase)' > js_secrets.txt
```

## Phase 4: Parameter Discovery (where injections actually live)

You said you're "testing random parameters hoping for SQLi or XSS."
Stop guessing. Find the real parameters:

```bash
# Arjun discovers hidden parameters on endpoints
arjun -u "$TARGET/search" -oJ arjun_search.json
arjun -u "$TARGET/api/users" -oJ arjun_api.json -m POST

# For each interesting endpoint from fuzzing
cat hidden_endpoints.txt | while read line; do
  code=$(echo "$line" | awk '{print $1}')
  url=$(echo "$line" | awk '{print $2}')
  [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ] && \
    arjun -u "$url" --stable -oJ "arjun_$(echo $url | md5sum | cut -c1-8).json" 2>/dev/null
done

# Also extract params from any URLs found by crawling
katana -u "$TARGET" -jc -kf all -d 3 -silent -o crawled_urls.txt
cat crawled_urls.txt | unfurl keys | sort -u > discovered_params.txt
```

## Phase 5: Systematic Vulnerability Testing

### For Every Input Field / Parameter Found:

```
INPUT TYPE          | WHAT TO TEST
--------------------|--------------------------------------------
Search box          | XSS: <img src=x onerror=alert(1)>
                    | SQLi: ' OR '1'='1' --
                    | SSTI: {{7*7}} or ${7*7}

Login form          | SQLi in username: admin'--
                    | Account enumeration: valid vs invalid user
                    |   different response = enumeration
                    | Brute force: is there rate limiting?
                    | 2FA bypass: can you skip the 2FA step?
                    |   (complete login, then go directly to
                    |    authenticated URL without entering 2FA)

File upload         | Extension bypass: .php.jpg, .pHp, .php%00.jpg
                    | Content-Type bypass: change to image/png
                    | SVG with XSS: <svg onload=alert(1)>
                    | XXE in .xlsx: unzip, inject entity, rezip
                    | Path traversal in filename: ../../../etc/cron.d/shell

URL parameter       | SSRF: url=http://169.254.169.254/
                    | Open redirect: url=//evil.com
                    | LFI: url=file:///etc/passwd

ID/numeric param    | IDOR: change the number, see other user data
                    | SQLi: id=1 AND 1=1 vs id=1 AND 1=2

Sort/order param    | SQLi: sort=name;SLEEP(5)--
                    | Often overlooked, often injectable

API JSON body       | Mass assignment: add "role":"admin","isAdmin":true
                    | NoSQLi: {"user":{"$ne":""},"pass":{"$ne":""}}
                    | Type juggling: send number where string expected
```

### 403 Bypass (don't skip blocked paths)
```bash
URL="https://example.com/admin"

# Path tricks
for p in "/admin" "/admin/" "/admin/." "//admin" "/./admin" \
         "/admin..;/" "/%2e/admin" "/admin%20" "/admin%09" \
         "/admin;" "/Admin" "/ADMIN" "/admin.json" "/admin?"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com${p}")
  [ "$CODE" != "403" ] && [ "$CODE" != "404" ] && echo "$CODE https://example.com${p}"
done

# Header tricks
for h in "X-Original-URL: /admin" \
         "X-Forwarded-For: 127.0.0.1" \
         "X-Custom-IP-Authorization: 127.0.0.1" \
         "X-Real-IP: 127.0.0.1" \
         "X-Forwarded-Host: 127.0.0.1"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$h" "$URL")
  [ "$CODE" != "403" ] && echo "$CODE Header: $h"
done

# Method swap
for m in GET POST PUT PATCH DELETE OPTIONS TRACE; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" "$URL")
  [ "$CODE" != "403" ] && echo "$CODE Method: $m"
done
```

## Phase 6: Nuclei (targeted, not spray-and-pray)

```bash
# Don't run all templates. Target what's relevant:

# Exposed panels and default creds
nuclei -u "$TARGET" -tags default-login,panel -severity medium,high,critical

# Tech-specific (based on what you identified in Phase 1)
nuclei -u "$TARGET" -tags apache,nginx,tomcat,wordpress,jira -severity medium,high,critical

# Misconfigurations and exposures
nuclei -u "$TARGET" -tags exposure,misconfig,config -severity medium,high,critical

# Known CVEs for the specific software version you found
nuclei -u "$TARGET" -tags cve -severity high,critical

# File disclosure
nuclei -u "$TARGET" -tags file,disclosure -severity medium,high,critical
```

## The Mental Model: Stop Discovering, Start Breaking

After Phase 2, you should have:
- A list of live endpoints
- Knowledge of the tech stack
- Hidden API endpoints from JS
- Discovered parameters

Now your job changes from "find more things" to "break each thing."

For each endpoint, ask:
1. What is this endpoint supposed to do?
2. What input does it take?
3. What happens if I give it unexpected input?
4. What happens if I remove authentication?
5. What happens if I change an ID to someone else's?
6. What happens if I change the HTTP method?
7. Does it handle XML? (XXE)
8. Does it fetch URLs? (SSRF)
9. Does it include files? (LFI)
10. Does it interact with a database? (SQLi)

If you can't answer these questions for an endpoint, you don't
understand it well enough yet. Go back and interact with it more
before trying to break it.

## Common SRT Gotcha: Information Overload

When ffuf gives you 500 results and you feel overwhelmed:

```bash
# Filter for only the interesting status codes
cat ffuf_out.json | jq '.results[] | select(.status == 200) | .url'

# Sort by response size — outliers are interesting
cat ffuf_out.json | jq '.results[] | select(.status == 200) | {url: .url, length: .length}' | sort

# Ignore the noise. Focus ONLY on:
# 1. Admin/management interfaces
# 2. API endpoints
# 3. File disclosure (.env, .config, .bak)
# 4. Upload/download functionality
# 5. Anything with input fields
# 6. 403s on interesting-sounding paths

# Everything else (static pages, marketing content, images) = skip
```
