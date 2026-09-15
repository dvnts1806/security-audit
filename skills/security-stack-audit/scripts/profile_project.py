#!/usr/bin/env python3
"""
profile_project.py — Build an architecture & exposure profile of a codebase.

A dependency CVE only matters in proportion to how the code actually uses it.
This script gathers cheap, deterministic signals about the project's shape so the
audit can prioritize by *reachability and exposure* instead of treating every
advisory equally:

  * language mix (by file count and rough LOC)
  * detected frameworks / runtimes (web servers, ORMs, cloud SDKs)
  * likely entry points (what actually boots the app)
  * exposed surfaces (HTTP servers, routes, listening ports, public handlers)
  * deployment surface (Dockerfiles, compose, CI, IaC)
  * security-relevant touchpoints (auth, crypto, secrets, deserialization,
    subprocess/exec, raw SQL) — as *pointers for the agent to inspect*, not verdicts

It reasons about signals, not semantics: it points the agent at the files worth
reading. The agent reads them and forms the architectural judgment.

Stdlib only, no network. Bounded: caps files scanned and bytes read per file so
it stays fast on large repos.

Usage:
    python3 profile_project.py [PROJECT_DIR] [--json OUT.json] [--max-files 20000]
"""
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", "dist",
    "build", "target", ".next", ".nuxt", ".gradle", ".idea", ".pytest_cache",
    "site-packages", ".cargo", ".terraform", "coverage", ".cache",
}

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".java": "Java", ".kt": "Kotlin",
    ".cs": "C#", ".c": "C", ".h": "C/C++", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
    ".sh": "Shell", ".sql": "SQL", ".html": "HTML", ".css": "CSS", ".vue": "Vue",
    ".svelte": "Svelte", ".dart": "Dart",
}

CODE_EXTS = set(LANG_BY_EXT) - {".html", ".css", ".sql"}

# framework/library signatures: label -> (list of regexes, list of ecosystems it hints)
FRAMEWORK_SIGNATURES = {
    # web servers / frameworks
    "Express (Node)": [r"require\(['\"]express['\"]\)", r"from ['\"]express['\"]"],
    "Next.js": [r"from ['\"]next", r"\"next\"\s*:"],
    "NestJS": [r"@nestjs/"],
    "Fastify": [r"require\(['\"]fastify['\"]\)", r"from ['\"]fastify['\"]"],
    "Koa": [r"require\(['\"]koa['\"]\)"],
    "Flask": [r"from flask import", r"Flask\(__name__\)"],
    "Django": [r"from django", r"DJANGO_SETTINGS_MODULE", r"manage\.py"],
    "FastAPI": [r"from fastapi import", r"FastAPI\("],
    "Tornado": [r"import tornado"],
    "Gin (Go)": [r"github\.com/gin-gonic/gin"],
    "Echo (Go)": [r"github\.com/labstack/echo"],
    "net/http (Go)": [r"http\.ListenAndServe"],
    "Rails": [r"Rails::Application", r"rails/all"],
    "Sinatra": [r"require ['\"]sinatra['\"]"],
    "Spring Boot": [r"org\.springframework\.boot", r"@SpringBootApplication"],
    "Laravel": [r"laravel/framework", r"Illuminate\\\\"],
    "ASP.NET": [r"Microsoft\.AspNetCore"],
    "Actix (Rust)": [r"actix_web"],
    "Axum (Rust)": [r"\baxum\b"],
    # data / infra
    "SQL/ORM": [r"sqlalchemy", r"sequelize", r"typeorm", r"gorm\.io", r"ActiveRecord",
                r"prisma", r"mongoose", r"psycopg2", r"pg\.Pool", r"mysql2"],
    "Redis": [r"import redis", r"require\(['\"]redis['\"]\)", r"go-redis"],
    "GraphQL": [r"graphql", r"apollo-server"],
    "gRPC": [r"grpc"],
    # cloud SDKs
    "AWS SDK": [r"boto3", r"aws-sdk", r"aws-sdk-go"],
    "GCP SDK": [r"google\.cloud", r"cloud\.google\.com/go"],
    "Azure SDK": [r"azure\.", r"Azure\."],
    # auth
    "JWT": [r"jsonwebtoken", r"pyjwt", r"jwt\.encode", r"github\.com/golang-jwt"],
    "OAuth/OIDC": [r"passport", r"authlib", r"oauth2", r"openid"],
}

# security touchpoints: label -> regex — pointers for the agent to inspect
SECURITY_TOUCHPOINTS = {
    "shell/exec": r"(subprocess\.|os\.system\(|child_process|exec\.Command|Runtime\.getRuntime|shell_exec|`.*\$\{)",
    "raw SQL / string-built query": r"(execute\(\s*[\"'].*(SELECT|INSERT|UPDATE|DELETE)|\.query\(\s*[\"'`].*\+|f[\"'].*(SELECT|INSERT).*\{)",
    "deserialization": r"(pickle\.load|yaml\.load\(|Marshal\.load|ObjectInputStream|unserialize\()",
    "crypto": r"(hashlib\.|crypto\.|bcrypt|scrypt|argon2|AES|RSA|createCipher|MessageDigest)",
    "secrets in code": r"(?i)(api[_-]?key|secret|passwd|password|token|private[_-]?key)\s*[:=]\s*[\"'][^\"'\s]{6,}",
    "template rendering (SSTI surface)": r"(render_template_string|Template\(.*\{\{|ejs\.render|jinja2)",
    "file upload / path": r"(multer|request\.files|MultipartFile|os\.path\.join\(.*request|sendFile\()",
    "CORS wildcard": r"(Access-Control-Allow-Origin[\"'\s:]*\*|cors\(\{[^}]*origin:\s*[\"']\*)",
}

ROUTE_PATTERNS = [
    r"@app\.(get|post|put|delete|patch|route)\b",           # flask/fastapi
    r"@(Get|Post|Put|Delete|Patch)\(",                       # nest
    r"\.(get|post|put|delete|patch|use)\(\s*[\"'`]/",        # express/koa
    r"router\.(get|post|put|delete|patch)\(",                # express router
    r"\b(GET|POST|PUT|DELETE|PATCH)\s+/",                    # go mux style / comments
    r"path\(", r"re_path\(", r"urlpatterns",                 # django
    r"resources?\s+:", r"(get|post|put|delete)\s+[\"']/",    # rails routes
]

ENTRYPOINT_NAMES = {
    "main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "__main__.py",
    "index.js", "index.ts", "server.js", "server.ts", "app.js", "app.ts", "main.js", "main.ts",
    "main.go", "index.php", "artisan", "config.ru", "Program.cs",
}
ENTRYPOINT_DIR_HINTS = ("cmd/", "bin/")

DEPLOY_FILES = {
    "Dockerfile": "container image",
    "docker-compose.yml": "container orchestration (local/compose)",
    "docker-compose.yaml": "container orchestration (local/compose)",
    "Procfile": "process manifest (Heroku-style)",
    "serverless.yml": "serverless functions",
    "vercel.json": "Vercel deploy",
    "netlify.toml": "Netlify deploy",
    "main.tf": "Terraform IaC",
}
CI_DIRS_FILES = [
    (".github/workflows", "GitHub Actions"),
    (".gitlab-ci.yml", "GitLab CI"),
    ("Jenkinsfile", "Jenkins"),
    (".circleci", "CircleCI"),
]

MAX_BYTES_PER_FILE = 400_000


def _iter_files(root, max_files):
    count = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and
                   not (d.startswith(".") and d not in {".github"})]
        for f in files:
            yield os.path.join(dirpath, f)
            count += 1
            if count >= max_files:
                return


def _read_head(path, limit=MAX_BYTES_PER_FILE):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def profile(root, max_files=20000):
    root = os.path.abspath(root)
    lang_files = Counter()
    lang_loc = Counter()
    frameworks = defaultdict(int)
    touchpoints = defaultdict(list)   # label -> [relpaths]
    route_hits = 0
    listening_ports = set()
    entry_points = []
    deploy = {}
    ci = []
    total_files = 0
    scanned_code = 0

    def rel(p):
        return os.path.relpath(p, root)

    # deployment / CI presence (cheap, name-based)
    for name, desc in DEPLOY_FILES.items():
        # search shallowly (root + one level) for common deploy files
        for base in (root,):
            cand = os.path.join(base, name)
            if os.path.exists(cand):
                deploy[rel(cand)] = desc
    for target, label in CI_DIRS_FILES:
        if os.path.exists(os.path.join(root, target)):
            ci.append(label)

    port_re = re.compile(r"(?:EXPOSE\s+|listen\(|ListenAndServe\(\s*[\"']?:?|PORT\s*[:=]\s*)(\d{2,5})")

    for path in _iter_files(root, max_files):
        total_files += 1
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()

        if base in DEPLOY_FILES:
            deploy[rel(path)] = DEPLOY_FILES[base]

        # entry points
        if base in ENTRYPOINT_NAMES or any(h in rel(path).replace("\\", "/") for h in ENTRYPOINT_DIR_HINTS) and ext in CODE_EXTS:
            if base in ENTRYPOINT_NAMES:
                entry_points.append(rel(path))

        if ext not in LANG_BY_EXT:
            # still scan Dockerfile/compose for exposed ports
            if base.startswith("Dockerfile") or base.startswith("docker-compose"):
                text = _read_head(path)
                for m in port_re.finditer(text):
                    listening_ports.add(m.group(1))
            continue

        lang = LANG_BY_EXT[ext]
        lang_files[lang] += 1
        text = _read_head(path)
        lang_loc[lang] += text.count("\n") + 1
        if ext in CODE_EXTS:
            scanned_code += 1

        # frameworks
        for label, patterns in FRAMEWORK_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, text):
                    frameworks[label] += 1
                    break

        # routes
        for pat in ROUTE_PATTERNS:
            route_hits += len(re.findall(pat, text))

        # ports
        for m in port_re.finditer(text):
            listening_ports.add(m.group(1))

        # security touchpoints (record a handful of locations each)
        for label, pat in SECURITY_TOUCHPOINTS.items():
            if re.search(pat, text):
                if len(touchpoints[label]) < 15:
                    touchpoints[label].append(rel(path))

    # de-dup + rank frameworks by hit count
    fw_sorted = sorted(frameworks.items(), key=lambda kv: -kv[1])
    primary_langs = [l for l, _ in lang_files.most_common(5)]

    # crude "web-exposed" verdict
    web_frameworks = [f for f, _ in fw_sorted if any(
        k in f for k in ("Express", "Next", "Nest", "Fastify", "Koa", "Flask",
                         "Django", "FastAPI", "Tornado", "Gin", "Echo", "net/http",
                         "Rails", "Sinatra", "Spring", "Laravel", "ASP.NET",
                         "Actix", "Axum"))]
    is_web = bool(web_frameworks or route_hits > 0 or listening_ports)

    return {
        "project": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {"files_seen": total_files, "code_files_scanned": scanned_code},
        "languages": [
            {"language": l, "files": lang_files[l], "approx_loc": lang_loc[l]}
            for l in [x for x, _ in lang_files.most_common()]
        ],
        "primary_languages": primary_langs,
        "frameworks_detected": [{"name": n, "signal_files": c} for n, c in fw_sorted],
        "web_frameworks": web_frameworks,
        "exposure": {
            "internet_facing_likely": is_web,
            "route_definition_hits": route_hits,
            "listening_ports": sorted(listening_ports, key=lambda x: int(x)),
        },
        "entry_points": sorted(set(entry_points)),
        "deployment": deploy,
        "ci": ci,
        "security_touchpoints": {k: v for k, v in touchpoints.items()},
        "reachability_hint": (
            "Web/service-exposed: prioritize advisories in request-handling, "
            "parsing, auth, and serialization paths."
            if is_web else
            "No obvious network surface detected: remote-exploitation advisories may "
            "be lower priority than local/build-time ones. Confirm by reading entry points."
        ),
    }


def render_summary(p):
    lines = ["# Architecture & Exposure Profile", ""]
    lines.append(f"- **Project:** `{p['project']}`")
    lines.append(f"- **Primary languages:** {', '.join(p['primary_languages']) or 'unknown'}")
    if p["web_frameworks"]:
        lines.append(f"- **Web frameworks:** {', '.join(p['web_frameworks'])}")
    lines.append(f"- **Internet-facing likely:** {'yes' if p['exposure']['internet_facing_likely'] else 'no obvious surface'}")
    if p["exposure"]["listening_ports"]:
        lines.append(f"- **Ports:** {', '.join(p['exposure']['listening_ports'])}")
    if p["entry_points"]:
        lines.append(f"- **Entry points:** {', '.join(p['entry_points'][:8])}")
    if p["deployment"]:
        lines.append(f"- **Deployment:** {', '.join(sorted(set(p['deployment'].values())))}")
    if p["ci"]:
        lines.append(f"- **CI:** {', '.join(p['ci'])}")
    if p["security_touchpoints"]:
        lines.append("")
        lines.append("**Security touchpoints to inspect:**")
        for label, files in p["security_touchpoints"].items():
            lines.append(f"- {label}: {', '.join(files[:5])}" + (" …" if len(files) > 5 else ""))
    lines.append("")
    lines.append(f"> {p['reachability_hint']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Profile a project's architecture and exposure.")
    ap.add_argument("project_dir", nargs="?", default=".")
    ap.add_argument("--json", dest="out")
    ap.add_argument("--max-files", type=int, default=20000)
    ap.add_argument("--summary", action="store_true", help="Print markdown summary instead of JSON")
    args = ap.parse_args(argv)

    p = profile(args.project_dir, max_files=args.max_files)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(p, fh, indent=2)
    if args.summary:
        print(render_summary(p))
    else:
        print(json.dumps(p, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
