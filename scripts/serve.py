#!/usr/bin/env python3
"""Servidor HTTP local para o frontend do CVE Finder.

Serve os arquivos estaticos de frontend/ e expoe duas rotas de API que
chamam o binario `bin/cve_query` (compilado a partir de src/query.c) por
busca - ou seja, quem realmente responde a busca e' o mesmo codigo em C
testado no resto do projeto (finder_search / finder_search_product), nao
uma reimplementacao em Python ou JavaScript.

Uso: python3 scripts/serve.py  (ou `make serve`, que compila cve_query
primeiro). So' biblioteca padrao do Python, nenhuma dependencia externa.
"""

from __future__ import annotations

import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
QUERY_BIN = PROJECT_ROOT / "bin" / ("cve_query.exe" if sys.platform == "win32" else "cve_query")
PORT = 8000
SUBPROCESS_TIMEOUT_SECONDS = 10


def run_query(mode: str, query: str) -> tuple[int, bytes]:
    """Chama bin/cve_query e devolve (status_http, corpo_json_em_bytes)."""

    if not QUERY_BIN.exists():
        message = json.dumps({"error": f"{QUERY_BIN} nao existe. Rode `make serve` (ele compila antes)."})
        return 500, message.encode("utf-8")

    try:
        result = subprocess.run(
            [str(QUERY_BIN), mode, query],
            cwd=PROJECT_ROOT,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        message = json.dumps({"error": "A busca demorou demais e foi cancelada."})
        return 504, message.encode("utf-8")

    output = result.stdout.strip()
    if not output:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        message = json.dumps({"error": stderr or "cve_query nao respondeu nada."})
        return 500, message.encode("utf-8")

    # cve_query sempre imprime um objeto JSON valido (sucesso ou erro) -
    # so' repassamos como veio; o front distingue pelo campo "error".
    return 200, output


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self) -> None:
        parsed = urlparse(self.path)
        rel_path = parsed.path.lstrip("/") or "index.html"
        file_path = (FRONTEND_DIR / rel_path).resolve()

        # Nao deixa escapar de frontend/ (ex.: ../../algo_sensivel).
        if FRONTEND_DIR not in file_path.parents and file_path != FRONTEND_DIR:
            self.send_error(403, "Proibido")
            return
        if not file_path.is_file():
            self.send_error(404, "Nao encontrado")
            return

        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
        }
        content_type = content_types.get(file_path.suffix, "application/octet-stream")
        data = file_path.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (nome exigido pela biblioteca padrao)
        parsed = urlparse(self.path)

        if parsed.path in ("/api/cve", "/api/product"):
            mode = "cve" if parsed.path == "/api/cve" else "product"
            query = parse_qs(parsed.query).get("q", [""])[0].strip()
            if not query:
                self._send_json(400, json.dumps({"error": "Parametro q vazio."}).encode("utf-8"))
                return
            status, body = run_query(mode, query)
            self._send_json(status, body)
            return

        self._serve_static()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write("[serve] " + (format % args) + "\n")


def main() -> None:
    if not FRONTEND_DIR.is_dir():
        raise SystemExit(f"Diretorio nao encontrado: {FRONTEND_DIR}")

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}/"
    print(f"CVE Finder rodando em {url}  (Ctrl+C para parar)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
