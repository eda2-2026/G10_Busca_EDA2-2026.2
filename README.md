# G10_Busca_EDA2-2026.2

CVE Finder — trabalho 1 de Estrutura de Dados 2 (EDA2). Carrega a base de
CVEs de 2025 (formato oficial do MITRE, normalizada em CSV) e permite
buscar uma CVE pelo ID usando **busca binária**, mostrando o ano, se ela
foi aprovada (`PUBLISHED`) ou rejeitada (`REJECTED`) e os produtos que ela
afetou.

Link da Apresentação:
<div align="center">
  <br>
  <iframe width="560" height="315" src="https://www.youtube.com" title="Apresentação Trabalho 1 EDA2" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
</div>

## Arquitetura

O código em C é organizado em camadas, cada uma testável isoladamente:

```text
dados        csv.c      -> parsing CSV genérico (linhas, aspas, escapes)
             cve.c      -> struct CVE + carga de data/cves.csv
             product.c  -> struct Product + carga de data/products.csv
             json.c     -> parsing/escrita JSON genérico
             selection.c -> struct Selection + persistência em output/selections.json

algoritmo    search.c   -> busca binária por (ano, número) em CVEArray

aplicação    finder.c   -> junta busca de CVE + produtos numa operação só

interface    main.c     -> REPL: lê um CVE-ID do teclado, mostra o resultado,
                            grava a seleção em output/selections.json
```

A extração/normalização dos dados fica em Python
(`scripts/generate_cves_2025.py`); a busca em si é toda em C.

## Estrutura de diretórios

```text
data/       cves.csv, products.csv, vendors.csv, replacements.csv (base normalizada)
include/    headers dos módulos em C
src/        implementação dos módulos em C
scripts/    generate_cves_2025.py (gera os CSVs de data/ a partir do dump oficial do MITRE)
tests/c/    testes em C (Unity)
tests/python/ testes do script Python (pytest)
tests/unity/  framework de testes Unity (vendorizada, MIT license)
output/     gerado em runtime pelo REPL (output/selections.json) - não versionado
```

## Build

Requer `gcc` e `make` (Linux). Sem dependências externas para compilar
(a Unity já vem vendorizada em `tests/unity/`).

```sh
make          # compila bin/cve_finder
make clean    # remove build/ e bin/
```

## Rodar o finder

```sh
./bin/cve_finder
```

Abre um prompt interativo. Digite um CVE-ID (ex.: `CVE-2025-0001`, aceita
minúsculas e espaços nas pontas) e `sair` (ou `exit`, ou `Ctrl+D`) para
encerrar. Toda busca com sucesso é gravada em `output/selections.json`,
acumulando entre execuções (sem duplicar por `cve_id`) — pensado para um
frontend futuro consumir essa lista. Formato de cada entrada:

```json
{"cve_id": "CVE-2025-0001", "year": 2025, "state": "PUBLISHED", "products": ["Abacus"]}
```

## Testes

```sh
make test           # roda os testes em C e em Python
make test-c          # só os testes em C (um binário por módulo: bin/test_*)
make test-python      # só os testes em Python (pytest tests/python)
```

Cobertura atual: 108 testes em C (parsing CSV, carga de CVEs/produtos,
busca binária, JSON, persistência de seleções, junção CVE+produtos) + 31
testes em Python (funções de normalização e o pipeline completo de
geração dos CSVs, com fixtures sintéticas via `monkeypatch` — sem
depender do dump oficial completo).

## Origem dos dados

`data/*.csv` já vem pronto no repositório. Para regenerá-lo a partir do
dump oficial da MITRE (`cvelistV5`, não versionado aqui):

```sh
python3 scripts/generate_cves_2025.py --source /caminho/para/cvelistV5/cves/2025
```

O script é determinístico e só usa a biblioteca padrão do Python.
