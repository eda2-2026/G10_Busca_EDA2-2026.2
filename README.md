# G10_Busca_EDA2-2026.2

#### Enzo Menali Vettorato Toledo  - 241011054
#### Paulo Vitor Gomes de Brito Matos - 241025971

CVE Finder — trabalho 1 de Estrutura de Dados 2 (EDA2). Carrega a base de
CVEs de 2025 (formato oficial do MITRE, normalizada em CSV — 45.206
registros) e permite buscar por **CVE-ID** ou por **produto** usando
**busca binária**, mostrando o ano, se a CVE foi aprovada (`PUBLISHED`) ou
rejeitada (`REJECTED`) e os produtos que ela afetou. Inclui um benchmark
que mede o custo real da busca binária contra uma busca sequencial, e uma
interface web local que roda essas mesmas buscas ao vivo.

Link da Apresentação:
<div align="center">
  <br>
  <iframe width="560" height="315" src="https://www.youtube.com/embed/_XWHbnYXUGA" title="Apresentação Trabalho 1 EDA2" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
</div>

## Arquitetura

O código em C é organizado em camadas, cada uma testável isoladamente:

```text
dados        csv.c          -> parsing CSV genérico (linhas, aspas, escapes)
             cve.c          -> struct CVE + carga de data/cves.csv
             product.c      -> struct Product + carga de data/products.csv
             json.c         -> parsing/escrita JSON genérico
             selection.c    -> struct Selection + persistência em output/selections.json

algoritmo    search.c       -> busca binária/sequencial por (ano, número) em CVEArray
             product_index.c -> índice secundário por nome de produto (qsort) +
                                 busca binária/sequencial por nome

aplicação    finder.c       -> junta busca de CVE + produtos, e busca por produto,
                                numa operação só

interfaces   main.c         -> REPL: menu (1 CVE-ID / 2 produto / 0 sair),
                                grava cada busca com sucesso em output/selections.json
             bench.c        -> mede comparações e tempo: binária vs sequencial,
                                grava output/benchmark.json
             query.c        -> uma busca por chamada, em JSON no stdout - usado
                                pelo servidor local; formata a saída do Finder e
                                persiste as buscas de CVE encontradas
```

A extração/normalização dos dados fica em Python
(`scripts/generate_cves_2025.py`); toda busca é em C. O servidor HTTP local
(`scripts/serve.py`) e a página (`frontend/index.html`) são a única parte
fora do C - e mesmo assim quem responde cada busca é o binário `cve_query`,
chamado como subprocesso.

## Estrutura de diretórios

```text
data/         cves.csv, products.csv, vendors.csv, replacements.csv (base normalizada)
include/      headers dos módulos em C
src/          implementação dos módulos em C
scripts/      generate_cves_2025.py (gera os CSVs a partir do dump oficial do MITRE)
              serve.py (servidor HTTP local do frontend, só biblioteca padrão)
frontend/     index.html - interface web local
tests/c/      testes em C (Unity)
tests/python/ testes do script Python (pytest)
tests/unity/  framework de testes Unity 
output/       gerado em runtime (selections.json, benchmark.json) - não versionado
```

## Build

Requer `gcc`, `make` e `python3` (Linux e Windows). Sem dependências
externas para compilar (a Unity já vem vendorizada em `tests/unity/`) nem
para rodar o servidor (só biblioteca padrão do Python).

```sh
make          # compila bin/cve_finder e bin/cve_query
make clean    # remove build/ e bin/
```

## Rodar o finder (CLI)

```sh
./bin/cve_finder
```

Abre um menu interativo:

```text
1 - Buscar por CVE
2 - Buscar por produto
0 - Sair
```

CVE-ID aceita minúsculas e espaços nas pontas (ex.: `cve-2025-0001`); a
busca por produto é exata, exige o nome completo e ignora caixa
(`wordpress` == `WordPress`). Toda busca de CVE com sucesso é gravada em
`output/selections.json`, acumulando entre execuções sem duplicar por
`cve_id`:

```json
{"cve_id": "CVE-2025-0001", "year": 2025, "state": "PUBLISHED", "products": ["Abacus"]}
```

## Rodar a interface web local

```sh
make serve
```

Compila `bin/cve_query` e sobe um servidor em `http://127.0.0.1:8000/`
(Ctrl+C para parar). A página tem dois campos de busca (CVE-ID e produto,
mesmo menu do CLI) que chamam de verdade o binário `cve_query` a cada
consulta - não é uma reimplementação em JavaScript. Para CVEs publicadas,
o resultado mostra título (quando existente), descrição em inglês e
produtos associados; para CVEs rejeitadas, mostra o motivo da rejeição.
As buscas de CVE encontradas também são gravadas em
`output/selections.json`. Cada busca mostra, lado a lado, quantas
comparações a **busca binária** e a **busca sequencial** fizeram para
aquela mesma consulta (útil para ver o efeito na prática: numa busca que
não existe, a diferença é brutal; num elemento bem no início do array
carregado, a sequencial pode até "ganhar" - é matematicamente esperado,
não um bug). Como o servidor recarrega a base inteira a cada busca, a
resposta leva ~0,3-0,5s.

## Rodar o benchmark

```sh
make bench
```

Compila `bin/cve_bench` e mede, em 6 tamanhos de base (5% a 100% dos
45.206 CVEs reais, como prefixos do array já ordenado), a média de
comparações e o tempo de parede da busca binária e da sequencial - metade
das consultas com acerto, metade com erro, repetidas 20 vezes. Imprime uma
tabela no terminal e grava `output/benchmark.json`. Na base completa:

| métrica | binária | sequencial |
| --- | --- | --- |
| comparações (média) | ~14,7 | ~33.790 |
| tempo por busca (µs) | ~0,18 | ~194 |

Speedup de **~1089x** no tempo de parede.

## Testes

```sh
make test           # roda os testes em C e em Python
make test-c          # só os testes em C (um binário por módulo: bin/test_*)
make test-python      # só os testes em Python (pytest tests/python)
```

Cobertura atual: **160 testes em C** (parsing CSV, carga de CVEs/produtos,
busca binária e sequencial por CVE-ID, índice e busca por nome de produto,
JSON, persistência de seleções, junção CVE+produtos) + **31 testes em
Python** (funções de normalização e o pipeline completo de geração dos
CSVs, com fixtures sintéticas via `monkeypatch` - sem depender do dump
oficial completo). Zero warnings com `-Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wsign-conversion -Werror`.

## Origem dos dados

`data/*.csv` já vem pronto no repositório. Para regenerá-lo a partir do
dump oficial da MITRE (`cvelistV5`, não versionado aqui):

```sh
python3 scripts/generate_cves_2025.py --source /caminho/para/cvelistV5/cves/2025
```

O script é determinístico e só usa a biblioteca padrão do Python.
