"""Testes do gerador da base 2025: funcoes puras isoladas + o pipeline
completo (collect_records -> generate) com fixtures sinteticas pequenas.

collect_records()/validate_model()/generate() conferem os totais contra
constantes fixas do modulo (EXPECTED_TOTAL, EXPECTED_STATE_COUNTS,
EXPECTED_RELATION_COUNTS) amarradas ao dump oficial real de 2025 - uma
protecao contra processar um dump incompleto/corrompido. Para testar o
pipeline inteiro com poucos arquivos sinteticos, os testes abaixo trocam
essas constantes so' durante o teste via monkeypatch (restaurado sozinho
no final de cada teste). O script de producao em si nao e' alterado, e um
`python scripts/generate_cves_2025.py` continua conferindo os numeros
reais normalmente.
"""

import csv
import json
from pathlib import Path

import pytest

import generate_cves_2025 as gen


# ---------------------------------------------------------------------
# Funcoes puras
# ---------------------------------------------------------------------


def test_clean_text_trims_and_handles_non_strings():
    assert gen.clean_text("  x  ") == "x"
    assert gen.clean_text(None) == ""
    assert gen.clean_text(123) == ""
    assert gen.clean_text("") == ""


@pytest.mark.parametrize(
    "value", ["n/a", "N/A", "Unknown", "  unspecified  ", "-", "*", ""]
)
def test_is_valid_name_rejects_placeholders_case_insensitively(value):
    assert gen.is_valid_name(value) is False


def test_is_valid_name_accepts_real_value():
    assert gen.is_valid_name("Acme Corp") is True


def test_encode_single_line_text_escapes_backslash_before_newline():
    # A ordem do encode importa: se escapasse \n antes de \\, uma barra
    # invertida literal na entrada bagunçaria o \\n gerado depois. Testa
    # o mesmo contrato que csv_decode_text em C espera para desfazer.
    assert gen.encode_single_line_text("a\\b") == "a\\\\b"
    assert gen.encode_single_line_text("a\nb") == "a\\nb"


def test_encode_single_line_text_normalizes_crlf_and_cr():
    assert gen.encode_single_line_text("a\r\nb") == "a\\nb"
    assert gen.encode_single_line_text("a\rb") == "a\\nb"


def test_unique_valid_names_dedupes_case_insensitively_keeps_first_seen():
    affected = [{"vendor": "OpenSSL"}, {"vendor": "openssl"}, {"vendor": "Acme"}]
    assert gen.unique_valid_names(affected, "vendor") == ("Acme", "OpenSSL")


def test_unique_valid_names_ignores_placeholders_and_non_mappings():
    affected = [{"vendor": "n/a"}, "not a mapping", {"vendor": "Acme"}, {}]
    assert gen.unique_valid_names(affected, "vendor") == ("Acme",)


def test_unique_replacements_dedupes_and_sorts():
    # O formato exigido pelo regex e' "CVE-" maiusculo; a normalizacao de
    # caixa (casefold) so' entra pra comparar duplicatas, nao pra aceitar
    # variantes de escrita do prefixo.
    result = gen.unique_replacements(
        ["CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0002"], source=Path("x")
    )
    assert result == ("CVE-2024-0001", "CVE-2024-0002")


def test_unique_replacements_none_returns_empty_tuple():
    assert gen.unique_replacements(None, source=Path("x")) == ()


def test_unique_replacements_raises_on_invalid_id():
    with pytest.raises(gen.ValidationError):
        gen.unique_replacements(["not-a-cve-id"], source=Path("x"))


def test_first_english_value_picks_first_english_entry():
    items = [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "hello"}]
    assert gen.first_english_value(items, source=Path("x"), field="descriptions") == "hello"


def test_first_english_value_returns_empty_when_no_english():
    items = [{"lang": "es", "value": "hola"}]
    assert gen.first_english_value(items, source=Path("x"), field="descriptions") == ""


def test_first_english_value_returns_empty_for_non_list():
    assert gen.first_english_value(None, source=Path("x"), field="descriptions") == ""


def test_cve_sort_key_parses_year_and_number():
    assert gen.cve_sort_key("CVE-2025-42") == (2025, 42, "CVE-2025-42")


def test_cve_sort_key_raises_on_malformed_id():
    with pytest.raises(gen.ValidationError):
        gen.cve_sort_key("not-a-cve")


def _published_payload(
    cve_id, vendor="Acme", product="Widget", description="desc", title="", replaced_by=None
):
    cna = {
        "affected": [{"vendor": vendor, "product": product}],
        "descriptions": [{"lang": "en", "value": description}],
        "title": title,
    }
    if replaced_by is not None:
        cna["replacedBy"] = replaced_by
    return {"cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"}, "containers": {"cna": cna}}


def _rejected_payload(cve_id, reason="motivo", replaced_by=None):
    cna = {"rejectedReasons": [{"lang": "en", "value": reason}]}
    if replaced_by is not None:
        cna["replacedBy"] = replaced_by
    return {"cveMetadata": {"cveId": cve_id, "state": "REJECTED"}, "containers": {"cna": cna}}


def test_normalize_record_published_happy_path():
    payload = _published_payload(
        "CVE-2025-0001", vendor="Acme", product="Widget", description="d", title="t"
    )
    record = gen.normalize_record(payload, source=Path("x.json"))

    assert record.cve_id == "CVE-2025-0001"
    assert record.state == "PUBLISHED"
    assert record.description_en == "d"
    assert record.title == "t"
    assert record.rejection_reason_en == ""
    assert record.vendors == ("Acme",)
    assert record.products == ("Widget",)


def test_normalize_record_published_without_description_raises():
    payload = _published_payload("CVE-2025-0001", description="")
    with pytest.raises(gen.ValidationError):
        gen.normalize_record(payload, source=Path("x.json"))


def test_normalize_record_rejected_happy_path():
    payload = _rejected_payload("CVE-2025-0002", reason="motivo")
    record = gen.normalize_record(payload, source=Path("x.json"))

    assert record.state == "REJECTED"
    assert record.description_en == ""
    assert record.title == ""
    assert record.rejection_reason_en == "motivo"
    assert record.vendors == ()
    assert record.products == ()


def test_normalize_record_rejected_without_reason_raises():
    payload = _rejected_payload("CVE-2025-0002", reason="")
    with pytest.raises(gen.ValidationError):
        gen.normalize_record(payload, source=Path("x.json"))


def test_normalize_record_wrong_year_raises():
    payload = _published_payload("CVE-2024-0001")
    with pytest.raises(gen.ValidationError):
        gen.normalize_record(payload, source=Path("x.json"))


def test_normalize_record_unsupported_state_raises():
    payload = _published_payload("CVE-2025-0001")
    payload["cveMetadata"]["state"] = "EM_ANALISE"
    with pytest.raises(gen.ValidationError):
        gen.normalize_record(payload, source=Path("x.json"))


# ---------------------------------------------------------------------
# Pipeline completo: collect_records -> generate, com fixtures sinteticas
# ---------------------------------------------------------------------


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture
def small_dataset(tmp_path, monkeypatch):
    """3 CVEs sinteticos (2 PUBLISHED + 1 REJECTED) e os totais que batem
    com eles, ja' aplicados via monkeypatch nas constantes do modulo."""

    source_dir = tmp_path / "source"
    source_dir.mkdir()

    _write_json(
        source_dir / "CVE-2025-0001.json",
        _published_payload(
            "CVE-2025-0001", vendor="Acme", product="Widget",
            description="linha1\nlinha2", title="t1",
        ),
    )
    _write_json(
        source_dir / "CVE-2025-0002.json",
        _published_payload(
            "CVE-2025-0002", vendor="Beta Corp", product="Widget",
            description="d2", replaced_by=["CVE-2024-9999"],
        ),
    )
    _write_json(
        source_dir / "CVE-2025-0003.json",
        _rejected_payload("CVE-2025-0003", reason="motivo"),
    )

    monkeypatch.setattr(gen, "EXPECTED_TOTAL", 3)
    monkeypatch.setattr(gen, "EXPECTED_STATE_COUNTS", {"PUBLISHED": 2, "REJECTED": 1})
    # "Widget" e' produto tanto de CVE-2025-0001 quanto de CVE-2025-0002:
    # sao 2 linhas de relacao (cve_id, product), uma por CVE - a dedup de
    # unique_valid_names e' so' dentro do affected de um unico CVE.
    monkeypatch.setattr(
        gen, "EXPECTED_RELATION_COUNTS", {"vendors": 2, "products": 2, "replacements": 1}
    )

    return source_dir


def test_generate_end_to_end_writes_valid_csvs(tmp_path, small_dataset):
    output_dir = tmp_path / "output"

    summary = gen.generate(small_dataset, output_dir, workers=1)

    assert summary == {
        "total": 3, "published": 2, "rejected": 1,
        "vendors": 2, "products": 2, "replacements": 1,
    }

    with (output_dir / "cves.csv").open(newline="", encoding="utf-8") as csv_file:
        rows = {row["cve_id"]: row for row in csv.DictReader(csv_file)}

    assert rows["CVE-2025-0001"]["state"] == "PUBLISHED"
    # a quebra de linha real da descricao vira "\n" literal (barra + n) no CSV
    assert rows["CVE-2025-0001"]["description_en"] == "linha1\\nlinha2"
    assert rows["CVE-2025-0003"]["state"] == "REJECTED"
    assert rows["CVE-2025-0003"]["rejection_reason_en"] == "motivo"

    with (output_dir / "vendors.csv").open(newline="", encoding="utf-8") as csv_file:
        vendor_pairs = {(row["cve_id"], row["vendor"]) for row in csv.DictReader(csv_file)}
    assert vendor_pairs == {("CVE-2025-0001", "Acme"), ("CVE-2025-0002", "Beta Corp")}

    with (output_dir / "products.csv").open(newline="", encoding="utf-8") as csv_file:
        product_pairs = {(row["cve_id"], row["product"]) for row in csv.DictReader(csv_file)}
    assert product_pairs == {("CVE-2025-0001", "Widget"), ("CVE-2025-0002", "Widget")}

    with (output_dir / "replacements.csv").open(newline="", encoding="utf-8") as csv_file:
        replacement_rows = list(csv.DictReader(csv_file))
    assert replacement_rows == [{"cve_id": "CVE-2025-0002", "replaced_by": "CVE-2024-9999"}]


def test_generate_raises_when_file_count_does_not_match_expected_total(
    tmp_path, small_dataset, monkeypatch
):
    monkeypatch.setattr(gen, "EXPECTED_TOTAL", 999)

    with pytest.raises(gen.ValidationError, match="Expected 999 JSON files"):
        gen.generate(small_dataset, tmp_path / "output", workers=1)


def test_generate_raises_on_duplicate_cve_id(tmp_path, monkeypatch):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    _write_json(source_dir / "a.json", _published_payload("CVE-2025-0001", description="um"))
    _write_json(source_dir / "b.json", _published_payload("CVE-2025-0001", description="dois"))

    monkeypatch.setattr(gen, "EXPECTED_TOTAL", 2)

    with pytest.raises(gen.ValidationError, match="Duplicate CVE ID"):
        gen.generate(source_dir, tmp_path / "output", workers=1)


def test_generate_raises_on_state_count_mismatch(tmp_path, small_dataset, monkeypatch):
    monkeypatch.setattr(gen, "EXPECTED_STATE_COUNTS", {"PUBLISHED": 3, "REJECTED": 0})

    with pytest.raises(gen.ValidationError, match="Unexpected state counts"):
        gen.generate(small_dataset, tmp_path / "output", workers=1)
