"""CWE reference: bundled seeding, catalog import (safe XML), and display on findings and the library."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.findings import service as findings
from app.findings import taxonomy
from app.models import ActivityLog, CweEntry, TestCase, Vulnerability
from app.reference import cwe
from app.reference.cwe_data import BUNDLED
from app.services import engagements as engagement_service
from tests.conftest import engagement_data

BASE = "https://app.acme-corp.test"

SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" xmlns:xhtml="http://www.w3.org/1999/xhtml" Name="CWE" Version="4.99" Date="2026-01-01">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product builds an SQL command from untrusted input.</Description>
      <Extended_Description><xhtml:p>The <xhtml:b>syntax</xhtml:b> can be altered.</xhtml:p></Extended_Description>
      <Detection_Methods>
        <Detection_Method>
          <Method>Dynamic Analysis</Method>
          <Description><xhtml:p>Submit crafted inputs and observe query behavior.</xhtml:p></Description>
          <Effectiveness>High</Effectiveness>
        </Detection_Method>
      </Detection_Methods>
      <Potential_Mitigations>
        <Mitigation><Phase>Implementation</Phase><Description><xhtml:p>Use parameterized queries.</xhtml:p></Description></Mitigation>
      </Potential_Mitigations>
    </Weakness>
    <Weakness ID="99999" Name="Example Weakness" Abstraction="Variant" Structure="Simple" Status="Draft">
      <Description>Not in the bundled set.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"""


class TestBundledSeed:
    def test_seed_creates_references_and_test_cases(self, app):
        entries, cases = cwe.seed_cwe()
        assert entries == cases == len(BUNDLED)
        assert db.session.scalar(db.select(db.func.count()).select_from(CweEntry)) == len(BUNDLED)
        assert db.session.scalar(db.select(db.func.count()).select_from(TestCase).filter_by(framework="CWE")) == len(BUNDLED)

    def test_every_taxonomy_cwe_is_bundled(self):
        used = {code for item in taxonomy.CLASSES for code in item.cwes}
        assert used <= set(BUNDLED), f"missing: {used - set(BUNDLED)}"

    def test_bundled_entries_have_a_test_procedure(self, app):
        cwe.seed_cwe()
        for entry in db.session.scalars(db.select(CweEntry)):
            assert entry.recommended_test and entry.name and entry.url.startswith("https://cwe.mitre.org/")

    def test_seed_is_idempotent(self, app):
        cwe.seed_cwe()
        cwe.seed_cwe()
        assert db.session.scalar(db.select(db.func.count()).select_from(CweEntry)) == len(BUNDLED)

    def test_ensure_seeds_when_empty(self, app):
        assert db.session.scalar(db.select(db.func.count()).select_from(CweEntry)) == 0
        cwe.ensure_cwe()
        assert db.session.scalar(db.select(db.func.count()).select_from(CweEntry)) == len(BUNDLED)

    @pytest.mark.parametrize("value,expected", [("CWE-89", "CWE-89"), ("89", "CWE-89"), ("cwe89", "CWE-89"), ("", None), ("none", None)])
    def test_normalize_cwe_id(self, value, expected):
        assert cwe.normalize_cwe_id(value) == expected

    def test_cwe_for_lookup(self, app):
        cwe.seed_cwe()
        assert cwe.cwe_for("CWE-89").name.startswith("Improper Neutralization")
        assert cwe.cwe_for("89").cwe_id == "CWE-89"
        assert cwe.cwe_for("CWE-0") is None


class TestCatalogParser:
    def test_parses_weaknesses(self):
        records = {item["cwe_id"]: item for item in cwe.parse_cwe_catalog(SAMPLE)}
        assert set(records) == {"CWE-89", "CWE-99999"}
        item = records["CWE-89"]
        assert item["name"] == "SQL Injection" and item["abstraction"] == "Base"
        assert "syntax can be altered" in item["description"] and "<xhtml" not in item["description"]
        assert item["recommended_test"].startswith("Dynamic Analysis:") and "crafted inputs" in item["recommended_test"]
        assert item["mitigation"] == "Use parameterized queries."

    @pytest.mark.parametrize(
        "payload",
        [
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"><Weaknesses><Weakness ID="1" Name="&e;"><Description>x</Description></Weakness></Weaknesses></Weakness_Catalog>',
            '<!DOCTYPE x [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">]><Weakness_Catalog><Weaknesses/></Weakness_Catalog>',
            "<unclosed>",
            "not xml",
        ],
    )
    def test_hostile_or_malformed_xml_is_refused(self, payload):
        with pytest.raises(cwe.CweError):
            cwe.parse_cwe_catalog(payload)

    def test_missing_weaknesses_section_is_refused(self):
        with pytest.raises(cwe.CweError, match="Weaknesses"):
            cwe.parse_cwe_catalog('<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"></Weakness_Catalog>')

    def test_record_limit(self, monkeypatch):
        monkeypatch.setattr(cwe, "MAX_WEAKNESSES", 1)
        assert len(cwe.parse_cwe_catalog(SAMPLE)) == 1


class TestCatalogImport:
    def test_import_enriches_bundled_and_adds_new(self, app):
        cwe.seed_cwe()
        summary = cwe.import_cwe_catalog(cwe.parse_cwe_catalog(SAMPLE))
        assert summary.updated == 1 and summary.created == 1
        enriched = cwe.cwe_for("CWE-89")
        assert enriched.source == "imported" and "crafted inputs" in enriched.recommended_test
        assert cwe.cwe_for("CWE-99999").source == "imported"

    def test_imported_only_cwe_is_not_a_test_case(self, app):
        cwe.seed_cwe()
        cwe.import_cwe_catalog(cwe.parse_cwe_catalog(SAMPLE))
        assert db.session.scalar(db.select(TestCase).filter_by(test_id="CWE-99999")) is None

    def test_reseeding_does_not_overwrite_imported_entries(self, app):
        cwe.seed_cwe()
        cwe.import_cwe_catalog(cwe.parse_cwe_catalog(SAMPLE))
        cwe.seed_cwe()
        assert cwe.cwe_for("CWE-89").source == "imported" and "crafted inputs" in cwe.cwe_for("CWE-89").recommended_test

    def test_import_is_audited(self, app):
        cwe.seed_cwe()
        cwe.import_cwe_catalog(cwe.parse_cwe_catalog(SAMPLE))
        assert db.session.scalar(db.select(ActivityLog).filter_by(action="cwe.imported"))

    def test_cli_import(self, app, tmp_path):
        cwe.seed_cwe()
        path = tmp_path / "cwec.xml"
        path.write_text(SAMPLE)
        result = app.test_cli_runner().invoke(args=["ptp", "import-cwe", str(path)])
        assert result.exit_code == 0 and "created" in result.output

    def test_cli_rejects_xxe(self, app, tmp_path):
        path = tmp_path / "xxe.xml"
        path.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><Weakness_Catalog><Weaknesses/></Weakness_Catalog>')
        result = app.test_cli_runner().invoke(args=["ptp", "import-cwe", str(path)])
        assert result.exit_code != 0


class TestDisplay:
    @pytest.fixture
    def engagement(self, lead):
        item = engagement_service.create_engagement(
            engagement_data(primary_target_url=f"{BASE}/", authorized_scope=["app.acme-corp.test"], excluded_scope=[]), lead
        )
        engagement_service.confirm_authorization(item, lead, "SOW-CWE", "CISO")
        engagement_service.transition(item, "active", lead)
        db.session.commit()
        return item

    def test_finding_shows_cwe_reference_and_procedure(self, client, login, engagement, lead):
        row = findings.create_manual_finding(engagement, lead, {"name": "SQL injection", "url": f"{BASE}/x", "cwe": "CWE-89"})
        db.session.commit()
        login("lead.tester")
        body = client.get(f"/findings/{row.id}").data
        assert b"CWE reference" in body and b"CWE-89" in body and b"Recommended procedure to test" in body
        assert b"cwe.mitre.org/data/definitions/89.html" in body

    def test_finding_without_a_known_cwe_shows_no_panel(self, client, login, engagement, lead):
        row = findings.create_manual_finding(engagement, lead, {"name": "Odd issue", "url": f"{BASE}/x"})
        db.session.commit()
        login("lead.tester")
        assert b"CWE reference" not in client.get(f"/findings/{row.id}").data

    def test_library_lists_cwe_cases(self, client, login, make_user):
        make_user("viewer")
        login("viewer")
        body = client.get("/methodology/library?category=CWE").data
        assert b"CWE-89" in body and b"Common Weakness Enumeration" in body

    def test_cwe_test_case_page_renders(self, client, login, make_user):
        make_user("viewer")
        login("viewer")
        from app.reference import cwe as cwe_ref
        cwe_ref.ensure_cwe()
        case = db.session.scalar(db.select(TestCase).filter_by(test_id="CWE-89"))
        body = client.get(f"/methodology/library/{case.id}").data
        assert b"Testing procedure" in body and b"Common Weakness Enumeration" in body
