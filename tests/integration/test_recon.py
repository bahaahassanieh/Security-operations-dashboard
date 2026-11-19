"""Tool registry, runner, parsers, jobs and reconnaissance modules, using fake tool binaries."""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from app.extensions import db
from app.models import (
    ActivityLog,
    Asset,
    Endpoint,
    ExecutionJob,
    JobEvent,
    Subdomain,
    Technology,
    ToolRegistry,
    ToolRun,
)
from app.recon import inventory, modules, parsers
from app.services import engagements as service
from app.services import jobs
from app.tools import registry
from app.tools.runner import ToolCommand, UnsafeCommand, run_tool
from tests.conftest import engagement_data

ALL_METHODS = ["passive_recon", "active_recon", "port_scanning", "content_discovery"]


def script(path: Path, body: str) -> str:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return str(path)


class TestRunner:
    def test_captures_output_and_hash(self, tmp_path):
        exe = script(tmp_path / "t", 'echo hello; echo oops >&2')
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 10))
        assert result.status == "completed" and result.exit_code == 0
        assert result.output_path.read_text() == "hello\n"
        assert result.error_path.read_text() == "oops\n"
        assert len(result.output_sha256) == 64

    def test_arguments_are_never_interpreted_by_a_shell(self, tmp_path):
        marker = tmp_path / "pwned"
        exe = script(tmp_path / "t", 'printf "%s" "$1"')
        payload = f"; touch {marker}; $(touch {marker}) `touch {marker}` | touch {marker}"
        result = run_tool(ToolCommand(exe, (payload,), tmp_path / "w", 10))
        assert result.output_path.read_text() == payload
        assert not marker.exists()

    def test_timeout_kills_the_whole_process_group(self, tmp_path):
        pid_file = tmp_path / "child.pid"
        exe = script(tmp_path / "t", f"sleep 60 &\necho $! > {pid_file}\nwait")
        started = time.monotonic()
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 1))
        assert result.status == "timeout" and time.monotonic() - started < 8
        time.sleep(0.2)
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_cancellation_stops_the_tool(self, tmp_path):
        exe = script(tmp_path / "t", "sleep 60")
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 30), should_cancel=lambda: True)
        assert result.status == "cancelled"

    def test_nonzero_exit_is_reported(self, tmp_path):
        exe = script(tmp_path / "t", "exit 3")
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 10))
        assert result.status == "failed" and result.exit_code == 3

    def test_platform_secrets_are_not_inherited(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PTP_SECRET_KEY", "super-secret-value")
        exe = script(tmp_path / "t", "/usr/bin/env")
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 10))
        text = result.output_path.read_text()
        assert "super-secret-value" not in text and "PTP_" not in text

    def test_output_files_are_private(self, tmp_path):
        exe = script(tmp_path / "t", "echo x > created.txt")
        result = run_tool(ToolCommand(exe, (), tmp_path / "w", 10))
        created = result.output_path.parent / "created.txt"
        assert stat.S_IMODE(created.stat().st_mode) == 0o600
        assert stat.S_IMODE(result.output_path.parent.stat().st_mode) == 0o700

    @pytest.mark.parametrize(
        "command",
        [
            ToolCommand("relative/tool", (), Path("/tmp"), 5),
            ToolCommand("/bin/true", ("a\x00b",), Path("/tmp"), 5),
            ToolCommand("/bin/true", ("x" * 5000,), Path("/tmp"), 5),
            ToolCommand("/bin/true", (), Path("/tmp"), 0),
        ],
    )
    def test_unsafe_commands_are_rejected(self, command):
        with pytest.raises(UnsafeCommand):
            run_tool(command)


class TestRegistry:
    def test_every_required_tool_is_registered(self):
        required = {
            "amass", "subfinder", "httpx", "katana", "whatweb", "nmap", "ffuf", "burpsuite", "zap",
            "nuclei", "sqlmap", "dalfox", "jwt_tool", "testssl", "commix", "semgrep", "trivy",
            "retire", "dependency_check",
        }
        assert required <= set(registry.TOOLS)

    def test_kali_wrappers_and_lookalikes_are_avoided(self):
        assert registry.TOOLS["amass"].candidates == ("/usr/lib/amass/amass",)
        assert registry.TOOLS["nmap"].candidates == ("/usr/lib/nmap/nmap",)
        assert "httpx" not in registry.TOOLS["httpx"].candidates

    def test_sync_records_found_and_missing_tools(self, app, tmp_path):
        script(tmp_path / "ffuf", 'echo "ffuf version: 2.3.0"')
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        rows = {row.name: row for row in registry.sync_registry()}
        assert rows["ffuf"].health_status == "healthy" and rows["ffuf"].version == "2.3.0"
        assert rows["katana"].health_status == "missing" and rows["katana"].executable_path is None
        assert rows["katana"].install_instructions

    def test_tool_with_unreadable_version_is_degraded(self, app, tmp_path):
        script(tmp_path / "ffuf", "echo unknown")
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        rows = {row.name: row for row in registry.sync_registry()}
        assert rows["ffuf"].health_status == "degraded"

    def test_writable_executable_is_rejected(self, app, tmp_path):
        exe = script(tmp_path / "ffuf", "echo 1.0")
        os.chmod(exe, 0o777)
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        assert registry.locate(registry.TOOLS["ffuf"]) is None

    def test_group_writable_binary_in_private_group_is_accepted(self, app, tmp_path):
        exe = script(tmp_path / "ffuf", "echo 1.0")
        os.chmod(exe, 0o775)
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        assert registry.locate(registry.TOOLS["ffuf"]) == exe

    def test_group_writable_binary_in_shared_group_is_rejected(self, app, tmp_path, monkeypatch):
        exe = script(tmp_path / "ffuf", "echo 1.0")
        os.chmod(exe, 0o775)
        monkeypatch.setattr(registry, "_is_private_group", lambda _gid: False)
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        assert registry.locate(registry.TOOLS["ffuf"]) is None

    def test_disabled_tool_cannot_be_resolved(self, app, tmp_path):
        script(tmp_path / "ffuf", 'echo "ffuf version: 2.3.0"')
        app.config["TOOL_DIRS"] = [str(tmp_path)]
        registry.sync_registry()
        assert registry.resolve_tool("ffuf")
        db.session.scalar(db.select(ToolRegistry).filter_by(name="ffuf")).is_enabled = False
        db.session.commit()
        assert registry.resolve_tool("ffuf") is None

    def test_database_path_is_never_trusted(self, app, tmp_path):
        evil = script(tmp_path / "evil", "echo pwned")
        app.config["TOOL_DIRS"] = [str(tmp_path / "empty")]
        registry.sync_registry()
        row = db.session.scalar(db.select(ToolRegistry).filter_by(name="ffuf"))
        row.executable_path = evil
        db.session.commit()
        assert registry.resolve_tool("ffuf") is None

    def test_unknown_tool_cannot_be_resolved(self, app):
        assert registry.resolve_tool("bash") is None


class TestParsers:
    def write(self, tmp_path, text):
        path = tmp_path / "output"
        path.write_text(text)
        return path

    def test_httpx(self, tmp_path):
        line = json.dumps({"url": "http://a.test/", "host": "a.test", "port": "80", "status_code": 200,
                           "title": "T", "webserver": "nginx", "tech": ["Python:3.14", "jQuery"]})
        item = parsers.parse_httpx(self.write(tmp_path, line + "\nnot json\n[1]\n"))[0]
        assert item["port"] == 80 and item["technologies"] == [("Python", "3.14"), ("jQuery", "")]

    def test_whatweb(self, tmp_path):
        document = [{"target": "http://a/", "http_status": 200, "plugins": {
            "HTTPServer": {"string": ["nginx/1.2"]}, "Country": {"string": ["ZZ"]},
            "PHP": {"version": ["8.2,"]}}}]
        item = parsers.parse_whatweb(self.write(tmp_path, json.dumps(document)))[0]
        assert item["technologies"] == [("PHP", "8.2")] and item["server"] == "nginx/1.2"

    def test_ffuf(self, tmp_path):
        document = {"results": [{"url": "http://a/x", "status": 301, "redirectlocation": "/y"}]}
        assert parsers.parse_ffuf(self.write(tmp_path, json.dumps(document)))[0]["location"] == "/y"

    def test_dig(self, tmp_path):
        text = ("a.test. 300 IN A 203.0.113.5\n; comment\nbad line\n"
                'a.test. 300 IN TXT "v=spf1 -all"\na.test. 300 IN RRSIG ignored x\n')
        assert parsers.parse_dig(self.write(tmp_path, text)) == {
            "a.test": {"A": ["203.0.113.5"], "TXT": ['"v=spf1 -all"']}
        }

    def test_nmap(self, tmp_path):
        xml = ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="203.0.113.5"/><ports>'
               '<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>'
               '<port protocol="tcp" portid="81"><state state="closed"/></port></ports></host></nmaprun>')
        items = parsers.parse_nmap(self.write(tmp_path, xml))
        assert len(items) == 1 and items[0]["port"] == 443 and items[0]["product"] == "nginx"

    def test_sslscan(self, tmp_path):
        xml = ('<?xml version="1.0"?><document><ssltest><protocol type="tls" version="1.0" enabled="1"/>'
               '<protocol type="ssl" version="3" enabled="0"/><cipher strength="weak" cipher="RC4"/>'
               '<certificates><certificate><subject><![CDATA[a.test]]></subject>'
               '<altnames><![CDATA[DNS:a.test, DNS:b.test, IP:1.2.3.4]]></altnames>'
               '<expired>true</expired></certificate></certificates></ssltest></document>')
        item = parsers.parse_sslscan(self.write(tmp_path, xml))
        assert item["protocols"] == ["TLS 1.0"] and item["alt_names"] == ["a.test", "b.test"]
        assert item["expired"] is True and item["weak_ciphers"] == ["RC4"]

    @pytest.mark.parametrize(
        "payload",
        [
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><nmaprun>&b;</nmaprun>',
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>',
            "<?xml version='1.0'?><unclosed>",
            "garbage",
        ],
    )
    def test_hostile_xml_is_rejected(self, tmp_path, payload):
        assert parsers.parse_nmap(self.write(tmp_path, payload)) == []
        assert parsers.parse_sslscan(self.write(tmp_path, payload)) is None

    @pytest.mark.parametrize("payload", ["", "{", "[]", '{"results": "x"}', '[{"plugins": 5}]', "[" * 100000])
    def test_malformed_json_is_ignored(self, tmp_path, payload):
        path = self.write(tmp_path, payload)
        assert parsers.parse_ffuf(path) == [] and parsers.parse_whatweb(path) == []

    def test_tool_status_messages_are_not_hostnames(self, tmp_path):
        path = self.write(tmp_path, "No names discovered\nno\nwww.a.test\n")
        assert parsers.parse_names(path) == ["www.a.test"]

    def test_record_count_is_bounded(self, tmp_path):
        path = self.write(tmp_path, "\n".join(f"h{i}.test" for i in range(parsers.MAX_RECORDS + 50)))
        assert len(parsers.parse_names(path)) == parsers.MAX_RECORDS


@pytest.fixture
def recon_engagement(lead):
    item = service.create_engagement(
        engagement_data(
            authorized_methods=ALL_METHODS,
            primary_target_url="http://203.0.113.10/",
            authorized_scope=["203.0.113.10", "*.lab.acme-corp.test"],
            excluded_scope=["secret.lab.acme-corp.test", "http://203.0.113.10/admin"],
        ),
        lead,
    )
    service.confirm_authorization(item, lead, "SOW-2", "CISO")
    service.transition(item, "active", lead)
    db.session.commit()
    return item


@pytest.fixture
def fake_tools(app, tmp_path, monkeypatch):
    """Install fake binaries that log their arguments and emit realistic output."""
    monkeypatch.setattr("app.services.scope.system_resolver", lambda _host: ["93.184.216.34"])
    monkeypatch.setitem(
        registry.TOOLS, "amass",
        registry.ToolDefinition("amass", "Amass", "reconnaissance", (str(tmp_path / "no-amass"),), "x", ("subdomains",)),
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    record = f'echo "$(basename "$0") $*" >> {calls}\n'
    httpx = json.dumps({"url": "http://203.0.113.10/", "host": "203.0.113.10", "port": "80",
                        "scheme": "http", "status_code": 200, "title": "Lab", "webserver": "nginx",
                        "tech": ["PHP:8.2"]})
    outsider = json.dumps({"url": "http://outside.example.net/", "host": "outside.example.net",
                           "port": "80", "status_code": 200})
    script(bin_dir / "httpx-toolkit", record + f"cat <<'EOF'\n{httpx}\n{outsider}\nEOF")
    script(bin_dir / "subfinder", record + (
        "cat <<'EOF'\n"
        '{"host":"www.lab.acme-corp.test"}\n{"host":"secret.lab.acme-corp.test"}\n'
        '{"host":"evil.example.net"}\n{"host":"bad host;rm -rf"}\nEOF'))
    ffuf_report = json.dumps({"results": [
        {"url": "http://203.0.113.10/login", "status": 200},
        {"url": "http://203.0.113.10/admin", "status": 200}]})
    script(bin_dir / "ffuf", record + (
        'for a in "$@"; do case "$prev" in -w) cp "$a" ' + str(tmp_path / "used-words.txt") + ";; esac; prev=$a; done\n"
        f"cat > ffuf.json <<'EOF'\n{ffuf_report}\nEOF"))
    script(bin_dir / "whatweb", record + (
        "cat > whatweb.json <<'EOF'\n"
        '[{"target":"http://203.0.113.10/","http_status":200,"plugins":{"WordPress":{"version":["6.4"]}}}]\nEOF'))
    nmap_xml = ('<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.10"/><ports>'
                '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.2"/>'
                "</port></ports></host></nmaprun>")
    script(bin_dir / "nmap-fake", record + f"cat <<'EOF'\n{nmap_xml}\nEOF")
    app.config["TOOL_DIRS"] = [str(bin_dir)]
    app.config["JOB_DIR"] = tmp_path / "jobs"
    words = tmp_path / "words.txt"
    words.write_text("admin\nlogin\nadmin/users\n-evil\n../../etc/passwd\nbackup\n")
    app.config["WORDLIST_PATH"] = str(words)
    monkeypatch.setitem(
        registry.TOOLS, "nmap",
        registry.ToolDefinition("nmap", "Nmap", "reconnaissance", (str(bin_dir / "nmap-fake"),), "x", ("ports",)),
    )
    return calls


def run_job(engagement, actor, selected):
    job = jobs.create_recon_job(engagement, actor, selected)
    db.session.commit()
    claimed = jobs.claim_next_job()
    jobs.execute_job(claimed)
    return db.session.get(ExecutionJob, job.id)


class TestReconModules:
    def test_passive_results_are_classified_and_invalid_names_dropped(self, recon_engagement, lead, fake_tools):
        job = run_job(recon_engagement, lead, ["subdomains"])
        assert job.status == "completed"
        hosts = {row.hostname: row.in_scope for row in db.session.scalars(db.select(Subdomain))}
        assert hosts == {
            "www.lab.acme-corp.test": True,
            "secret.lab.acme-corp.test": False,
            "evil.example.net": False,
        }

    def test_out_of_scope_discoveries_are_never_contacted(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["subdomains", "http_probe"])
        inputs = db.session.scalars(db.select(ToolRun).filter_by(tool_name="httpx")).one()
        listed = Path(inputs.arguments[1]).read_text()
        assert "www.lab.acme-corp.test" in listed
        assert "evil.example.net" not in listed and "secret.lab" not in listed

    def test_out_of_scope_response_is_flagged(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["http_probe"])
        rows = {row.value: row.in_scope for row in db.session.scalars(db.select(Asset))}
        assert rows["http://203.0.113.10/"] is True and rows["http://outside.example.net/"] is False
        tech = db.session.scalar(db.select(Technology).filter_by(name="PHP"))
        assert tech.version == "8.2"

    def test_excluded_paths_are_removed_from_the_wordlist(self, recon_engagement, lead, fake_tools, tmp_path):
        run_job(recon_engagement, lead, ["content"])
        words = (tmp_path / "used-words.txt").read_text().split()
        assert words == ["login", "backup"]

    def test_excluded_endpoint_in_output_is_marked_out_of_scope(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["content"])
        rows = {row.path: row.in_scope for row in db.session.scalars(db.select(Endpoint))}
        assert rows == {"/login": True, "/admin": False}

    def test_nmap_runs_unprivileged_without_scripts(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["ports"])
        call = fake_tools.read_text()
        assert "--unprivileged" in call and "-sT" in call and "--max-rate 10" in call
        assert "--script" not in call and "-sC" not in call and "-O " not in call
        asset = db.session.scalar(db.select(Asset).filter_by(asset_type="network_service"))
        assert asset.port == 80 and asset.in_scope

    def test_tools_never_follow_redirects(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["http_probe", "fingerprint", "content"])
        call = fake_tools.read_text()
        assert "--follow-redirect=never" in call
        assert " -fr" not in call and " -follow-redirects" not in call and " -r " not in call

    def test_rate_limit_setting_reaches_tools(self, recon_engagement, lead, fake_tools):
        from app.services import settings

        settings.set_int("recon.rate_limit_rps", 3, lead)
        db.session.commit()
        run_job(recon_engagement, lead, ["http_probe", "content"])
        call = fake_tools.read_text()
        assert "-rl 3" in call and "-rate 3" in call

    def test_every_tool_target_is_gated_and_audited(self, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["fingerprint"])
        entry = db.session.scalar(
            db.select(ActivityLog).filter_by(action="execution.gate", outcome="success")
        )
        assert entry is not None

    def test_missing_tool_is_skipped_with_a_warning(self, recon_engagement, lead, fake_tools, app):
        job = run_job(recon_engagement, lead, ["subdomains"])
        messages = [event.message for event in job.events]
        assert any("amass is not available" in message for message in messages)
        assert job.status == "completed"


class TestCanonicalUrls:
    @pytest.mark.parametrize(
        "first,second",
        [
            ("http://a.test:8000", "http://a.test:8000/"),
            ("http://a.test:80/", "http://a.test/"),
            ("https://a.test:443/x", "https://a.test/x"),
            ("HTTP://A.TEST/", "http://a.test/"),
            ("http://a.test/#frag", "http://a.test/"),
        ],
    )
    def test_equivalent_urls_match(self, first, second):
        assert inventory.canonical_url(first) == inventory.canonical_url(second)

    @pytest.mark.parametrize(
        "first,second",
        [("http://a.test/", "https://a.test/"), ("http://a.test/x", "http://a.test/X"),
         ("http://a.test:8000/", "http://a.test:8001/")],
    )
    def test_distinct_urls_stay_distinct(self, first, second):
        assert inventory.canonical_url(first) != inventory.canonical_url(second)

    def test_same_site_is_stored_and_scanned_once(self, recon_engagement, lead, fake_tools):
        evaluator = service.build_evaluator(recon_engagement)
        for url in ("http://203.0.113.10", "http://203.0.113.10/", "http://203.0.113.10:80/"):
            inventory.save_asset(recon_engagement.id, evaluator, "web_service", url, "httpx", port=80)
        db.session.commit()
        run_job(recon_engagement, lead, ["content"])
        assert len(db.session.scalars(db.select(ToolRun).filter_by(tool_name="ffuf")).all()) == 1
        assert len(db.session.scalars(db.select(Asset).filter_by(asset_type="web_service")).all()) == 1


class TestJobLifecycle:
    def test_pause_holds_until_resumed(self, recon_engagement, lead, fake_tools, monkeypatch):
        job = jobs.create_recon_job(recon_engagement, lead, ["fingerprint"])
        job.pause_requested = True
        db.session.commit()
        seen = []

        def resume_after_first_wait(_seconds):
            seen.append(db.session.get(ExecutionJob, job.id).status)
            db.session.execute(
                db.update(ExecutionJob).where(ExecutionJob.id == job.id).values(pause_requested=False)
            )
            db.session.commit()

        monkeypatch.setattr(jobs.time, "sleep", resume_after_first_wait)
        jobs.execute_job(jobs.claim_next_job())
        db.session.refresh(job)
        assert seen[0] == "paused" and job.status == "completed"

    def test_worker_shutdown_requeues_the_job(self, recon_engagement, lead, fake_tools, monkeypatch):
        job = jobs.create_recon_job(recon_engagement, lead, ["http_probe", "fingerprint"])
        job.plan = {**job.plan, "current": 1}
        db.session.commit()
        monkeypatch.setattr(jobs._WorkerState, "stopping", True)
        jobs.execute_job(jobs.claim_next_job())
        db.session.refresh(job)
        assert job.status == "queued" and job.plan["current"] == 1

    def test_requires_authorized_method(self, engagement, lead, fake_tools):
        service.confirm_authorization(engagement, lead, "SOW", "CISO")
        service.transition(engagement, "active", lead)
        with pytest.raises(jobs.JobError, match="not authorized"):
            jobs.create_recon_job(engagement, lead, ["ports"])

    def test_requires_active_engagement(self, lead, fake_tools):
        item = service.create_engagement(engagement_data(authorized_methods=ALL_METHODS), lead)
        with pytest.raises(jobs.JobError, match="not active"):
            jobs.create_recon_job(item, lead, ["http_probe"])

    @pytest.mark.parametrize("selected", [[], ["unknown"], ["http_probe", "rm -rf /"]])
    def test_invalid_modules_are_rejected(self, recon_engagement, lead, fake_tools, selected):
        with pytest.raises(jobs.JobError):
            jobs.create_recon_job(recon_engagement, lead, selected)

    def test_uninstalled_module_is_rejected(self, recon_engagement, lead, fake_tools):
        with pytest.raises(jobs.JobError, match="Not installed"):
            jobs.create_recon_job(recon_engagement, lead, ["crawl"])

    def test_only_one_active_job_per_engagement(self, recon_engagement, lead, fake_tools):
        jobs.create_recon_job(recon_engagement, lead, ["http_probe"])
        db.session.commit()
        with pytest.raises(jobs.JobError, match="already running"):
            jobs.create_recon_job(recon_engagement, lead, ["http_probe"])

    def test_cancel_queued_job(self, recon_engagement, lead, fake_tools):
        job = jobs.create_recon_job(recon_engagement, lead, ["http_probe"])
        jobs.control_job(job, "cancel", lead)
        db.session.commit()
        assert job.status == "cancelled" and jobs.claim_next_job() is None

    def test_job_stops_if_engagement_is_paused(self, recon_engagement, lead, fake_tools):
        job = jobs.create_recon_job(recon_engagement, lead, ["http_probe"])
        db.session.commit()
        service.transition(recon_engagement, "paused", lead)
        db.session.commit()
        jobs.execute_job(jobs.claim_next_job())
        db.session.refresh(job)
        assert job.status == "failed" and "not active" in job.error_message
        assert not fake_tools.exists()

    def test_job_stops_if_authorization_is_revoked(self, recon_engagement, lead, fake_tools):
        job = jobs.create_recon_job(recon_engagement, lead, ["http_probe"])
        db.session.commit()
        recon_engagement.rules_of_engagement = "Changed without re-authorization"
        db.session.commit()
        jobs.execute_job(jobs.claim_next_job())
        db.session.refresh(job)
        assert job.status == "failed" and not fake_tools.exists()

    def test_failed_module_does_not_stop_the_job(self, recon_engagement, lead, fake_tools, monkeypatch):
        def explode(_ctx):
            raise RuntimeError("boom")

        original = modules.MODULES["http_probe"]
        monkeypatch.setitem(
            jobs.ALL_MODULES, "http_probe",
            modules.ReconModule("http_probe", "Probe", "", "active_recon", ("httpx",), explode),
        )
        job = run_job(recon_engagement, lead, ["http_probe", "fingerprint"])
        assert original is not None and job.status == "completed" and job.progress == 100
        assert any("failed unexpectedly" in event.message for event in job.events)

    def test_resumes_from_the_saved_module(self, recon_engagement, lead, fake_tools):
        job = jobs.create_recon_job(recon_engagement, lead, ["http_probe", "fingerprint"])
        job.plan = {**job.plan, "current": 1}
        db.session.commit()
        jobs.execute_job(jobs.claim_next_job())
        assert "httpx-toolkit" not in fake_tools.read_text()
        assert "whatweb" in fake_tools.read_text()


class TestReconPages:
    def test_pages_render(self, client, login, recon_engagement, lead, fake_tools):
        job = run_job(recon_engagement, lead, ["http_probe"])
        login("lead.tester")
        for path in (
            "/tools/", "/recon/", f"/recon/engagements/{recon_engagement.id}/new",
            f"/recon/jobs/{job.id}", f"/api/v1/jobs/{job.id}",
            f"/assets/?engagement={recon_engagement.id}&tab=services",
            f"/assets/?engagement={recon_engagement.id}&tab=hosts&scope=all",
            f"/assets/?engagement={recon_engagement.id}&tab=endpoints",
            f"/assets/?engagement={recon_engagement.id}&tab=technologies",
        ):
            assert client.get(path).status_code == 200, path

    def test_start_requires_confirmation(self, client, login, recon_engagement, fake_tools):
        login("lead.tester")
        client.post(f"/recon/engagements/{recon_engagement.id}/new", data={"modules": ["http_probe"]})
        assert db.session.scalar(db.select(ExecutionJob)) is None

    def test_start_through_ui(self, client, login, recon_engagement, fake_tools):
        login("lead.tester")
        response = client.post(
            f"/recon/engagements/{recon_engagement.id}/new",
            data={"modules": ["http_probe"], "confirm": "y"},
        )
        assert response.status_code == 302 and db.session.scalar(db.select(ExecutionJob)) is not None

    def test_unassigned_user_cannot_reach_job_or_output(self, client, login, make_user, recon_engagement, lead, fake_tools):
        job = run_job(recon_engagement, lead, ["http_probe"])
        run = db.session.scalar(db.select(ToolRun))
        make_user("outsider")
        login("outsider")
        for path in (f"/recon/jobs/{job.id}", f"/api/v1/jobs/{job.id}", f"/recon/runs/{run.id}/output",
                     f"/recon/engagements/{recon_engagement.id}/new",
                     f"/assets/?engagement={recon_engagement.id}"):
            assert client.get(path).status_code == 404, path
        assert client.post(f"/recon/jobs/{job.id}/control", data={"action": "cancel"}).status_code == 404

    def test_read_only_role_cannot_start_jobs(self, client, login, make_user, recon_engagement, fake_tools):
        make_user("auditor.one", "Auditor")
        login("auditor.one")
        path = f"/recon/engagements/{recon_engagement.id}/new"
        assert client.post(path, data={"modules": ["http_probe"], "confirm": "y"}).status_code == 403

    def test_tester_cannot_manage_tools(self, client, login, make_user):
        make_user("plain.tester")
        login("plain.tester")
        assert client.post("/tools/refresh").status_code == 403

    def test_output_path_outside_job_dir_is_refused(self, client, login, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["http_probe"])
        run = db.session.scalar(db.select(ToolRun))
        run.output_path = "/etc/passwd"
        db.session.commit()
        login("lead.tester")
        assert client.get(f"/recon/runs/{run.id}/output").status_code == 404

    def test_output_is_served_as_inert_attachment(self, client, login, recon_engagement, lead, fake_tools):
        run_job(recon_engagement, lead, ["http_probe"])
        run = db.session.scalar(db.select(ToolRun))
        login("lead.tester")
        response = client.get(f"/recon/runs/{run.id}/output")
        assert response.mimetype == "text/plain" and "attachment" in response.headers["Content-Disposition"]

    def test_hostile_tool_output_is_escaped(self, client, login, recon_engagement):
        payload = "<script>alert(1)</script>"
        evaluator = service.build_evaluator(recon_engagement)
        inventory.save_asset(
            recon_engagement.id, evaluator, "web_service", "http://203.0.113.10/x", "httpx",
            attributes={"title": payload},
        )
        db.session.commit()
        login("lead.tester")
        body = client.get(f"/assets/?engagement={recon_engagement.id}").data
        assert payload.encode() not in body and b"&lt;script&gt;" in body

    def test_no_route_accepts_a_tool_path_or_command(self, app):
        rules = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint.startswith("tools.")]
        assert sorted(rules) == ["/tools/", "/tools/<int:tool_id>/toggle", "/tools/refresh"]

    def test_job_events_are_returned_incrementally(self, client, login, recon_engagement, lead, fake_tools):
        job = run_job(recon_engagement, lead, ["http_probe"])
        last = db.session.scalar(db.select(JobEvent).order_by(JobEvent.id.desc()))
        login("lead.tester")
        assert client.get(f"/api/v1/jobs/{job.id}?after={last.id}").get_json()["events"] == []
