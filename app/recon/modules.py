"""Reconnaissance modules.

Rules every module follows:

* Each target passes the execution gate immediately before it is touched.
* Only in-scope results feed later modules. Out-of-scope discoveries are recorded, never contacted.
* Tools never follow redirects, and requests are rate limited.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from flask import current_app

from app.extensions import db
from app.models import Asset, Engagement, ExecutionJob, JobEvent, Subdomain, ToolRun, User
from app.recon import inventory, parsers
from app.services import engagements as engagement_service
from app.services import settings
from app.services.scope import ScopeDecision, ScopeError, parse_target
from app.tools.registry import resolve_tool
from app.tools.runner import ToolCommand, ToolResult, run_tool

logger = logging.getLogger("ptp.recon")

_WORD = re.compile(r"^[A-Za-z0-9._~][A-Za-z0-9._~/-]{0,127}$")
_MAX_WORDS = 5000
_HTTP_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt", "ssl/http"}


class JobCancelled(Exception):
    """The job was cancelled, or the worker is shutting down, while a tool ran."""


@dataclass
class ReconContext:
    """Everything a module needs to run one step of a job."""

    job: ExecutionJob
    engagement: Engagement
    actor: User
    module: "ReconModule"
    should_cancel: Callable[[], bool]
    pause_hook: Callable[[], None] = lambda: None

    def __post_init__(self) -> None:
        self.evaluator = engagement_service.build_evaluator(self.engagement)
        self.rate = settings.get_int("recon.rate_limit_rps")
        self.timeout = settings.get_int("recon.tool_timeout_seconds")
        self.max_hosts = settings.get_int("recon.max_hosts")

    def log(self, message: str, level: str = "info") -> None:
        db.session.add(
            JobEvent(
                job_id=self.job.id, level=level, module=self.module.name,
                message=inventory.clean(message, 1000),
            )
        )
        db.session.commit()

    def gate(self, target: str) -> ScopeDecision | None:
        """Pass a target through the execution gate. A denial skips only that target."""
        try:
            return engagement_service.authorize_execution(
                self.engagement, target, self.actor, self.module.method
            )
        except engagement_service.ExecutionDenied as exc:
            self.log(f"Skipped {target}: {exc}", "warning")
            return None

    def execute(self, tool: str, arguments: list[str], target: str) -> ToolResult | None:
        """Run a tool once and record the invocation."""
        executable = resolve_tool(tool)
        if executable is None:
            self.log(f"{tool} is not available, so this step was skipped.", "warning")
            return None
        run = ToolRun(
            job_id=self.job.id, tool_name=tool, module=self.module.name,
            target=inventory.clean(target, 2048), arguments=arguments,
        )
        db.session.add(run)
        db.session.commit()
        workdir = Path(current_app.config["JOB_DIR"]) / str(self.job.id) / f"{run.id}-{tool}"
        result = run_tool(
            ToolCommand(executable, tuple(arguments), workdir, self.timeout), self.should_cancel
        )
        run.status = result.status
        run.exit_code = result.exit_code
        run.duration_ms = result.duration_ms
        run.output_path = str(result.output_path)
        run.output_sha256 = result.output_sha256
        run.output_bytes = result.output_bytes
        if result.status != "completed":
            run.error_output = inventory.clean(
                result.error_path.read_text(errors="replace")[-2000:], 2000
            )
        db.session.commit()
        if result.status == "cancelled":
            raise JobCancelled
        if result.status == "timeout":
            self.log(f"{tool} timed out on {target} and was stopped.", "warning")
        elif result.status == "failed":
            self.log(f"{tool} exited with code {result.exit_code} on {target}.", "warning")
        return result

    def hosts(self) -> list[str]:
        """Return in-scope hosts, capped by the configured limit."""
        found = [target.host for target in self.engagement.targets]
        found += [
            entry.value for entry in self.engagement.inclusions if entry.entry_type in ("domain", "ip")
        ]
        found += db.session.scalars(
            db.select(Subdomain.hostname)
            .filter_by(engagement_id=self.engagement.id, in_scope=True)
            .order_by(Subdomain.id)
        ).all()
        unique = [
            host for host in dict.fromkeys(found) if self.evaluator.evaluate(host).allowed
        ]
        if len(unique) > self.max_hosts:
            self.log(f"Limited to the first {self.max_hosts} of {len(unique)} hosts.", "warning")
        return unique[: self.max_hosts]

    def web_urls(self) -> list[str]:
        """Return in-scope web services, falling back to the primary target."""
        urls = db.session.scalars(
            db.select(Asset.value)
            .filter_by(engagement_id=self.engagement.id, asset_type="web_service", in_scope=True)
            .order_by(Asset.id)
        ).all()
        primary = inventory.canonical_url(self.engagement.primary_target_url)
        found = list(dict.fromkeys(inventory.canonical_url(url) for url in [*urls, primary]))
        allowed = [url for url in found if self.evaluator.evaluate(url).allowed]
        return allowed[: self.max_hosts]

    def save_tech(self, asset: Asset, technologies, source: str) -> None:
        for name, version in technologies:
            inventory.save_technology(self.engagement.id, asset.id, name, version, source)


def run_dns(ctx: ReconContext) -> None:
    """Enumerate DNS records for in-scope hostnames."""
    for host in ctx.hosts():
        if parse_target(host).ip is not None or ctx.gate(host) is None:
            continue
        queries = [item for kind in ("A", "AAAA", "CNAME", "MX", "NS", "TXT") for item in (host, kind)]
        result = ctx.execute("dig", ["+noall", "+answer", "+time=3", "+tries=1", *queries], host)
        if result is None:
            continue
        for name, records in parsers.parse_dig(result.output_path).items():
            addresses = records.get("A", []) + records.get("AAAA", [])
            inventory.save_subdomain(
                ctx.engagement.id, ctx.evaluator, name, "dig",
                dns_records=records, resolved_ips=addresses,
            )
        db.session.commit()


def run_subdomains(ctx: ReconContext) -> None:
    """Passively enumerate subdomains of domains covered by a wildcard rule."""
    domains = [e.value[2:] for e in ctx.engagement.inclusions if e.entry_type == "wildcard"]
    if not domains:
        ctx.log("No wildcard scope rules, so there are no domains to enumerate.")
    minutes = max(1, ctx.timeout // 60)
    for domain in domains:
        try:
            engagement_service.authorize_passive_enumeration(
                ctx.engagement, domain, ctx.actor, ctx.module.method
            )
        except engagement_service.ExecutionDenied as exc:
            ctx.log(f"Skipped {domain}: {exc}", "warning")
            continue
        names: list[tuple[str, str]] = []
        result = ctx.execute(
            "subfinder",
            ["-d", domain, "-oJ", "-silent", "-nc", "-duc", "-max-time", str(minutes),
             "-rl", str(ctx.rate)],
            domain,
        )
        if result is not None:
            names += [(name, "subfinder") for name in parsers.parse_subfinder(result.output_path)]
        result = ctx.execute(
            "amass",
            ["enum", "-passive", "-d", domain, "-timeout", str(minutes), "-dir", "amass-data",
             "-nocolor", "-silent"],
            domain,
        )
        if result is not None and result.status == "completed":
            data = str(result.output_path.parent / "amass-data")
            listing = ctx.execute("amass", ["subs", "-d", domain, "-names", "-dir", data], domain)
            if listing is not None:
                names += [(name, "amass") for name in parsers.parse_names(listing.output_path)]
        kept = 0
        for name, source in names:
            row = inventory.save_subdomain(ctx.engagement.id, ctx.evaluator, name, source)
            kept += bool(row and row.in_scope)
        db.session.commit()
        ctx.log(f"{domain}: {len(names)} names found, {kept} in scope.")


def _pinned_address(host: str, decision: ScopeDecision) -> str:
    """Scan the exact address that was validated, so DNS cannot change between check and use."""
    return decision.resolved_ips[0] if decision.resolved_ips else host


def run_ports(ctx: ReconContext) -> None:
    """Identify exposed TCP services with an unprivileged connect scan."""
    top_ports = settings.get_int("recon.nmap_top_ports")
    for host in ctx.hosts():
        decision = ctx.gate(host)
        if decision is None:
            continue
        address = _pinned_address(host, decision)
        arguments = [
            "--unprivileged", "-sT", "-sV", "--version-intensity", "2", "-Pn", "-n", "--open",
            "--top-ports", str(top_ports), "--max-rate", str(ctx.rate), "--max-retries", "1",
            "--host-timeout", f"{ctx.timeout}s", "-oX", "-",
        ]
        if ipaddress.ip_address(address).version == 6:
            arguments.append("-6")
        result = ctx.execute("nmap", [*arguments, address], host)
        if result is None:
            continue
        for item in parsers.parse_nmap(result.output_path):
            if item["port"] is None:
                continue
            label = f"[{host}]" if ":" in host else host
            value = f"{label}:{item['port']}"
            asset = inventory.save_asset(
                ctx.engagement.id, ctx.evaluator, "network_service", value, "nmap",
                port=item["port"], protocol=item["protocol"], service=item["service"],
                ip_address=item["ip"], scope_target=host,
                attributes={"product": inventory.clean(item["product"], 128),
                            "version": inventory.clean(item["version"], 64)},
            )
            if item["product"]:
                ctx.save_tech(asset, [(item["product"], item["version"])], "nmap")
        db.session.commit()


def _probe_inputs(ctx: ReconContext) -> list[str]:
    """Combine in-scope hosts, known web services and open HTTP-like ports."""
    candidates = [*ctx.hosts(), *ctx.web_urls()]
    services = db.session.scalars(
        db.select(Asset).filter_by(
            engagement_id=ctx.engagement.id, asset_type="network_service", in_scope=True
        )
    ).all()
    candidates += [row.value for row in services if (row.service or "") in _HTTP_SERVICES]
    return list(dict.fromkeys(candidates))[: ctx.max_hosts * 4]


def run_http_probe(ctx: ReconContext) -> None:
    """Find live web services. Redirects are recorded but never followed."""
    allowed = [item for item in _probe_inputs(ctx) if ctx.gate(item) is not None]
    if not allowed:
        ctx.log("No in-scope hosts to probe.")
        return
    workdir = Path(current_app.config["JOB_DIR"]) / str(ctx.job.id) / "inputs"
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    input_file = workdir / f"httpx-{ctx.job.id}.txt"
    input_file.write_text("\n".join(allowed) + "\n")
    result = ctx.execute(
        "httpx",
        ["-l", str(input_file), "-j", "-silent", "-nc", "-duc", "-sc", "-title", "-server", "-td",
         "-ip", "-cl", "-ct", "-location", "-irh", "-rl", str(ctx.rate), "-t", "5", "-timeout", "10",
         "-retries", "1"],
        f"{len(allowed)} targets",
    )
    if result is None:
        return
    services = parsers.parse_httpx(result.output_path)
    for item in services:
        asset = inventory.save_asset(
            ctx.engagement.id, ctx.evaluator, "web_service", item["url"], "httpx",
            port=item["port"], protocol=item["scheme"], service=item["scheme"] or "http",
            ip_address=item["ip"],
            attributes={
                "status_code": item["status_code"],
                "title": inventory.clean(item["title"], 255),
                "server": inventory.clean(item["server"], 128),
                "content_type": inventory.clean(item["content_type"], 128),
                "security_headers": item.get("security_headers") or {},
            },
        )
        inventory.save_endpoint(
            ctx.engagement.id, ctx.evaluator, item["url"], "httpx",
            status_code=item["status_code"], content_type=item["content_type"],
            redirect_location=item["location"], asset_id=asset.id,
        )
        ctx.save_tech(asset, item["technologies"], "httpx")
    db.session.commit()
    ctx.log(f"{len(services)} live web services found.")


def _web_asset(ctx: ReconContext, url: str, source: str) -> Asset:
    return inventory.save_asset(ctx.engagement.id, ctx.evaluator, "web_service", url, source)


def _existing_web_asset(ctx: ReconContext, url: str, source: str) -> Asset:
    row = db.session.scalar(
        db.select(Asset).filter_by(
            engagement_id=ctx.engagement.id, asset_type="web_service",
            value=inventory.canonical_url(url),
        )
    )
    return row or _web_asset(ctx, url, source)


def run_fingerprint(ctx: ReconContext) -> None:
    """Identify technologies with WhatWeb's passive aggression level."""
    for url in ctx.web_urls():
        if ctx.gate(url) is None:
            continue
        result = ctx.execute(
            "whatweb",
            ["--no-errors", "-q", "-a", "1", "--follow-redirect=never", "--max-threads", "1",
             "--open-timeout", "10", "--read-timeout", "15", "--colour=never",
             "--log-json=whatweb.json", url],
            url,
        )
        if result is None:
            continue
        report = result.output_path.parent / "whatweb.json"
        asset = _existing_web_asset(ctx, url, "whatweb")
        for item in parsers.parse_whatweb(report):
            ctx.save_tech(asset, item["technologies"], "whatweb")
            if item["server"]:
                asset.attributes = {
                    **(asset.attributes or {}), "server": inventory.clean(item["server"], 128)
                }
        db.session.commit()


def run_tls(ctx: ReconContext) -> None:
    """Inspect TLS protocols and certificates of in-scope HTTPS services."""
    for url in ctx.web_urls():
        parsed = parse_target(url)
        if parsed.scheme != "https" or ctx.gate(url) is None:
            continue
        host = f"[{parsed.host}]" if parsed.ip and parsed.ip.version == 6 else parsed.host
        endpoint = f"{host}:{parsed.effective_port}"
        result = ctx.execute(
            "sslscan",
            ["--xml=-", "--no-colour", "--timeout=5", "--connect-timeout=10", "--sleep=100", endpoint],
            url,
        )
        details = parsers.parse_sslscan(result.output_path) if result else None
        if details is None:
            continue
        inventory.save_asset(
            ctx.engagement.id, ctx.evaluator, "certificate", endpoint, "sslscan",
            port=parsed.effective_port, protocol="tls", scope_target=url,
            attributes={key: value for key, value in details.items()},
        )
        for name in details["alt_names"]:
            if not name.startswith("*."):
                inventory.save_subdomain(ctx.engagement.id, ctx.evaluator, name, "certificate")
        db.session.commit()


def build_wordlist(ctx: ReconContext, base_url: str, destination: Path) -> int:
    """Write only words whose URL is in scope, so excluded paths are never requested."""
    source = Path(current_app.config["WORDLIST_PATH"])
    try:
        words = source.read_text(errors="ignore").splitlines()[: _MAX_WORDS * 2]
    except OSError:
        return 0
    kept = [
        word for word in dict.fromkeys(item.strip() for item in words)
        if _WORD.match(word)
        and ".." not in word.split("/")
        and ctx.evaluator.evaluate(f"{base_url}/{word}").allowed
    ][:_MAX_WORDS]
    destination.write_text("\n".join(kept) + "\n")
    return len(kept)


def run_content(ctx: ReconContext) -> None:
    """Discover files and directories without recursion or following redirects."""
    origins = {}
    for url in ctx.web_urls():
        parts = urlsplit(url)
        origins.setdefault(f"{parts.scheme}://{parts.netloc}", url)
    for base, url in origins.items():
        if ctx.gate(base) is None:
            continue
        workdir = Path(current_app.config["JOB_DIR"]) / str(ctx.job.id) / "inputs"
        workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        wordlist = workdir / f"words-{abs(hash(base))}.txt"
        if build_wordlist(ctx, base, wordlist) == 0:
            ctx.log("No usable wordlist entries, so content discovery was skipped.", "warning")
            continue
        result = ctx.execute(
            "ffuf",
            ["-u", f"{base}/FUZZ", "-w", str(wordlist), "-of", "json", "-o", "ffuf.json", "-s",
             "-noninteractive", "-ac", "-rate", str(ctx.rate), "-t", "5", "-timeout", "10",
             "-maxtime", str(ctx.timeout), "-mc", "200,204,301,302,307,401,403,405"],
            base,
        )
        if result is None:
            continue
        asset = _existing_web_asset(ctx, url, "ffuf")
        items = parsers.parse_ffuf(result.output_path.parent / "ffuf.json")
        for item in items:
            inventory.save_endpoint(
                ctx.engagement.id, ctx.evaluator, item["url"], "ffuf",
                status_code=item["status_code"], content_type=item["content_type"],
                redirect_location=item["location"], asset_id=asset.id,
            )
        db.session.commit()
        ctx.log(f"{base}: {len(items)} paths discovered.")


def _exclusion_pattern(ctx: ReconContext) -> str | None:
    paths = [
        re.escape(urlsplit(entry.value).path)
        for entry in ctx.engagement.exclusions if entry.entry_type == "url"
    ]
    return "|".join(path for path in paths if path) or None


def run_crawl(ctx: ReconContext) -> None:
    """Crawl in-scope web services for endpoints and JavaScript files, staying on the same host."""
    excluded = _exclusion_pattern(ctx)
    for url in ctx.web_urls():
        if ctx.gate(url) is None:
            continue
        arguments = ["-u", url, "-j", "-silent", "-nc", "-duc", "-d", "2", "-jc", "-fs", "fqdn",
                     "-rl", str(ctx.rate), "-c", "5", "-p", "1", "-timeout", "10"]
        if excluded:
            arguments += ["-cos", excluded]
        result = ctx.execute("katana", arguments, url)
        if result is None:
            continue
        asset = _existing_web_asset(ctx, url, "katana")
        items = parsers.parse_katana(result.output_path)
        for item in items:
            inventory.save_endpoint(
                ctx.engagement.id, ctx.evaluator, item["url"], "katana", method=item["method"],
                status_code=item["status_code"], asset_id=asset.id,
            )
        db.session.commit()
        ctx.log(f"{url}: {len(items)} endpoints crawled.")


@dataclass(frozen=True)
class ReconModule:
    """A selectable reconnaissance step."""

    name: str
    label: str
    description: str
    method: str
    tools: tuple[str, ...]
    run: Callable[[ReconContext], None]
    covers: tuple[str, ...] = ()


# Listed in execution order: each module feeds the ones after it.
MODULES = {
    module.name: module
    for module in (
        ReconModule("dns", "DNS records", "Enumerate A, AAAA, CNAME, MX, NS and TXT records.",
                    "passive_recon", ("dig",), run_dns, covers=("WSTG-INFO-04",)),
        ReconModule("subdomains", "Subdomain discovery", "Query passive sources for wildcard-scoped domains.",
                    "passive_recon", ("subfinder", "amass"), run_subdomains, covers=("WSTG-INFO-04", "WSTG-CONF-10")),
        ReconModule("ports", "Port and service scan", "Unprivileged TCP connect scan of common ports.",
                    "port_scanning", ("nmap",), run_ports, covers=("WSTG-INFO-04", "WSTG-CONF-01")),
        ReconModule("http_probe", "HTTP service discovery", "Find live web services and their metadata.",
                    "active_recon", ("httpx",), run_http_probe, covers=("WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09")),
        ReconModule("fingerprint", "Technology fingerprinting", "Identify frameworks and server software.",
                    "active_recon", ("whatweb",), run_fingerprint, covers=("WSTG-INFO-08", "WSTG-INFO-09")),
        ReconModule("tls", "TLS inspection", "Review protocols, ciphers and certificates.",
                    "active_recon", ("sslscan",), run_tls, covers=("WSTG-CRYP-01", "WSTG-CONF-07")),
        ReconModule("content", "Directory and file discovery", "Wordlist discovery that skips excluded paths.",
                    "content_discovery", ("ffuf",), run_content, covers=("WSTG-CONF-03", "WSTG-CONF-04", "WSTG-CONF-05", "WSTG-INFO-03")),
        ReconModule("crawl", "Endpoint crawl", "Crawl pages and JavaScript for endpoints.",
                    "content_discovery", ("katana",), run_crawl, covers=("WSTG-INFO-06", "WSTG-INFO-07")),
    )
}

__all__ = ["MODULES", "JobCancelled", "ReconContext", "ReconModule", "ScopeError"]
