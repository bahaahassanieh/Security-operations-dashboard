"""Central registry of security tools: definitions, detection and health.

Executable locations come only from the definitions in this file. They can never be set through
the web interface or read back from the database, so neither can be used to run another program.
"""
from __future__ import annotations

import grp
import logging
import os
import pwd
import re
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from flask import current_app

from app.extensions import db
from app.models import ToolRegistry, utcnow
from app.tools.runner import ToolCommand, run_tool

logger = logging.getLogger("ptp.tools")

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DEFAULT_VERSION = r"v?(\d+\.\d+(?:\.\d+)*)"
_VERSION_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class ToolDefinition:
    """Static facts about one tool."""

    name: str
    display_name: str
    category: str
    candidates: tuple[str, ...]
    install: str
    modules: tuple[str, ...]
    version_args: tuple[str, ...] | None = ("--version",)
    version_pattern: str = _DEFAULT_VERSION
    permissions: tuple[str, ...] = field(default=("network",))
    optional: bool = False
    note: str = ""


TOOLS = {
    tool.name: tool
    for tool in (
        ToolDefinition(
            "subfinder", "Subfinder", "reconnaissance", ("subfinder",),
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            ("subdomains",), ("-version", "-duc"), r"Current Version: v?([\d.]+)",
        ),
        ToolDefinition(
            "amass", "OWASP Amass", "reconnaissance", ("/usr/lib/amass/amass",),
            "sudo apt install amass", ("subdomains",), ("-version",),
            note="Runs the real binary directly, because Kali's wrapper script can invoke sudo.",
        ),
        ToolDefinition(
            "httpx", "ProjectDiscovery httpx", "reconnaissance",
            ("httpx-toolkit", "~/go/bin/httpx"), "sudo apt install httpx-toolkit",
            ("http_probe",), ("-version", "-duc"), r"Current Version: v?([\d.]+)",
            note="/usr/bin/httpx on Kali is an unrelated Python client and is never used.",
        ),
        ToolDefinition(
            "katana", "Katana", "reconnaissance", ("katana",),
            "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            ("crawl",), ("-version", "-duc"), r"Current Version: v?([\d.]+)",
        ),
        ToolDefinition(
            "ffuf", "ffuf", "reconnaissance", ("ffuf",), "sudo apt install ffuf",
            ("content",), ("-V",),
        ),
        ToolDefinition(
            "whatweb", "WhatWeb", "reconnaissance", ("whatweb",), "sudo apt install whatweb",
            ("fingerprint",),
        ),
        ToolDefinition(
            "nmap", "Nmap", "reconnaissance", ("/usr/lib/nmap/nmap",), "sudo apt install nmap",
            ("ports",), note="Always runs as an unprivileged TCP connect scan.",
        ),
        ToolDefinition(
            "dig", "dig (DNS)", "reconnaissance", ("dig",), "sudo apt install dnsutils",
            ("dns",), ("-v",), r"DiG ([\d.]+)",
        ),
        ToolDefinition(
            "sslscan", "sslscan", "reconnaissance", ("sslscan",), "sudo apt install sslscan",
            ("tls",),
        ),
        ToolDefinition(
            "testssl", "testssl.sh", "web_testing", ("testssl", "testssl.sh"),
            "sudo apt install testssl.sh", ("tls",),
        ),
        ToolDefinition(
            "nuclei", "Nuclei", "web_testing", ("nuclei",), "sudo apt install nuclei",
            ("vulnerability_scan",), ("-version", "-duc"), r"Engine Version: v?([\d.]+)",
        ),
        ToolDefinition(
            "sqlmap", "sqlmap", "web_testing", ("sqlmap",), "sudo apt install sqlmap",
            ("injection",),
        ),
        ToolDefinition(
            "dalfox", "Dalfox", "web_testing", ("dalfox",),
            "go install github.com/hahwul/dalfox/v2@latest", ("injection",), ("version",),
        ),
        ToolDefinition(
            "jwt_tool", "JWT Tool", "web_testing", ("jwt_tool", "jwt-tool"),
            "pipx install git+https://github.com/ticarpi/jwt_tool", ("authentication",), None,
        ),
        ToolDefinition(
            "commix", "Commix", "web_testing", ("commix",), "sudo apt install commix",
            ("injection",), note="Requires explicit safe execution controls in a later phase.",
        ),
        ToolDefinition(
            "zap", "OWASP ZAP", "web_testing", ("zaproxy", "zap.sh"), "sudo apt install zaproxy",
            ("vulnerability_scan",), None,
        ),
        ToolDefinition(
            "burpsuite", "Burp Suite", "web_testing", ("burpsuite",), "sudo apt install burpsuite",
            ("manual_testing",), None, optional=True,
            note="Optional. Professional features need a commercial license.",
        ),
        ToolDefinition(
            "semgrep", "Semgrep", "code_analysis", ("semgrep",), "pipx install semgrep",
            ("source_analysis",), permissions=("filesystem",),
        ),
        ToolDefinition(
            "trivy", "Trivy", "code_analysis", ("trivy",), "sudo apt install trivy",
            ("dependency_analysis",), permissions=("filesystem",),
        ),
        ToolDefinition(
            "retire", "Retire.js", "code_analysis", ("retire",), "npm install -g retire",
            ("dependency_analysis",), permissions=("filesystem",),
        ),
        ToolDefinition(
            "dependency_check", "OWASP Dependency-Check", "code_analysis",
            ("dependency-check", "dependency-check.sh"), "sudo apt install dependency-check",
            ("dependency_analysis",), None, permissions=("filesystem",),
        ),
    )
}


def _is_private_group(gid: int) -> bool:
    """True for the user's own single-member group, as created by default on Debian and Kali."""
    try:
        group = grp.getgrgid(gid)
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return False
    return gid == os.getgid() and group.gr_name == user and set(group.gr_mem) <= {user}


def is_safe_executable(path: str) -> bool:
    """Accept only regular executables that other users cannot modify."""
    try:
        real = os.path.realpath(path)
        info = os.stat(real)
    except OSError:
        return False
    group_writable = bool(info.st_mode & stat.S_IWGRP) and not _is_private_group(info.st_gid)
    return (
        stat.S_ISREG(info.st_mode)
        and bool(info.st_mode & stat.S_IXUSR)
        and not info.st_mode & stat.S_IWOTH
        and not group_writable
        and info.st_uid in (0, os.getuid())
    )


def locate(definition: ToolDefinition) -> str | None:
    """Find a tool using only its defined candidates and the allow-listed directories."""
    for candidate in definition.candidates:
        if candidate.startswith(("/", "~")):
            paths = [os.path.expanduser(candidate)]
        else:
            paths = [os.path.join(directory, candidate) for directory in current_app.config["TOOL_DIRS"]]
        for path in paths:
            if is_safe_executable(path):
                return path
    return None


def detect_version(definition: ToolDefinition, path: str) -> str | None:
    """Ask a tool for its version. Returns ``None`` when it cannot be determined."""
    if definition.version_args is None:
        return None
    with tempfile.TemporaryDirectory(prefix="ptp-version-") as workdir:
        try:
            result = run_tool(
                ToolCommand(path, definition.version_args, Path(workdir), _VERSION_TIMEOUT_SECONDS)
            )
            text = result.output_path.read_text(errors="replace")
            text += result.error_path.read_text(errors="replace")
        except OSError as exc:
            logger.warning("version_check_failed", extra={"tool": definition.name, "error": str(exc)})
            return None
    match = re.search(definition.version_pattern, _ANSI.sub("", text))
    return match.group(1)[:64] if match else None


def sync_registry() -> list[ToolRegistry]:
    """Detect every tool and update the registry. Operator choices are preserved. Commits."""
    rows = {row.name: row for row in db.session.scalars(db.select(ToolRegistry))}
    paths = {name: locate(definition) for name, definition in TOOLS.items()}
    with ThreadPoolExecutor(max_workers=8) as pool:  # Keeps a refresh within the request timeout.
        versions = dict(
            zip(
                TOOLS,
                pool.map(
                    lambda name: detect_version(TOOLS[name], paths[name]) if paths[name] else None,
                    TOOLS,
                ),
                strict=True,
            )
        )
    for name, definition in TOOLS.items():
        row = rows.get(name)
        if row is None:
            row = ToolRegistry(name=name, is_enabled=True, configuration={})
            db.session.add(row)
            rows[name] = row
        path, version = paths[name], versions[name]
        row.display_name = definition.display_name
        row.category = definition.category
        row.install_instructions = definition.install
        row.supported_modules = list(definition.modules)
        row.required_permissions = list(definition.permissions)
        row.executable_path = path
        row.version = version
        if path is None:
            row.health_status = "missing"
        elif version or definition.version_args is None:
            row.health_status = "healthy"
        else:
            row.health_status = "degraded"
        row.last_checked_at = utcnow()
    db.session.commit()
    return sorted(rows.values(), key=lambda item: (item.category, item.name))


def resolve_tool(name: str) -> str | None:
    """Return the executable for an enabled, installed tool, re-checking it on every use."""
    definition = TOOLS.get(name)
    if definition is None:
        return None
    row = db.session.scalar(db.select(ToolRegistry).filter_by(name=name))
    if row is not None and not row.is_enabled:
        return None
    return locate(definition)
