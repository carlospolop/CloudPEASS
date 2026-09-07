"""Read-only Azure CLI capability probing used as a last-resort fallback."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ENTRY_RE = re.compile(
    r"^\s*(?P<name>[a-z0-9][a-z0-9-]*)(?:\s+\[[^]]+\])?\s*:\s*(?P<description>.*)$",
    re.IGNORECASE,
)
OPTION_RE = re.compile(r"(?<!\w)--[a-zA-Z0-9][a-zA-Z0-9-]*")

READ_PREFIXES = ("list", "show", "get", "query", "search", "check", "exists")
BLOCKED_PATH_PARTS = frozenset(
    {
        "browse",
        "connect",
        "download",
        "exec",
        "execute",
        "export",
        "invoke",
        "login",
        "logout",
        "open",
        "rdp",
        "run",
        "run-command",
        "ssh",
    }
)
BLOCKED_ROOT_GROUPS = frozenset(
    {"account", "cache", "cloud", "config", "configure", "extension", "interactive", "upgrade"}
)


@dataclass(frozen=True)
class CLIProbeResult:
    command: Tuple[str, ...]
    succeeded: bool
    status: str
    detail: str = ""

    @property
    def permission_label(self) -> str:
        return "az-cli/read/" + "/".join(self.command)


def normalize_help_line(raw_line: str) -> str:
    """Normalize ANSI, carriage returns, and terminal overstrikes."""

    line = ANSI_RE.sub("", raw_line.replace("\r", ""))
    while "\b" in line:
        line = re.sub(r".\x08", "", line)
    return line.rstrip()


def parse_help_entries(lines: Iterable[str], heading: str) -> List[str]:
    """Parse an Azure CLI help section without relying on border characters."""

    expected = heading.rstrip(":").lower()
    in_section = False
    entries = []
    for raw_line in lines:
        line = normalize_help_line(raw_line)
        stripped = line.strip()
        if stripped.rstrip(":").lower() == expected:
            in_section = True
            continue
        if in_section and stripped and not line[:1].isspace():
            break
        if not in_section or not stripped:
            continue
        match = ENTRY_RE.match(line)
        if match:
            entries.append(match.group("name").lower())
    return list(dict.fromkeys(entries))


def required_options(lines: Iterable[str]) -> List[str]:
    """Find required options across current, old, Unix, and Windows help output."""

    options = []
    in_required = False
    normalized_lines = [normalize_help_line(line) for line in lines]
    for line in normalized_lines:
        stripped = line.strip()
        heading = stripped.rstrip(":").lower()
        if heading == "required arguments":
            in_required = True
            continue
        if in_required and stripped and not line[:1].isspace():
            in_required = False
        if in_required or "[required]" in line.lower() or "required: true" in line.lower():
            options.extend(OPTION_RE.findall(line))
    prose = " ".join(line.strip() for line in normalized_lines)
    if re.search(r"\bshould provide either\b", prose, re.I):
        # Azure's generated help sometimes omits [Required] for mutually
        # exclusive resource identifiers. Any marker is enough to skip safely.
        options.extend(OPTION_RE.findall(prose))
    return list(dict.fromkeys(options))


def is_safe_read_command(path: Sequence[str]) -> bool:
    if not path:
        return False
    lowered = tuple(part.lower() for part in path)
    if lowered[0] in BLOCKED_ROOT_GROUPS:
        return False
    if any(part in BLOCKED_PATH_PARTS for part in lowered):
        return False
    leaf = lowered[-1]
    return leaf.startswith(READ_PREFIXES)


class AzureCLIReadProbe:
    """Discover and run only non-interactive read commands from ``az --help``."""

    def __init__(
        self,
        subscription_id: str,
        *,
        services: Optional[Sequence[str]] = None,
        threads: int = 4,
        timeout: int = 30,
        debug: bool = False,
        executable: Optional[str] = None,
    ):
        self.subscription_id = subscription_id
        self.services = {service.strip().lower() for service in (services or []) if service.strip()}
        self.threads = max(1, int(threads))
        self.timeout = max(5, int(timeout))
        self.debug = debug
        self.executable = executable or shutil.which("az")

    @staticmethod
    def environment():
        env = os.environ.copy()
        env.update(
            {
                "AZURE_CORE_COLLECT_TELEMETRY": "no",
                "AZURE_CORE_DISABLE_CONFIRM_PROMPT": "yes",
                "AZURE_CORE_NO_COLOR": "yes",
                "AZURE_CORE_ONLY_SHOW_ERRORS": "yes",
                "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
                "PAGER": "cat",
            }
        )
        for name in (
            "AZURE_BATCH_ACCESS_KEY",
            "AZURE_STORAGE_ACCOUNT",
            "AZURE_STORAGE_CONNECTION_STRING",
            "AZURE_STORAGE_KEY",
            "AZURE_STORAGE_SAS_TOKEN",
        ):
            env.pop(name, None)
        return env

    def _run(self, args: Sequence[str], timeout: Optional[int] = None):
        if not self.executable:
            return None
        try:
            return subprocess.run(
                [self.executable, *args],
                capture_output=True,
                timeout=timeout or self.timeout,
                env=self.environment(),
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

    def help(self, path: Sequence[str]) -> List[str]:
        result = self._run([*path, "--help"])
        if result is None or result.returncode != 0:
            return []
        return (result.stdout + "\n" + result.stderr).splitlines()

    def discover_commands(self, max_depth: int = 6) -> List[Tuple[str, ...]]:
        root_help = self.help([])
        roots = parse_help_entries(root_help, "Subgroups")
        roots = [root for root in roots if root not in BLOCKED_ROOT_GROUPS]
        if self.services:
            roots = [root for root in roots if root in self.services]

        queue = [(root,) for root in roots]
        visited = set()
        commands = []
        while queue:
            level = [
                path
                for path in queue
                if path not in visited and len(path) <= max_depth
            ]
            queue = []
            visited.update(level)
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                help_pages = executor.map(self.help, level)
                for path, lines in zip(level, help_pages):
                    for subgroup in parse_help_entries(lines, "Subgroups"):
                        child = (*path, subgroup)
                        if not any(part in BLOCKED_PATH_PARTS for part in child):
                            queue.append(child)
                    for command in parse_help_entries(lines, "Commands"):
                        candidate = (*path, command)
                        if is_safe_read_command(candidate):
                            commands.append(candidate)
        return list(dict.fromkeys(commands))

    def probe(self, command: Sequence[str]) -> CLIProbeResult:
        command = tuple(command)
        if not is_safe_read_command(command):
            return CLIProbeResult(command, False, "unsafe-skipped")

        help_lines = self.help(command)
        required = required_options(help_lines)
        if required:
            return CLIProbeResult(command, False, "arguments-required", ", ".join(required))
        if not help_lines:
            return CLIProbeResult(command, False, "help-unavailable")

        args = [
            *command,
            "--subscription",
            self.subscription_id,
            "--output",
            "none",
            "--only-show-errors",
        ]
        result = self._run(args)
        if result is None:
            return CLIProbeResult(command, False, "timeout-or-launch-error")
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode == 0:
            return CLIProbeResult(command, True, "confirmed")

        lower = output.lower()
        if any(
            marker in lower
            for marker in (
                "authorizationfailed",
                "forbidden",
                "permission",
                "unauthorized",
                "does not have authorization",
            )
        ):
            status = "denied"
        elif any(marker in lower for marker in ("not found", "could not be found", "resourcenotfound")):
            status = "likely-resource-not-found"
        else:
            status = "inconclusive"
        detail = re.sub(r"\s+", " ", output)[:300] if self.debug else ""
        return CLIProbeResult(command, False, status, detail)
