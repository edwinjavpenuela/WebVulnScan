#!/usr/bin/env python3
"""WebVulnScan: interfaz profesional y segura para perfiles de Nmap."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_TIMEOUT_SECONDS = 1800
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    nmap_args: tuple[str, ...]
    privileged_hint: bool = False


@dataclass(frozen=True)
class ScanResult:
    started_at: str
    duration_seconds: float
    command: list[str]
    targets: list[str]
    profile: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    dry_run: bool = False


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Reconocimiento rapido con deteccion de servicios en los 100 puertos mas comunes.",
        nmap_args=("-T3", "--top-ports", "100", "-sV"),
    ),
    "standard": ScanProfile(
        name="standard",
        description="Perfil equilibrado para evaluaciones defensivas: servicios y scripts por defecto.",
        nmap_args=("-T3", "--top-ports", "1000", "-sV", "-sC"),
    ),
    "web": ScanProfile(
        name="web",
        description="Foco en puertos HTTP/HTTPS habituales y servicios web alternativos.",
        nmap_args=("-T3", "-p", "80,443,8000,8080,8081,8443,9000,9443", "-sV", "-sC"),
    ),
    "deep": ScanProfile(
        name="deep",
        description="Evaluacion amplia de todos los puertos. Puede tardar bastante.",
        nmap_args=("-T3", "-p-", "-A"),
    ),
    "low-noise": ScanProfile(
        name="low-noise",
        description="Escaneo mas lento y conservador sobre pocos puertos comunes.",
        nmap_args=("-sS", "-T2", "--top-ports", "100", "-sV"),
        privileged_hint=True,
    ),
}

PROFILE_ALIASES = {
    "1": "quick",
    "2": "standard",
    "3": "web",
    "4": "deep",
    "5": "low-noise",
    "rapido": "quick",
    "rapida": "quick",
    "estandar": "standard",
    "normal": "standard",
    "profundo": "deep",
    "web": "web",
    "bajo-ruido": "low-noise",
    "low_noise": "low-noise",
    "sigiloso": "low-noise",
    "agresivo": "deep",
}


class WebVulnScanError(ValueError):
    """Raised when user-provided scan input is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_target(raw_target: str) -> str:
    candidate = raw_target.strip()
    if not candidate:
        raise WebVulnScanError("El target no puede estar vacio.")

    if "/" in candidate:
        try:
            return str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            pass

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = parsed.hostname or candidate
    host = host.strip("[]").rstrip(".")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    if not DOMAIN_RE.fullmatch(host):
        raise WebVulnScanError(
            f"Target invalido: {raw_target!r}. Usa un dominio, IP, CIDR o URL valida."
        )
    return host


def validate_ports(raw_ports: str) -> str:
    ports = raw_ports.strip()
    if not ports:
        raise WebVulnScanError("La lista de puertos no puede estar vacia.")

    for item in ports.split(","):
        part = item.strip()
        if not part:
            raise WebVulnScanError("La lista de puertos contiene un elemento vacio.")

        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                raise WebVulnScanError(f"Rango de puertos invalido: {part!r}.")
            start, end = int(start_raw), int(end_raw)
            if start > end:
                raise WebVulnScanError(f"Rango de puertos invertido: {part!r}.")
            values = (start, end)
        else:
            if not part.isdigit():
                raise WebVulnScanError(f"Puerto invalido: {part!r}.")
            values = (int(part),)

        if any(value < 1 or value > 65535 for value in values):
            raise WebVulnScanError(f"Puerto fuera de rango: {part!r}.")

    return ports


def resolve_profile(name: str) -> ScanProfile:
    normalized = name.strip().lower()
    canonical = PROFILE_ALIASES.get(normalized, normalized)
    try:
        return PROFILES[canonical]
    except KeyError as exc:
        options = ", ".join(sorted(PROFILES))
        raise WebVulnScanError(f"Perfil desconocido: {name!r}. Opciones: {options}.") from exc


def remove_profile_ports(args: tuple[str, ...]) -> list[str]:
    cleaned: list[str] = []
    skip_next = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-p", "--top-ports"}:
            skip_next = True
            continue
        if arg.startswith("-p") and len(arg) > 2:
            continue
        cleaned.append(arg)

    return cleaned


def build_nmap_command(
    nmap_path: str,
    profile: ScanProfile,
    targets: list[str],
    ports: str | None = None,
) -> list[str]:
    profile_args = remove_profile_ports(profile.nmap_args) if ports else list(profile.nmap_args)
    if ports:
        profile_args.extend(["-p", ports])
    return [nmap_path, *profile_args, *targets]


def resolve_nmap_path(nmap: str) -> str:
    if "/" in nmap:
        path = Path(nmap)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise WebVulnScanError(f"No existe o no es ejecutable el binario de Nmap: {nmap}")

    resolved = shutil.which(nmap)
    if not resolved:
        raise WebVulnScanError("Nmap no esta instalado o no esta en PATH.")
    return resolved


def run_nmap(command: list[str], targets: list[str], profile: str, timeout: int) -> ScanResult:
    started_at = utc_now()
    started = time.monotonic()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - started
        return ScanResult(
            started_at=started_at,
            duration_seconds=round(duration, 3),
            command=command,
            targets=targets,
            profile=profile,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        timeout_message = f"El escaneo excedio el timeout configurado ({timeout}s)."
        return ScanResult(
            started_at=started_at,
            duration_seconds=round(duration, 3),
            command=command,
            targets=targets,
            profile=profile,
            exit_code=124,
            stdout=stdout,
            stderr=f"{stderr}\n{timeout_message}".strip(),
            timed_out=True,
        )


def build_dry_run(command: list[str], targets: list[str], profile: str) -> ScanResult:
    return ScanResult(
        started_at=utc_now(),
        duration_seconds=0,
        command=command,
        targets=targets,
        profile=profile,
        exit_code=0,
        stdout="",
        stderr="",
        dry_run=True,
    )


def render_text_report(result: ScanResult) -> str:
    status = "DRY-RUN" if result.dry_run else ("OK" if result.exit_code == 0 else "ERROR")
    lines = [
        "WebVulnScan Report",
        f"Status: {status}",
        f"Profile: {result.profile}",
        f"Targets: {', '.join(result.targets)}",
        f"Started: {result.started_at}",
        f"Duration: {result.duration_seconds}s",
        f"Exit code: {result.exit_code}",
        f"Command: {shlex.join(result.command)}",
    ]

    if result.dry_run:
        lines.append("\nDry-run activo: no se ejecuto Nmap.")
    if result.stdout:
        lines.extend(["\n--- Nmap stdout ---", result.stdout.rstrip()])
    if result.stderr:
        lines.extend(["\n--- Nmap stderr ---", result.stderr.rstrip()])

    return "\n".join(lines) + "\n"


def render_json_report(result: ScanResult) -> str:
    return json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n"


def write_or_print(report: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


def list_profiles() -> str:
    rows = ["Perfiles disponibles:"]
    for key in sorted(PROFILES):
        profile = PROFILES[key]
        hint = " (puede requerir privilegios)" if profile.privileged_hint else ""
        rows.append(f"- {key}: {profile.description}{hint}")
    return "\n".join(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webvulnscan",
        description="CLI defensiva para ejecutar perfiles Nmap reproducibles sobre targets autorizados.",
    )
    parser.add_argument("targets", nargs="*", help="Dominio, IP, CIDR o URL autorizada.")
    parser.add_argument("--target", action="append", help="Target adicional. Puede repetirse.")
    parser.add_argument(
        "--profile",
        default="standard",
        help="Perfil de escaneo: quick, standard, web, deep o low-noise.",
    )
    parser.add_argument("--ports", help="Puertos a evaluar, por ejemplo: 80,443,8080 o 1-1024.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Timeout en segundos.")
    parser.add_argument("--nmap", default="nmap", help="Ruta o nombre del binario de Nmap.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Formato del reporte.")
    parser.add_argument("--output", type=Path, help="Archivo de salida del reporte.")
    parser.add_argument("--dry-run", action="store_true", help="Muestra el comando sin ejecutar Nmap.")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirma que tienes autorizacion explicita para escanear los targets.",
    )
    parser.add_argument("--list-profiles", action="store_true", help="Lista perfiles y termina.")
    return parser


def collect_targets(args: argparse.Namespace) -> list[str]:
    raw_targets = [*args.targets, *(args.target or [])]
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in raw_targets:
        target = normalize_target(raw)
        if target not in seen:
            normalized.append(target)
            seen.add(target)

    return normalized


def execute(args: argparse.Namespace) -> int:
    if args.list_profiles:
        print(list_profiles())
        return 0

    if args.timeout < 1:
        raise WebVulnScanError("El timeout debe ser mayor que cero.")

    profile = resolve_profile(args.profile)
    targets = collect_targets(args)
    if not targets:
        raise WebVulnScanError("Debes indicar al menos un target autorizado.")

    if not args.dry_run and not args.confirm_authorized:
        raise WebVulnScanError(
            "Para ejecutar el escaneo debes agregar --confirm-authorized."
        )

    ports = validate_ports(args.ports) if args.ports else None
    nmap_path = args.nmap if args.dry_run else resolve_nmap_path(args.nmap)
    command = build_nmap_command(nmap_path, profile, targets, ports)
    result = build_dry_run(command, targets, profile.name) if args.dry_run else run_nmap(
        command,
        targets,
        profile.name,
        args.timeout,
    )
    report = render_json_report(result) if args.format == "json" else render_text_report(result)
    write_or_print(report, args.output)
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return execute(args)
    except WebVulnScanError as exc:
        parser.exit(status=2, message=f"webvulnscan: error: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
