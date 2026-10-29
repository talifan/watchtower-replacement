#!/usr/bin/env python3
"""Allow-listed Compose updater triggered by Diun's authenticated webhook."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import ipaddress
import json
import logging
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path("/home/example/repo")
PROJECT = ROOT / "watchtower-replacement"
ENV_FILE = PROJECT / ".env"
STATE_FILE = Path("/var/lib/diun-updater/state.json")
TELEGRAM_TOKEN_FILE = Path("/root/snap/docker/common/diun-telegram-token")
TELEGRAM_CHAT_IDS_FILE = Path("/root/snap/docker/common/diun-telegram-chatids.json")
LISTEN_ADDRESS = "172.17.0.1"
LISTEN_PORT = 9868
DOCKER_SUBNET = ipaddress.ip_network("172.17.0.0/16")
MAX_BODY = 64 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
MONTHLY_TAG_RE = re.compile(r"^(\d{2})(0[1-9]|1[0-2])\.(\d+)$")


@dataclass(frozen=True)
class Target:
    compose_file: str
    services: tuple[str, ...]
    mode: str = "floating"
    expected_tag: str | None = None
    tag_pattern: str | None = None
    major: int | None = None
    fallback_tag: str | None = None
    env_key: str | None = None
    pin_digest: bool = False
    image_anchor: str | None = None


# File-provider image names are normalized to registry/path without the tag.
# Every target is explicit; webhook data never becomes a shell argument except
# after it has passed the repository, tag, and digest allow-lists below.
TARGETS: dict[str, tuple[Target, ...]] = {
    "ghcr.io/crazy-max/diun": (
        Target("watchtower-replacement/compose.yaml", ("diun",), "semver", tag_pattern=r"^4\.\d+\.\d+$", major=4),
    ),
    "docker.io/diygod/rsshub": (
        Target("rsshub/docker-compose.yml", ("rsshub",), expected_tag="latest"),
    ),
    "ghcr.io/flaresolverr/flaresolverr": (
        Target("torr_stack/docker-compose.yml", ("flaresolverr",), expected_tag="latest"),
    ),
    "ghcr.io/hotio/jellyfin": (
        Target("jellyfin/docker-compose.yml", ("jellyfin",), expected_tag="latest"),
    ),
    "ghcr.io/hotio/prowlarr": (
        Target("torr_stack/docker-compose.yml", ("prowlarr",), expected_tag="latest"),
    ),
    "ghcr.io/hotio/qbittorrent": (
        Target("torr_stack/docker-compose.yml", ("qbittorrent",), expected_tag="latest"),
    ),
    "ghcr.io/hotio/radarr": (
        Target("torr_stack/docker-compose.yml", ("radarr",), expected_tag="latest"),
    ),
    "ghcr.io/hotio/sonarr": (
        Target("torr_stack/docker-compose.yml", ("sonarr",), expected_tag="latest"),
    ),
    "ghcr.io/immich-app/immich-machine-learning": (
        Target("immich/docker-compose.yml", ("immich-server", "immich-machine-learning"), expected_tag="release"),
    ),
    "ghcr.io/immich-app/immich-server": (
        Target("immich/docker-compose.yml", ("immich-server", "immich-machine-learning"), expected_tag="release"),
    ),
    "ghcr.io/immich-app/postgres": (
        Target("immich/docker-compose.yml", ("database",), expected_tag="14-vectorchord0.4.3-pgvectors0.2.0"),
    ),
    "ghcr.io/seerr-team/seerr": (
        Target("jellyseerr/docker-compose.yml", ("jellyseerr",), expected_tag="latest"),
    ),
    "ghcr.io/yourok/torrserver": (
        Target("torrserver/docker-compose.yml", ("torrserver",), expected_tag="latest"),
    ),
    "docker.io/linuxserver/heimdall": (
        Target("heimdall/docker-compose.yml", ("heimdall",), expected_tag="latest"),
    ),
    "docker.io/linuxserver/jackett": (
        Target("jackett/compose.yaml", ("jackett",), expected_tag="latest"),
    ),
    "docker.io/s1t5/mailarchiver": (
        Target("/home/example/docker/mailarchive/compose.yml", ("mailarchive-app",), "monthly", tag_pattern=r"^\d{4}\.\d+$"),
    ),
    "mcr.microsoft.com/playwright/mcp": (
        Target("mcp-playwright/docker-compose.yml", ("mcp-playwright",), "semver", tag_pattern=r"^v0\.0\.\d+$", major=0, fallback_tag="v0.0.82", pin_digest=True),
    ),
    "docker.io/ollama/ollama": (
        Target("ollama/docker-compose.yml", ("ollama",), expected_tag="latest"),
    ),
    "docker.io/openspeedtest/latest": (
        Target("openspeedtest/compose.yaml", ("speedtest",), expected_tag="latest"),
    ),
    "docker.io/portainer/portainer-ee": (
        Target("portainer/docker-compose.yml", ("portainer",), expected_tag="latest"),
    ),
    "docker.io/jc21/nginx-proxy-manager": (
        Target("proxy/docker-compose.yml", ("app",), "semver", tag_pattern=r"^2\.\d+\.\d+$", major=2),
    ),
    "ghcr.io/qdrant/qdrant/qdrant": (
        Target("qdrant/docker-compose.yml", ("qdrant",), "semver", tag_pattern=r"^v1\.19\.\d+$", major=1),
    ),
    "ghcr.io/rclone/rclone": (
        Target("yandexdisk_backup/docker-compose.yml", ("main",), "semver", tag_pattern=r"^1\.\d+\.\d+$", major=1, pin_digest=True, image_anchor="x-backup-common"),
    ),
    "docker.io/library/redis": (
        Target("rsshub/docker-compose.yml", ("redis",), expected_tag="alpine"),
    ),
    "docker.io/library/postgres": (
        Target("n8n/news-bot-engine/docker-compose.yml", ("news-bot-postgres",), expected_tag="16-alpine"),
    ),
    "docker.io/valkey/valkey": (
        Target("immich/docker-compose.yml", ("redis",), expected_tag="8-bookworm"),
    ),
    "docker.io/vaultwarden/server": (
        Target("vaultwarden/docker-compose.yml", ("vaultwarden",), "semver", tag_pattern=r"^1\.\d+\.\d+$", major=1, env_key="VW_IMAGE"),
    ),
    "docker.io/ruslanys/yandex.disk": (
        Target("yandexdisk_secondary/docker-compose.yml", ("yandexdisk_secondary",), expected_tag="latest"),
    ),
}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("diun-updater")
jobs: queue.Queue[dict[str, Any]] = queue.Queue()
pending: set[str] = set()
pending_lock = threading.Lock()


def canonical_repo(reference: str) -> tuple[str, str, str | None]:
    """Return (registry/path, tag, digest), applying Docker Hub defaults."""
    image = reference.strip()
    digest = None
    if "@" in image:
        image, digest = image.rsplit("@", 1)
    slash = image.rfind("/")
    colon = image.rfind(":")
    if colon > slash:
        repo, tag = image[:colon], image[colon + 1 :]
    else:
        repo, tag = image, "latest"
    first, sep, rest = repo.partition("/")
    if not sep or ("." not in first and ":" not in first and first != "localhost"):
        repo = "docker.io/" + repo
    if repo.startswith("docker.io/") and "/" not in repo[len("docker.io/") :]:
        repo = "docker.io/library/" + repo[len("docker.io/") :]
    return repo.lower(), tag, digest


def valid_digest(digest: Any) -> str | None:
    if isinstance(digest, str) and DIGEST_RE.fullmatch(digest):
        return digest
    return None


def parse_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip("\"'")
    return result


def service_image_lines(lines: list[str], service: str) -> list[int]:
    """Find image fields directly under a Compose service, allowing any YAML indent."""
    services_header = None
    services_indent = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)services:\s*(?:#.*)?$", line.rstrip("\r\n"))
        if match:
            services_header = index
            services_indent = len(match.group(1))
            break
    if services_header is None:
        raise ValueError("Compose file has no services section")

    def mapping(line: str) -> tuple[int, str] | None:
        body = line.rstrip("\r\n")
        match = re.match(r"^(\s*)([A-Za-z0-9_.-]+):(?:\s|$)", body)
        if not match:
            return None
        return len(match.group(1)), match.group(2)

    service_headers: list[tuple[int, int, str]] = []
    section_end = len(lines)
    for index in range(services_header + 1, len(lines)):
        parsed = mapping(lines[index])
        if parsed and parsed[0] <= services_indent:
            section_end = index
            break
        if parsed and parsed[0] > services_indent:
            service_headers.append((index, parsed[0], parsed[1]))
    if not service_headers:
        raise ValueError("Compose services section is empty")
    service_indent = min(indent for _, indent, _ in service_headers)
    target_headers = [
        index for index, indent, name in service_headers
        if indent == service_indent and name == service
    ]
    if len(target_headers) != 1:
        raise ValueError(f"expected one service {service}, found {len(target_headers)}")
    target_start = target_headers[0]
    target_end = section_end
    for index, indent, _ in service_headers:
        if index > target_start and indent <= service_indent:
            target_end = index
            break

    property_indents = [
        parsed[0]
        for line in lines[target_start + 1:target_end]
        if (parsed := mapping(line)) is not None and parsed[0] > service_indent
    ]
    if not property_indents:
        return []
    property_indent = min(property_indents)
    return [
        index for index in range(target_start + 1, target_end)
        if (parsed := mapping(lines[index])) is not None
        and parsed[0] == property_indent
        and parsed[1] == "image"
    ]


def image_value(line: str, service: str) -> str:
    body = line.rstrip("\r\n")
    match = re.match(r"^\s*image:\s*(['\"]?)([^'\"\s]+)\1(?:\s|#|$)", body)
    if not match:
        raise ValueError(f"invalid image field for service {service}")
    return match.group(2)


def service_image(text: str, service: str) -> str:
    lines = text.splitlines(keepends=True)
    image_lines = service_image_lines(lines, service)
    if len(image_lines) != 1:
        raise ValueError(f"expected one image field for service {service}, found {len(image_lines)}")
    return image_value(lines[image_lines[0]], service)


def anchor_image(text: str, anchor: str) -> str:
    in_anchor = False
    images: list[str] = []
    for line in text.splitlines():
        if re.match(rf"^{re.escape(anchor)}:\s*&?[^\s]*\s*$", line):
            in_anchor = True
            continue
        if in_anchor and line and not line[0].isspace():
            in_anchor = False
        if in_anchor:
            match = re.match(r"^  image:\s*(\S+)", line)
            if match:
                images.append(match.group(1).strip("\"'"))
    if len(images) != 1:
        raise ValueError(f"expected one image field in anchor {anchor}, found {len(images)}")
    return images[0]


def update_anchor_image(text: str, anchor: str, old_ref: str, new_ref: str) -> str:
    lines = text.splitlines(keepends=True)
    in_anchor = False
    replaced = 0
    old_tag = canonical_repo(old_ref)[1]
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        if re.match(rf"^{re.escape(anchor)}:\s*&?[^\s]*\s*$", body):
            in_anchor = True
            continue
        if in_anchor and body and not body[0].isspace():
            in_anchor = False
        if in_anchor and re.match(r"^  image:\s*", body):
            prefix, image_part = body.split("image:", 1)
            current_token = image_part.strip().split()[0].strip("\"'")
            if canonical_repo(current_token)[0] != canonical_repo(old_ref)[0]:
                raise ValueError(f"image repository changed unexpectedly in anchor {anchor}")
            tail = image_part.strip()
            suffix = tail[len(tail.split()[0]) :]
            suffix = re.sub(rf"\b{re.escape(old_tag)}\b", canonical_repo(new_ref)[1], suffix)
            ending = "\n" if line.endswith("\n") else ""
            lines[index] = f"{prefix}image: {new_ref}{suffix}{ending}"
            replaced += 1
    if replaced != 1:
        raise ValueError(f"expected to replace one image in anchor {anchor}, replaced {replaced}")
    return "".join(lines)


def update_service_image(
    text: str,
    service: str,
    old_ref: str,
    new_ref: str,
    old_tag_override: str | None = None,
) -> str:
    lines = text.splitlines(keepends=True)
    image_lines = service_image_lines(lines, service)
    if len(image_lines) != 1:
        raise ValueError(f"expected one image field for {service}, found {len(image_lines)}")
    old_tag = old_tag_override or canonical_repo(old_ref)[1]
    index = image_lines[0]
    line = lines[index]
    body = line.rstrip("\r\n")
    prefix, image_part = body.split("image:", 1)
    match = re.match(r"^(\s*)(['\"]?)([^'\"\s]+)\2(.*)$", image_part)
    if not match:
        raise ValueError(f"invalid image field for service {service}")
    current_token = match.group(3)
    if canonical_repo(current_token)[0] != canonical_repo(old_ref)[0]:
        raise ValueError(f"image repository changed unexpectedly for {service}")
    suffix = re.sub(rf"\b{re.escape(old_tag)}\b", canonical_repo(new_ref)[1], match.group(4))
    ending = line[len(body):]
    lines[index] = f"{prefix}image:{match.group(1)}{match.group(2)}{new_ref}{match.group(2)}{suffix}{ending}"
    return "".join(lines)


def atomic_write(path: Path, content: str) -> None:
    mode = path.stat().st_mode & 0o777
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def compose_file_path(target: Target) -> Path:
    path = Path(target.compose_file)
    return path if path.is_absolute() else ROOT / path


def read_target_image(target: Target, service: str) -> str:
    compose_path = compose_file_path(target)
    if target.env_key:
        value = parse_env_file(compose_path.parent / ".env").get(target.env_key)
        if not value:
            raise ValueError(f"missing {target.env_key} in {compose_path.parent / '.env'}")
        return value
    if target.image_anchor:
        return anchor_image(compose_path.read_text(), target.image_anchor)
    return service_image(compose_path.read_text(), service)


def semver(tag: str) -> tuple[int, int, int] | None:
    match = SEMVER_RE.fullmatch(tag)
    return tuple(map(int, match.groups())) if match else None


def monthly_release(tag: str) -> tuple[int, int, int] | None:
    match = MONTHLY_TAG_RE.fullmatch(tag)
    return tuple(map(int, match.groups())) if match else None


def set_env_image(target: Target, old_ref: str, new_ref: str) -> None:
    path = compose_file_path(target)
    env_path = path.parent / ".env"
    lines = env_path.read_text().splitlines(keepends=True)
    updated = 0
    for index, line in enumerate(lines):
        if line.startswith(f"{target.env_key}="):
            ending = "\n" if line.endswith("\n") else ""
            lines[index] = f"{target.env_key}={new_ref}{ending}"
            updated += 1
    if updated != 1:
        raise ValueError(f"expected one {target.env_key} value in {env_path}, found {updated}")
    atomic_write(env_path, "".join(lines))


def run_compose(target: Target, args: list[str], timeout: int = 1800) -> str:
    compose_path = compose_file_path(target)
    command = [
        "/snap/docker/current/bin/docker",
        "compose",
        "--project-directory",
        str(compose_path.parent),
        "-f",
        str(compose_path),
        *args,
    ]
    result = subprocess.run(
        command,
        cwd=compose_path.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        log.error("Compose failed (%s): %s", " ".join(args), result.stdout[-6000:])
        raise RuntimeError(f"Compose returned {result.returncode}")
    if result.stdout.strip():
        log.info("Compose %s: %s", " ".join(args), result.stdout[-3000:].strip())
    return result.stdout


def running_image_matches(target: Target, service: str, expected_ref: str) -> bool:
    compose_path = compose_file_path(target)
    command = [
        "/snap/docker/current/bin/docker",
        "compose",
        "--project-directory",
        str(compose_path.parent),
        "-f",
        str(compose_path),
        "ps",
        "-q",
        service,
    ]
    result = subprocess.run(command, cwd=compose_path.parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError(f"cannot inspect running Compose service {service}: {result.stderr[-1000:]}")
    container_ids = result.stdout.strip().splitlines()
    if not container_ids:
        return False
    expected_repo, expected_tag, expected_digest = canonical_repo(expected_ref)
    if expected_tag == "latest" and target.fallback_tag and "@" in expected_ref:
        expected_tag = target.fallback_tag
    for container_id in container_ids:
        inspect = subprocess.run(
            ["/snap/docker/current/bin/docker", "inspect", "--format", "{{.Config.Image}}", container_id],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
        ).stdout.strip()
        actual_repo, actual_tag, actual_digest = canonical_repo(inspect)
        if actual_tag == "latest" and target.fallback_tag and "@" in inspect:
            actual_tag = target.fallback_tag
        if actual_repo != expected_repo or actual_tag != expected_tag:
            return False
        if expected_digest and actual_digest != expected_digest:
            return False
    return True


def target_event(
    target: Target,
    expected_repo: str,
    tag: str,
    digest: str | None,
    status: str,
) -> tuple[bool, bool]:
    """Return (should_deploy, config_changed) for this target."""
    if target.mode == "floating":
        if tag != target.expected_tag:
            return False, False
        changed = False
        compose_path = compose_file_path(target)
        text = compose_path.read_text()
        updated = text
        pinned = False
        for service in target.services:
            current = service_image(updated, service)
            current_repo, _, current_digest = canonical_repo(current)
            if current_repo != expected_repo:
                raise ValueError(f"configured image for {service} does not match Diun inventory")
            pinned = pinned or bool(current_digest)
            if digest and current_digest and current_digest != digest:
                updated = update_service_image(updated, service, current, current.rsplit("@", 1)[0] + "@" + digest)
                changed = True
        if pinned and not digest:
            return False, False
        if changed:
            atomic_write(compose_path, updated)
        return True, changed

    if target.mode == "monthly":
        if not target.tag_pattern or not re.fullmatch(target.tag_pattern, tag):
            return False, False
        candidate = monthly_release(tag)
        if not candidate:
            return False, False
        for service in target.services:
            current_ref = read_target_image(target, service)
            current_repo, current_tag, _ = canonical_repo(current_ref)
            if current_repo != expected_repo:
                raise ValueError(f"configured image for {service} does not match Diun inventory")
            current = monthly_release(current_tag)
            if not current:
                raise ValueError(f"cannot determine monthly release for {service}: {current_ref}")
            if candidate < current:
                return False, False
            if candidate > current:
                raw_repo = current_ref.split("@", 1)[0]
                slash = raw_repo.rfind("/")
                colon = raw_repo.rfind(":")
                if colon > slash:
                    raw_repo = raw_repo[:colon]
                compose_path = compose_file_path(target)
                updated = update_service_image(
                    compose_path.read_text(), service, current_ref, f"{raw_repo}:{tag}"
                )
                atomic_write(compose_path, updated)
                return True, True
            if tag == current_tag and status in {"new", "update"}:
                return status == "update" or not running_image_matches(target, service, current_ref), False
        return False, False

    if target.mode != "semver" or not target.tag_pattern or not re.fullmatch(target.tag_pattern, tag):
        return False, False
    candidate = semver(tag)
    if not candidate or target.major is None or candidate[0] != target.major:
        return False, False

    currents: list[tuple[str, tuple[int, int, int] | None, str]] = []
    for service in target.services:
        current_ref = read_target_image(target, service)
        current_repo, current_tag, current_digest = canonical_repo(current_ref)
        if current_repo != expected_repo:
            raise ValueError(f"configured image for {service} does not match Diun inventory")
        if current_tag == "latest" and "@" in current_ref:
            current_tag = target.fallback_tag or ""
        current = semver(current_tag) if current_tag else None
        if not current and target.fallback_tag:
            current_tag = target.fallback_tag
            current = semver(current_tag)
        if not current:
            raise ValueError(f"cannot determine current version for {service}: {current_ref}")
        if current[0] != target.major or candidate < current:
            return False, False
        currents.append((current_ref, current, current_digest or ""))

    changed = False
    deploy = False
    for service, (current_ref, current, current_digest) in zip(target.services, currents):
        _, current_tag, _ = canonical_repo(current_ref)
        if current_tag == "latest" and "@" in current_ref:
            current_tag = target.fallback_tag or ""
        version_changed = candidate > current
        digest_changed = bool(digest and target.pin_digest and digest != current_digest)
        if version_changed or digest_changed:
            if target.pin_digest and not digest:
                raise ValueError(f"registry digest missing for pinned image {tag}")
            # Keep the Compose spelling/registry prefix from its current ref.
            raw_repo = current_ref.split("@", 1)[0]
            slash = raw_repo.rfind("/")
            colon = raw_repo.rfind(":")
            if colon > slash:
                raw_repo = raw_repo[:colon]
            new_ref = f"{raw_repo}:{tag}"
            if target.pin_digest:
                new_ref += f"@{digest}"
            if target.env_key:
                set_env_image(target, current_ref, new_ref)
            else:
                compose_path = compose_file_path(target)
                text = compose_path.read_text()
                if target.image_anchor:
                    updated = update_anchor_image(text, target.image_anchor, current_ref, new_ref)
                else:
                    updated = update_service_image(text, service, current_ref, new_ref, target.fallback_tag)
                atomic_write(compose_path, updated)
            changed = True
            deploy = True
        elif tag == current_tag and status in {"new", "update"}:
            deploy = status == "update" or not running_image_matches(target, service, current_ref)
    return deploy, changed


def compose_service_container_ids(target: Target, service: str) -> list[str]:
    compose_path = compose_file_path(target)
    result = subprocess.run(
        [
            "/snap/docker/current/bin/docker",
            "compose",
            "--project-directory",
            str(compose_path.parent),
            "-f",
            str(compose_path),
            "ps",
            "-q",
            service,
        ],
        cwd=compose_path.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"cannot inspect Compose service {service}: {result.stderr[-1000:]}")
    return result.stdout.strip().splitlines()


def inspect_service_container(container_id: str) -> tuple[str, str, str]:
    output = subprocess.run(
        [
            "/snap/docker/current/bin/docker",
            "inspect",
            "--format",
            "{{.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
            container_id,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=True,
    ).stdout.strip()
    image_id, separator, state_and_health = output.partition("|")
    if not separator:
        raise RuntimeError("Docker returned an invalid container status")
    state, _, health = state_and_health.partition("|")
    return image_id, state, health


def run_target(target: Target) -> bool:
    services = list(target.services)
    before = {
        service: tuple(
            inspect_service_container(container_id)[0]
            for container_id in compose_service_container_ids(target, service)
        )
        for service in services
    }
    run_compose(target, ["pull", *services])
    run_compose(target, ["up", "-d", "--no-deps", *services])
    deadline = time.monotonic() + 300
    for service in services:
        container_ids = compose_service_container_ids(target, service)
        if not container_ids:
            raise RuntimeError(f"Compose returned no container for service {service}")
        while True:
            wait_for_health = False
            for container_id in container_ids:
                _, state, health = inspect_service_container(container_id)
                if state != "running" or health == "unhealthy":
                    raise RuntimeError(f"service {service} failed readiness (state={state}, health={health or 'n/a'})")
                wait_for_health = wait_for_health or health == "starting"
            if not wait_for_health:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"service {service} did not become healthy within 300 seconds")
            time.sleep(3)

    after = {
        service: tuple(
            inspect_service_container(container_id)[0]
            for container_id in compose_service_container_ids(target, service)
        )
        for service in services
    }
    return before != after


def notify_update_result(repo: str, tag: str, success: bool) -> None:
    message = (
        f"HomeAlert: ✅ Образ обновлён: {repo}:{tag}"
        if success
        else f"HomeAlert: ❌ Не удалось обновить образ: {repo}:{tag}"
    )
    try:
        token = TELEGRAM_TOKEN_FILE.read_text().strip()
        chat_ids = json.loads(TELEGRAM_CHAT_IDS_FILE.read_text())
        if not token or not isinstance(chat_ids, list) or not chat_ids:
            raise ValueError("Telegram notification credentials are incomplete")
    except Exception as exc:
        log.warning("Cannot prepare update-result Telegram notification (%s)", type(exc).__name__)
        return

    for chat_id in chat_ids:
        if isinstance(chat_id, bool) or not isinstance(chat_id, (str, int)):
            continue
        body = json.dumps({"chat_id": chat_id, "text": message}).encode()
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = json.loads(response.read())
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise RuntimeError("Telegram API rejected notification")
        except Exception as exc:
            log.warning("Update-result Telegram notification failed (%s)", type(exc).__name__)


def state_events() -> set[str]:
    try:
        payload = json.loads(STATE_FILE.read_text())
        return set(payload.get("handled", []))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return set()


def save_event(event_key: str) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    handled = list(state_events())
    if event_key not in handled:
        handled.append(event_key)
    payload = {"handled": handled[-1000:]}
    fd, tmp_name = tempfile.mkstemp(prefix=".state.", dir=STATE_FILE.parent)
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(payload, file)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, STATE_FILE)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def process_event(event: dict[str, Any]) -> None:
    status = event.get("status")
    if status not in {"new", "update"} or event.get("provider") != "file":
        return
    image = event.get("image")
    if not isinstance(image, str) or len(image) > 512:
        log.warning("Ignoring event with invalid image field")
        return
    repo, tag, _ = canonical_repo(image)
    digest = valid_digest(event.get("digest"))
    targets = TARGETS.get(repo)
    if not targets:
        log.info("No deployment rule for %s", repo)
        return
    event_key = hashlib.sha256(f"{repo}:{tag}@{digest or ''}".encode()).hexdigest()
    if event_key in state_events():
        log.info("Ignoring already handled update for %s:%s", repo, tag)
        return

    deploy_targets: list[Target] = []
    try:
        for target in targets:
            deploy, _ = target_event(target, repo, tag, digest, status)
            if deploy:
                deploy_targets.append(target)
    except Exception:
        log.exception("Update preparation failed for %s:%s", repo, tag)
        notify_update_result(repo, tag, success=False)
        return
    if not deploy_targets:
        save_event(event_key)
        log.info("No newer allowed release for %s:%s", repo, tag)
        return

    image_changed = False
    try:
        for target in deploy_targets:
            log.info("Updating %s:%s via %s (%s)", repo, tag, target.compose_file, ",".join(target.services))
            image_changed = run_target(target) or image_changed
    except Exception:
        log.exception("Update failed for %s:%s; the failed release was not marked handled", repo, tag)
        notify_update_result(repo, tag, success=False)
        return
    save_event(event_key)
    if not image_changed:
        log.info("No container image changed for %s:%s", repo, tag)
        return
    log.info("Update completed for %s:%s", repo, tag)
    notify_update_result(repo, tag, success=True)


def worker() -> None:
    while True:
        event = jobs.get()
        key = event["_queue_key"]
        try:
            process_event(event)
        except Exception:
            log.exception("Unhandled updater error")
        finally:
            with pending_lock:
                pending.discard(key)
            jobs.task_done()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "DiunComposeUpdater/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        log.info("http %s %s", self.client_address[0], format % args)

    def send_json(self, status: int, payload: dict[str, str]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/diun":
            self.send_json(404, {"error": "not found"})
            return
        try:
            peer = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            self.send_json(403, {"error": "forbidden"})
            return
        if peer not in DOCKER_SUBNET:
            self.send_json(403, {"error": "forbidden"})
            return
        token = parse_env_file(ENV_FILE).get("DIUN_UPDATER_TOKEN", "")
        expected = f"Bearer {token}" if token else ""
        received = self.headers.get("Authorization", "")
        if not expected or not hmac.compare_digest(received, expected):
            self.send_json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self.send_json(413, {"error": "invalid body size"})
            return
        try:
            event = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "invalid JSON"})
            return
        if not isinstance(event, dict):
            self.send_json(400, {"error": "invalid event"})
            return
        image = event.get("image")
        if not isinstance(image, str):
            self.send_json(400, {"error": "missing image"})
            return
        repo, tag, _ = canonical_repo(image)
        key = hashlib.sha256(f"{repo}:{tag}@{event.get('digest', '')}".encode()).hexdigest()
        with pending_lock:
            if key not in pending:
                pending.add(key)
                event["_queue_key"] = key
                jobs.put(event)
        self.send_json(202, {"status": "accepted"})


def main() -> None:
    if not ENV_FILE.is_file():
        raise SystemExit(f"missing updater token file: {ENV_FILE}")
    threading.Thread(target=worker, daemon=True, name="compose-update-worker").start()
    server = http.server.ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)
    server.daemon_threads = True
    log.info("Listening on %s:%s for authenticated Diun updates", LISTEN_ADDRESS, LISTEN_PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
