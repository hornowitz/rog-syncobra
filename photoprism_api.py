#!/usr/bin/env python3
"""Photoprism REST API helpers shared by rog-syncobra tools."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional, Sequence

import requests


def _expand_path(path: str) -> str:
    """Return a normalized absolute path with user expansion."""

    return os.path.abspath(os.path.expanduser(path))


logger = logging.getLogger('rog-syncobra')

STATE_DIR = '/var/lib/rog-syncobra'
PHOTOPRISM_PENDING_FILE = os.path.join(
    STATE_DIR, 'pending-photoprism-commands.txt'
)


@dataclass(frozen=True)
class PhotoprismTask:
    path: str = ''
    rescan: bool = False
    cleanup: bool = False
    display_path: str = field(default='', compare=False)


@dataclass
class PhotoprismAPIConfig:
    base_url: str
    username: str
    password: str
    verify_tls: bool = True
    rescan: bool = False
    cleanup: bool = False
    path_strip_prefixes: tuple[str, ...] = ()


class PhotoprismAPIError(Exception):
    """Raised when communicating with the Photoprism API fails."""


class PhotoprismAPIClient:
    def __init__(self, config: PhotoprismAPIConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_tls
        self._logged_in = False

    def _url(self, path: str) -> str:
        base = self.config.base_url.rstrip('/')
        return f"{base}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, *, payload: Optional[dict] = None) -> dict:
        url = self._url(path)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "PhotoprismAPI: preparing %s %s payload=%s",
                method,
                url,
                json.dumps(payload, sort_keys=True) if payload is not None else '{}',
            )
        try:
            response = self.session.request(
                method,
                url,
                json=payload,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise PhotoprismAPIError(str(exc)) from exc

        if response.status_code >= 400:
            detail = response.text.strip()
            if detail:
                detail = " ".join(detail.split())
                if len(detail) > 512:
                    detail = detail[:509] + '...'
                detail = f" ({detail})"
            else:
                detail = ''
            raise PhotoprismAPIError(
                f"HTTP {response.status_code} {response.reason} for {url}{detail}"
            )

        if response.content:
            try:
                return response.json()
            except ValueError:
                pass
        return {}

    def login(self) -> None:
        if self._logged_in:
            return
        logger.debug(
            "PhotoprismAPI: logging in as %s", self.config.username or '<unknown>'
        )
        data = self._request(
            'POST',
            '/api/v1/session',
            payload={'username': self.config.username, 'password': self.config.password},
        )
        token = data.get('access_token')
        if not token:
            raise PhotoprismAPIError('Photoprism API login failed: no access token')
        self.session.headers.update({'Authorization': f'Bearer {token}'})
        self._logged_in = True

    def trigger_index(self, path: str, rescan: bool, cleanup: bool) -> None:
        self.login()
        logger.debug(
            "PhotoprismAPI: POST %s path=%s rescan=%s cleanup=%s",
            self._url('/api/v1/index'),
            path,
            rescan,
            cleanup,
        )
        self._request(
            'POST',
            '/api/v1/index',
            payload={'path': path, 'rescan': rescan, 'cleanup': cleanup},
        )


def _strip_photoprism_prefixes(path: str, prefixes: Sequence[str]) -> str:
    if not prefixes:
        return path

    cleaned = path
    leading_slash = cleaned.startswith('/')
    normalized_path = cleaned.replace('\\', '/')
    candidate = PurePosixPath(normalized_path)

    prefix_candidates: list[PurePosixPath] = []
    seen: set[str] = set()
    for prefix in prefixes:
        if not prefix:
            continue
        cleaned_prefix = prefix.strip()
        if not cleaned_prefix:
            continue
        normalized_prefix = cleaned_prefix.replace('\\', '/')
        prefix_path = PurePosixPath(normalized_prefix)
        key = prefix_path.as_posix()
        if not key or key in seen:
            continue
        seen.add(key)
        prefix_candidates.append(prefix_path)

    if not prefix_candidates:
        return path

    for prefix_path in sorted(prefix_candidates, key=lambda value: len(value.as_posix()), reverse=True):
        try:
            relative = candidate.relative_to(prefix_path)
        except ValueError:
            continue

        relative_str = relative.as_posix()
        if relative_str == '.':
            relative_str = ''

        if leading_slash:
            return '/' if not relative_str else '/' + relative_str
        return relative_str

    return path


def _parse_photoprism_task(raw: str) -> Optional[PhotoprismTask]:
    if not raw:
        return None
    if raw.startswith('{'):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            logger.debug(
                "Ignoring legacy Photoprism command task entry: %s", raw
            )
            return None
        mode = payload.get('type')
        if mode in (None, 'api'):
            path = payload.get('path', '')
            rescan = bool(payload.get('rescan', False))
            cleanup = bool(payload.get('cleanup', False))
            display_path = payload.get('display_path', path)
            return PhotoprismTask(
                path=path,
                rescan=rescan,
                cleanup=cleanup,
                display_path=display_path,
            )
        if mode == 'command':
            command = payload.get('command', '').strip()
            if command:
                logger.debug(
                    "Dropping legacy Photoprism command task: %s", command
                )
            return None
    if raw.startswith('API|'):
        value = raw[4:]
        return PhotoprismTask(path=value, display_path=value)
    logger.debug("Ignoring legacy Photoprism command task entry: %s", raw)
    return None


def _serialize_photoprism_task(task: PhotoprismTask) -> str:
    payload = {
        'type': 'api',
        'path': task.path,
        'rescan': task.rescan,
        'cleanup': task.cleanup,
        'display_path': task.display_path or task.path,
    }
    return json.dumps(payload, sort_keys=True)


def _dedupe_tasks(tasks: Sequence[PhotoprismTask]) -> list[PhotoprismTask]:
    seen: set[PhotoprismTask] = set()
    deduped: list[PhotoprismTask] = []
    for task in tasks:
        if task in seen:
            continue
        seen.add(task)
        deduped.append(task)
    return deduped


def _task_within_library_root(task: PhotoprismTask, library_root: Optional[Path]) -> bool:
    """Return True if *task* refers to a path that lives under *library_root*."""

    if library_root is None:
        return True

    normalized_root = Path(_expand_path(str(library_root)))
    candidates = [task.display_path, task.path]

    for candidate in candidates:
        if not candidate:
            continue

        # The Photoprism API accepts '/' to mean "library root" regardless of
        # the actual filesystem layout, so treat it as always valid here.
        if candidate == '/':
            return True

        candidate_path = Path(candidate)

        # Relative paths are interpreted with respect to the library root, so
        # they are always considered valid.
        if not candidate_path.is_absolute():
            return True

        try:
            expanded = Path(_expand_path(str(candidate_path)))
        except OSError:
            continue

        if expanded == normalized_root:
            return True

        try:
            expanded.relative_to(normalized_root)
        except ValueError:
            continue
        else:
            return True

    return False


def load_pending_photoprism_tasks() -> list[PhotoprismTask]:
    tasks: list[PhotoprismTask] = []
    seen: set[PhotoprismTask] = set()
    try:
        with open(PHOTOPRISM_PENDING_FILE, 'r', encoding='utf-8') as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                task = _parse_photoprism_task(raw)
                if task is None or task in seen:
                    continue
                seen.add(task)
                tasks.append(task)
    except FileNotFoundError:
        return []
    except OSError as exc:
        logger.warning(
            "Unable to read pending Photoprism tasks from %s: %s",
            PHOTOPRISM_PENDING_FILE,
            exc,
        )
    return tasks


def save_pending_photoprism_tasks(tasks: Sequence[PhotoprismTask]) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(PHOTOPRISM_PENDING_FILE, 'w', encoding='utf-8') as handle:
            for task in tasks:
                handle.write(_serialize_photoprism_task(task) + '\n')
    except OSError as exc:
        logger.warning(
            "Unable to persist pending Photoprism tasks to %s: %s",
            PHOTOPRISM_PENDING_FILE,
            exc,
        )


def handle_photoprism_index(
    dry_run: bool,
    changes_detected: bool,
    targets: Sequence[Path],
    library_root: Optional[Path],
    api_config: Optional[PhotoprismAPIConfig],
    display_root: Optional[Path] = None,
) -> None:
    have_api = bool(
        api_config
        and api_config.base_url
        and api_config.username
        and api_config.password
    )

    if not have_api:
        return

    normalized_targets: list[Path] = []
    seen_paths: set[str] = set()
    for target in targets:
        normalized = Path(_expand_path(str(target)))
        key = str(normalized)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        normalized_targets.append(normalized)

    dest_root_path = Path(_expand_path(str(library_root))) if library_root else None
    display_root_path: Optional[Path]
    if display_root is None:
        display_root_path = None
    else:
        try:
            display_root_path = Path(_expand_path(str(display_root)))
        except TypeError:
            display_root_path = None

    def _format_display_target(task: PhotoprismTask) -> str:
        """Return a human friendly path for *task* suitable for logging."""

        def _resolve_candidate(value: str) -> Optional[str]:
            if not value:
                return None

            candidate = value.strip()
            if not candidate or candidate == '.':
                return None

            if candidate == '/':
                base = display_root_path or dest_root_path
                return base.as_posix() if base is not None else '/'

            if candidate.startswith('/'):
                normalized_candidate = candidate
                base_candidates: list[Path] = []
                if display_root_path is not None:
                    base_candidates.append(display_root_path)
                if dest_root_path is not None:
                    base_candidates.append(dest_root_path)

                for base in base_candidates:
                    base_str = base.as_posix().rstrip('/') or '/'
                    if normalized_candidate == base_str:
                        return normalized_candidate
                    if normalized_candidate.startswith(base_str + '/'):
                        return normalized_candidate

                base = display_root_path or dest_root_path
                if base is not None:
                    return (base / normalized_candidate.lstrip('/')).as_posix()
                return normalized_candidate

            base = display_root_path or dest_root_path
            if base is not None:
                return (base / candidate).as_posix()
            return candidate

        for candidate in (task.display_path, task.path):
            resolved = _resolve_candidate(candidate)
            if resolved:
                return resolved

        base = display_root_path or dest_root_path
        if base is not None:
            return base.as_posix()
        return '/'

    api_tasks: list[PhotoprismTask] = []
    for target in normalized_targets:
        path_value = ''
        display_value = ''
        if dest_root_path is not None:
            try:
                relative = target.relative_to(dest_root_path)
            except ValueError:
                logger.debug(
                    "Skipping Photoprism target outside library root: %s",
                    target,
                )
                continue
            relative_path = Path(relative)
            absolute_dest = dest_root_path / relative_path
        else:
            relative_path = None
            absolute_dest = target

        if display_root_path is not None and relative_path is not None:
            display_path = display_root_path / relative_path
            display_value = display_path.as_posix()
            path_value = display_value
        elif relative_path is not None:
            display_value = absolute_dest.as_posix()
            path_value = relative_path.as_posix()
        else:
            display_value = target.as_posix()
            path_value = display_value

        if api_config and api_config.path_strip_prefixes:
            path_value = _strip_photoprism_prefixes(
                path_value,
                api_config.path_strip_prefixes,
            )

        if path_value in ('', '.'):
            path_value = '/'
        if not display_value:
            display_value = path_value
        api_tasks.append(
            PhotoprismTask(
                path=path_value,
                rescan=api_config.rescan,
                cleanup=api_config.cleanup,
                display_path=display_value,
            )
        )

    if not api_tasks:
        if display_root_path is not None:
            default_display = display_root_path.as_posix()
        elif dest_root_path is not None:
            default_display = dest_root_path.as_posix()
        else:
            default_display = '/'
        api_tasks.append(
            PhotoprismTask(
                path='/',
                rescan=api_config.rescan,
                cleanup=api_config.cleanup,
                display_path=default_display,
            )
        )

    new_tasks = _dedupe_tasks(api_tasks)
    pending = load_pending_photoprism_tasks()

    if logger.isEnabledFor(logging.DEBUG):
        for task in new_tasks:
            logger.debug(
                'PhotoprismAPI: queued task payload=%s',
                _serialize_photoprism_task(task),
            )

    if dest_root_path is not None and pending:
        filtered: list[PhotoprismTask] = []
        for task in pending:
            if _task_within_library_root(task, dest_root_path):
                filtered.append(task)
            else:
                display_target = _format_display_target(task)
                logger.info(
                    'Dropping Photoprism task outside library root: %s',
                    display_target,
                )
        pending = filtered

    if dry_run:
        if changes_detected:
            for task in new_tasks:
                if task not in pending:
                    display_target = _format_display_target(task)
                    logger.info(
                        '[DRY] Would trigger Photoprism API index for: %s',
                        display_target,
                    )
        return

    if changes_detected:
        for task in new_tasks:
            if task not in pending:
                pending.append(task)

    if not pending:
        return

    remaining = list(pending)

    try:
        api_client = PhotoprismAPIClient(api_config)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            'Photoprism API client initialization failed (%s); will retry later',
            exc,
        )
        return

    for idx, task in enumerate(pending):
        display_target = _format_display_target(task)
        logger.info('Triggering Photoprism API index for: %s', display_target)
        try:
            api_client.trigger_index(task.path or '/', task.rescan, task.cleanup)
        except PhotoprismAPIError as exc:
            logger.warning(
                'Photoprism API request failed (%s); will retry later',
                exc,
            )
            remaining = pending[idx:]
            break
        else:
            logger.info('Photoprism API index request accepted')
            remaining = pending[idx + 1 :]

    save_pending_photoprism_tasks(remaining)


__all__ = [
    'PhotoprismAPIClient',
    'PhotoprismAPIConfig',
    'PhotoprismAPIError',
    'PhotoprismTask',
    'handle_photoprism_index',
    'load_pending_photoprism_tasks',
    'save_pending_photoprism_tasks',
    'STATE_DIR',
    'PHOTOPRISM_PENDING_FILE',
]

