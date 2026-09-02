"""Streaming, resumable, deduplicating Cowrie JSON importer."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from config import IMPORT_BATCH_SIZE
from db import connect, init_db, utc_now
from ingest import EVENT_INSERT_SQL, normalize_event


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True)
class LogMember:
    container: Path
    member_path: str
    source_name: str
    size: int
    file_key: str
    opener: Callable[[], BinaryIO]


def _source_name(path: str) -> str:
    parts = Path(path.replace("\\", "/")).parts
    for part in parts:
        if part.startswith("cowrie-logs-"):
            return part.removeprefix("cowrie-logs-")
    parent = Path(path).parent.name
    return parent or "cowrie"


def _is_cowrie_json(name: str) -> bool:
    filename = Path(name).name
    return filename.startswith("cowrie.json") and not filename.endswith(".gitignore")


def discover_logs(path: str | Path) -> Iterator[LogMember]:
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Cowrie log path does not exist: {path}")

    if path.is_file() and zipfile.is_zipfile(path):
        archive = zipfile.ZipFile(path)
        try:
            infos = [i for i in archive.infolist() if not i.is_dir() and _is_cowrie_json(i.filename)]
        finally:
            archive.close()
        for info in sorted(infos, key=lambda item: item.filename):
            key_text = f"zip|{path}|{info.filename}|{info.CRC}|{info.file_size}"

            def open_member(p=path, member=info.filename):
                owner = zipfile.ZipFile(p)
                raw = owner.open(member)
                raw._nisec_zip_owner = owner  # type: ignore[attr-defined]
                return raw

            yield LogMember(
                path, info.filename, _source_name(info.filename), info.file_size,
                hashlib.sha256(key_text.encode()).hexdigest(), open_member,
            )
        return

    candidates = [path] if path.is_file() else sorted(
        p for p in path.rglob("*") if p.is_file() and _is_cowrie_json(p.name)
    )
    for file_path in candidates:
        stat = file_path.stat()
        key_text = f"file|{file_path}|{stat.st_size}|{stat.st_mtime_ns}"
        yield LogMember(
            file_path,
            file_path.name,
            _source_name(str(file_path)),
            stat.st_size,
            hashlib.sha256(key_text.encode()).hexdigest(),
            lambda p=file_path: p.open("rb"),
        )


@contextmanager
def _open_text(member: LogMember):
    raw = member.opener()
    owner = getattr(raw, "_nisec_zip_owner", None)
    text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
    try:
        yield text
    finally:
        text.close()
        if owner is not None:
            owner.close()


def _already_complete(conn, file_key: str) -> bool:
    row = conn.execute("SELECT status FROM imports WHERE file_key=?", (file_key,)).fetchone()
    return bool(row and row["status"] == "complete")


def import_member(member: LogMember, *, max_lines: int | None = None) -> dict:
    init_db()
    conn = connect()
    if _already_complete(conn, member.file_key):
        conn.close()
        return {"member": member.member_path, "status": "skipped", "reason": "already imported"}

    conn.execute(
        """INSERT INTO imports(file_key,container_path,member_path,source_name,size_bytes,
           imported_at,status) VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(file_key) DO UPDATE SET imported_at=excluded.imported_at,status='running',error=NULL""",
        (member.file_key, str(member.container), member.member_path, member.source_name,
         member.size, utc_now(), "running"),
    )
    conn.commit()

    lines_seen = invalid = inserted = 0
    truncated = False
    batch: list[tuple] = []
    try:
        with _open_text(member) as stream:
            for line in stream:
                if max_lines is not None and lines_seen >= max_lines:
                    truncated = True
                    break
                lines_seen += 1
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict) or not raw.get("eventid"):
                        raise ValueError("not a Cowrie event")
                    batch.append(normalize_event(raw, "cowrie", member.source_name))
                except (json.JSONDecodeError, ValueError, TypeError):
                    invalid += 1
                    continue

                if len(batch) >= IMPORT_BATCH_SIZE:
                    before = conn.total_changes
                    conn.executemany(EVENT_INSERT_SQL, batch)
                    inserted += conn.total_changes - before
                    conn.commit()
                    batch.clear()

        if batch:
            before = conn.total_changes
            conn.executemany(EVENT_INSERT_SQL, batch)
            inserted += conn.total_changes - before
            conn.commit()

        duplicates = max(lines_seen - invalid - inserted, 0)
        final_status = "partial" if truncated else "complete"
        conn.execute(
            """UPDATE imports SET lines_seen=?,events_inserted=?,duplicates_skipped=?,
               invalid_lines=?,status=?,error=NULL WHERE file_key=?""",
            (lines_seen, inserted, duplicates, invalid, final_status, member.file_key),
        )
        conn.commit()
        return {
            "member": member.member_path, "source": member.source_name, "status": final_status,
            "lines": lines_seen, "inserted": inserted, "duplicates": duplicates, "invalid": invalid,
        }
    except Exception as exc:
        conn.execute(
            "UPDATE imports SET lines_seen=?,events_inserted=?,invalid_lines=?,status='failed',error=? WHERE file_key=?",
            (lines_seen, inserted, invalid, str(exc)[:2000], member.file_key),
        )
        conn.commit()
        raise
    finally:
        conn.close()


def import_path(
    path: str | Path,
    *,
    max_files: int | None = None,
    max_lines_per_file: int | None = None,
    progress: ProgressCallback = print,
) -> dict:
    members = list(discover_logs(path))
    if max_files is not None:
        members = members[:max_files]
    if not members:
        raise ValueError(f"No cowrie.json log files found under {path}")

    totals = {"files": len(members), "complete": 0, "partial": 0, "skipped": 0, "lines": 0, "inserted": 0, "duplicates": 0, "invalid": 0}
    for index, member in enumerate(members, 1):
        progress(f"[{index}/{len(members)}] {member.source_name}/{member.member_path}")
        result = import_member(member, max_lines=max_lines_per_file)
        status = result["status"]
        totals[status] = totals.get(status, 0) + 1
        for key in ("lines", "inserted", "duplicates", "invalid"):
            totals[key] += int(result.get(key, 0))
        progress(
            f"    {status}: {result.get('inserted', 0):,} inserted, "
            f"{result.get('duplicates', 0):,} duplicates, {result.get('invalid', 0):,} invalid"
        )
    return totals
