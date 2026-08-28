"""SQLite persistence for the local organizational dashboard.

The store retains product metadata and report projections, never uploaded raw
configuration text. Built-in engines and the canonical report contract remain
independent from this module.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


PROFILE_STATUSES = {"draft", "published", "archived"}
TRAINING_STATUSES = {"review", "confirmed", "failed"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DashboardStore:
    """Small transactional repository for local dashboard state."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS device_records (
                    record_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    vendor_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_device_records_device
                    ON device_records(device_id);
                CREATE INDEX IF NOT EXISTS idx_device_records_vendor_status
                    ON device_records(vendor_key, status);

                CREATE TABLE IF NOT EXISTS training_sessions (
                    session_id TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS training_patterns (
                    session_id TEXT NOT NULL,
                    pattern_hash TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    category TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    source TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    structural INTEGER NOT NULL DEFAULT 0,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    confirmed INTEGER NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, pattern_hash),
                    FOREIGN KEY (session_id) REFERENCES training_sessions(session_id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS training_api_runs (
                    run_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    model TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    input_tokens INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL,
                    cost_usd REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES training_sessions(session_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_training_api_runs_session
                    ON training_api_runs(session_id, created_at);

                CREATE TABLE IF NOT EXISTS knowledge_sources (
                    source_id TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    excerpt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vendor_profiles (
                    profile_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    normalization_version TEXT NOT NULL DEFAULT 'vendor-line-v1',
                    status TEXT NOT NULL,
                    source_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (source_id) REFERENCES knowledge_sources(source_id)
                        ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS profile_rules (
                    rule_id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    pattern_hash TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    secure_when TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    framework TEXT NOT NULL DEFAULT '',
                    framework_control_id TEXT NOT NULL DEFAULT '',
                    source_reference TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (profile_id) REFERENCES vendor_profiles(profile_id)
                        ON DELETE CASCADE
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(training_sessions)").fetchall()
            }
            if "source_id" not in columns:
                connection.execute("ALTER TABLE training_sessions ADD COLUMN source_id TEXT")
            rule_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(profile_rules)").fetchall()
            }
            if "pattern_hash" not in rule_columns:
                connection.execute(
                    "ALTER TABLE profile_rules ADD COLUMN pattern_hash TEXT NOT NULL DEFAULT ''"
                )
            profile_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(vendor_profiles)").fetchall()
            }
            if "normalization_version" not in profile_columns:
                connection.execute(
                    "ALTER TABLE vendor_profiles ADD COLUMN normalization_version "
                    "TEXT NOT NULL DEFAULT 'vendor-line-v1'"
                )

    @staticmethod
    def _json_object(value: dict[str, Any]) -> str:
        if not isinstance(value, dict):
            raise TypeError("stored record must be a JSON object")
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    def upsert_device_record(self, record: dict[str, Any]) -> None:
        required = ("record_id", "device_id", "vendor_key", "status")
        missing = [key for key in required if not str(record.get(key, "")).strip()]
        if missing:
            raise ValueError(f"device record missing required fields: {', '.join(missing)}")
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO device_records
                    (record_id, device_id, vendor_key, status, record_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    device_id=excluded.device_id,
                    vendor_key=excluded.vendor_key,
                    status=excluded.status,
                    record_json=excluded.record_json,
                    updated_at=excluded.updated_at
                """,
                (
                    record["record_id"],
                    record["device_id"],
                    record["vendor_key"],
                    record["status"],
                    self._json_object(record),
                    _utc_now(),
                ),
            )

    def delete_device_record(self, record_id: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM device_records WHERE record_id = ?", (record_id,))

    def get_device_record(self, record_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT record_json FROM device_records WHERE record_id = ?", (record_id,)
            ).fetchone()
        return json.loads(row["record_json"]) if row else None

    def load_device_records(self) -> dict[str, dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT record_id, record_json FROM device_records ORDER BY updated_at"
            ).fetchall()
        return {row["record_id"]: json.loads(row["record_json"]) for row in rows}

    def create_training_session(self, session: dict[str, Any]) -> None:
        required = ("session_id", "vendor", "platform", "filename", "config_sha256")
        missing = [key for key in required if not str(session.get(key, "")).strip()]
        if missing:
            raise ValueError(f"training session missing required fields: {', '.join(missing)}")
        status = str(session.get("status", "review"))
        if status not in TRAINING_STATUSES:
            raise ValueError(f"unsupported training status: {status}")
        now = _utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO training_sessions
                    (session_id, vendor, platform, filename, config_sha256, status,
                     source_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["session_id"], session["vendor"], session["platform"],
                    session["filename"], session["config_sha256"], status,
                    session.get("source_id"), now, now,
                ),
            )

    def save_training_patterns(self, session_id: str, patterns: list[dict[str, Any]]) -> None:
        now = _utc_now()
        with self._connection() as connection:
            for pattern in patterns:
                if not pattern.get("pattern_hash") or not pattern.get("pattern"):
                    raise ValueError("training pattern requires pattern_hash and redacted pattern")
                connection.execute(
                    """
                    INSERT INTO training_patterns
                        (session_id, pattern_hash, pattern, category, reasoning, source,
                         mode, structural, occurrence_count, confirmed, note, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id, pattern_hash) DO UPDATE SET
                        category=excluded.category,
                        reasoning=excluded.reasoning,
                        source=excluded.source,
                        mode=excluded.mode,
                        structural=excluded.structural,
                        occurrence_count=excluded.occurrence_count,
                        confirmed=excluded.confirmed,
                        note=excluded.note,
                        updated_at=excluded.updated_at
                    """,
                    (
                        session_id,
                        pattern["pattern_hash"],
                        pattern["pattern"],
                        str(pattern.get("category", "unknown")),
                        str(pattern.get("reasoning", "")),
                        str(pattern.get("source", "unknown")),
                        str(pattern.get("mode", "dry-run")),
                        int(bool(pattern.get("structural", False))),
                        int(pattern.get("occurrence_count", 1)),
                        int(bool(pattern.get("confirmed", False))),
                        str(pattern.get("note", "")),
                        now,
                    ),
                )

    def get_training_session(self, session_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            session = connection.execute(
                "SELECT * FROM training_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not session:
                return None
            patterns = connection.execute(
                """
                SELECT pattern_hash, pattern, category, reasoning, source, mode,
                       structural, occurrence_count, confirmed, note
                FROM training_patterns WHERE session_id = ?
                ORDER BY occurrence_count DESC, pattern
                """,
                (session_id,),
            ).fetchall()
            api_runs = connection.execute(
                """
                SELECT run_id, model, call_count, input_tokens, output_tokens,
                       cost_usd, created_at
                FROM training_api_runs WHERE session_id = ?
                ORDER BY created_at, run_id
                """,
                (session_id,),
            ).fetchall()
        result = dict(session)
        result["patterns"] = [
            {
                **dict(row),
                "structural": bool(row["structural"]),
                "confirmed": bool(row["confirmed"]),
            }
            for row in patterns
        ]
        result["api_runs"] = [dict(row) for row in api_runs]
        return result

    def list_training_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT s.*,
                       COUNT(p.pattern_hash) AS pattern_count,
                       COALESCE(SUM(p.confirmed), 0) AS confirmed_count
                FROM training_sessions s
                LEFT JOIN training_patterns p ON p.session_id = s.session_id
                GROUP BY s.session_id
                ORDER BY s.updated_at DESC
                LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_prior_training_pattern(
        self, vendor: str, platform: str, pattern_hash: str
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT p.pattern_hash, p.pattern, p.category, p.reasoning, p.source,
                       p.mode, p.structural, p.occurrence_count, p.confirmed, p.note
                FROM training_patterns p
                JOIN training_sessions s ON s.session_id = p.session_id
                WHERE lower(s.vendor) = lower(?) AND lower(s.platform) = lower(?)
                  AND p.pattern_hash = ?
                  AND (p.confirmed = 1 OR p.source = 'provider')
                ORDER BY p.confirmed DESC, p.updated_at DESC
                LIMIT 1
                """,
                (vendor, platform, pattern_hash),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["structural"] = bool(result["structural"])
        result["confirmed"] = bool(result["confirmed"])
        return result

    def update_training_classifications(
        self, session_id: str, patterns: list[dict[str, Any]]
    ) -> None:
        """Persist provider/cache suggestions without confirming them."""
        now = _utc_now()
        with self._connection() as connection:
            for pattern in patterns:
                cursor = connection.execute(
                    """
                    UPDATE training_patterns
                    SET category = ?, reasoning = ?, source = ?, mode = ?,
                        confirmed = 0, updated_at = ?
                    WHERE session_id = ? AND pattern_hash = ? AND confirmed = 0
                    """,
                    (
                        str(pattern.get("category", "unknown")),
                        str(pattern.get("reasoning", "")),
                        str(pattern.get("source", "provider")),
                        str(pattern.get("mode", "real-api")),
                        now,
                        session_id,
                        pattern["pattern_hash"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise KeyError(
                        f"unconfirmed training pattern not found: {pattern['pattern_hash']}"
                    )
            connection.execute(
                "UPDATE training_sessions SET updated_at = ? WHERE session_id = ?",
                (now, session_id),
            )

    def record_training_api_run(self, run: dict[str, Any]) -> None:
        required = ("run_id", "session_id", "model")
        missing = [key for key in required if not str(run.get(key, "")).strip()]
        if missing:
            raise ValueError(f"training API run missing required fields: {', '.join(missing)}")
        numeric = {
            "call_count": int(run.get("call_count", 0)),
            "input_tokens": int(run.get("input_tokens", 0)),
            "output_tokens": int(run.get("output_tokens", 0)),
            "cost_usd": float(run.get("cost_usd", 0.0)),
        }
        if any(value < 0 for value in numeric.values()):
            raise ValueError("training API usage values must be non-negative")
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO training_api_runs
                    (run_id, session_id, model, call_count, input_tokens,
                     output_tokens, cost_usd, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run["run_id"], run["session_id"], run["model"],
                    numeric["call_count"], numeric["input_tokens"],
                    numeric["output_tokens"], numeric["cost_usd"], _utc_now(),
                ),
            )

    def get_training_pattern(self, session_id: str, pattern_hash: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT pattern_hash, pattern, category, reasoning, source, mode,
                       structural, occurrence_count, confirmed, note
                FROM training_patterns
                WHERE session_id = ? AND pattern_hash = ?
                """,
                (session_id, pattern_hash),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["structural"] = bool(result["structural"])
        result["confirmed"] = bool(result["confirmed"])
        return result

    def list_confirmed_patterns(self, vendor: str, platform: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT p.pattern_hash, p.pattern, p.category, p.note,
                       MAX(p.updated_at) AS updated_at
                FROM training_patterns p
                JOIN training_sessions s ON s.session_id = p.session_id
                WHERE lower(s.vendor) = lower(?) AND lower(s.platform) = lower(?)
                  AND p.confirmed = 1 AND p.structural = 0
                GROUP BY p.pattern_hash, p.pattern, p.category, p.note
                ORDER BY p.pattern
                """,
                (vendor, platform),
            ).fetchall()
        return [dict(row) for row in rows]

    def confirm_training_pattern(
        self, session_id: str, pattern_hash: str, category: str, note: str = ""
    ) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE training_patterns
                SET category = ?, confirmed = 1, source = 'human_confirmed',
                    mode = 'human-confirmed', note = ?, updated_at = ?
                WHERE session_id = ? AND pattern_hash = ?
                """,
                (category, note, _utc_now(), session_id, pattern_hash),
            )
            if cursor.rowcount != 1:
                raise KeyError("training pattern not found")
            remaining = connection.execute(
                """
                SELECT COUNT(*) FROM training_patterns
                WHERE session_id = ? AND structural = 0 AND confirmed = 0
                """,
                (session_id,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE training_sessions SET status = ?, updated_at = ? WHERE session_id = ?",
                ("confirmed" if remaining == 0 else "review", _utc_now(), session_id),
            )

    def add_knowledge_source(self, source: dict[str, Any]) -> None:
        required = (
            "source_id", "vendor", "platform", "filename", "media_type",
            "content_sha256", "excerpt",
        )
        missing = [key for key in required if not str(source.get(key, "")).strip()]
        if missing:
            raise ValueError(f"knowledge source missing required fields: {', '.join(missing)}")
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO knowledge_sources
                    (source_id, vendor, platform, filename, media_type,
                     content_sha256, excerpt, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source["source_id"], source["vendor"], source["platform"],
                    source["filename"], source["media_type"],
                    source["content_sha256"], source["excerpt"], _utc_now(),
                ),
            )

    def create_vendor_profile(self, profile: dict[str, Any]) -> None:
        required = ("profile_id", "name", "vendor", "platform")
        missing = [key for key in required if not str(profile.get(key, "")).strip()]
        if missing:
            raise ValueError(f"vendor profile missing required fields: {', '.join(missing)}")
        status = str(profile.get("status", "draft"))
        if status not in PROFILE_STATUSES:
            raise ValueError(f"unsupported profile status: {status}")
        now = _utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO vendor_profiles
                    (profile_id, name, vendor, platform, normalization_version,
                     status, source_id,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile["profile_id"], profile["name"], profile["vendor"],
                    profile["platform"],
                    str(profile.get("normalization_version", "vendor-line-v1")),
                    status, profile.get("source_id"), now, now,
                ),
            )

    def list_vendor_profiles(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT p.*, COUNT(r.rule_id) AS rule_count
                FROM vendor_profiles p
                LEFT JOIN profile_rules r ON r.profile_id = p.profile_id AND r.enabled = 1
                GROUP BY p.profile_id
                ORDER BY p.updated_at DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_vendor_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            profile = connection.execute(
                "SELECT * FROM vendor_profiles WHERE profile_id = ?", (profile_id,)
            ).fetchone()
            if not profile:
                return None
            rules = connection.execute(
                "SELECT * FROM profile_rules WHERE profile_id = ? ORDER BY created_at, rule_id",
                (profile_id,),
            ).fetchall()
            source = None
            if profile["source_id"]:
                source = connection.execute(
                    """
                    SELECT source_id, filename, media_type, content_sha256, excerpt, created_at
                    FROM knowledge_sources WHERE source_id = ?
                    """,
                    (profile["source_id"],),
                ).fetchone()
        result = dict(profile)
        result["rules"] = [{**dict(row), "enabled": bool(row["enabled"])} for row in rules]
        result["source"] = dict(source) if source else None
        return result

    def add_profile_rule(self, rule: dict[str, Any]) -> None:
        required = (
            "rule_id", "profile_id", "title", "category", "pattern_hash", "pattern",
            "secure_when", "severity", "source_reference", "remediation",
        )
        missing = [key for key in required if not str(rule.get(key, "")).strip()]
        if missing:
            raise ValueError(f"profile rule missing required fields: {', '.join(missing)}")
        if rule["secure_when"] not in {"present", "absent"}:
            raise ValueError("secure_when must be present or absent")
        if rule["severity"] not in {"low", "medium", "high"}:
            raise ValueError("severity must be low, medium, or high")
        now = _utc_now()
        with self._connection() as connection:
            profile = connection.execute(
                "SELECT status FROM vendor_profiles WHERE profile_id = ?",
                (rule["profile_id"],),
            ).fetchone()
            if not profile:
                raise KeyError("vendor profile not found")
            if profile["status"] != "draft":
                raise ValueError("published or archived profiles cannot be edited")
            duplicate = connection.execute(
                "SELECT 1 FROM profile_rules WHERE profile_id = ? AND pattern_hash = ?",
                (rule["profile_id"], rule["pattern_hash"]),
            ).fetchone()
            if duplicate:
                raise ValueError("this confirmed pattern is already a rule in the profile")
            connection.execute(
                """
                INSERT INTO profile_rules
                    (rule_id, profile_id, title, category, pattern_hash, pattern,
                     secure_when, severity, framework, framework_control_id,
                     source_reference, remediation, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["rule_id"], rule["profile_id"], rule["title"], rule["category"],
                    rule["pattern_hash"], rule["pattern"], rule["secure_when"],
                    rule["severity"], str(rule.get("framework", "")),
                    str(rule.get("framework_control_id", "")), rule["source_reference"],
                    rule["remediation"], int(bool(rule.get("enabled", True))), now, now,
                ),
            )
            connection.execute(
                "UPDATE vendor_profiles SET updated_at = ? WHERE profile_id = ?",
                (now, rule["profile_id"]),
            )

    def publish_vendor_profile(self, profile_id: str) -> None:
        with self._connection() as connection:
            profile = connection.execute(
                "SELECT status, source_id FROM vendor_profiles WHERE profile_id = ?",
                (profile_id,),
            ).fetchone()
            if not profile:
                raise KeyError("vendor profile not found")
            if profile["status"] != "draft":
                raise ValueError("only draft profiles can be published")
            if not profile["source_id"]:
                raise ValueError("profile requires an attached knowledge source before publication")
            rule_count = connection.execute(
                "SELECT COUNT(*) FROM profile_rules WHERE profile_id = ? AND enabled = 1",
                (profile_id,),
            ).fetchone()[0]
            if rule_count < 1:
                raise ValueError("profile requires at least one enabled rule")
            connection.execute(
                "UPDATE vendor_profiles SET status = 'published', updated_at = ? WHERE profile_id = ?",
                (_utc_now(), profile_id),
            )
