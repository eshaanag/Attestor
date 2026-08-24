"""Provenance and byte-integrity checks for the Phase B Cisco corpus."""

import hashlib
import json
from pathlib import Path


CORPUS_DIR = Path(__file__).parent / "fixtures" / "network" / "cisco_ios"


def test_cisco_reference_corpus_manifest_is_complete_and_unchanged():
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["license"] == "MIT"
    assert manifest["repository"].startswith("https://github.com/")
    assert len(manifest["commit"]) == 40
    assert manifest["retrieved_at"] == "2026-08-24"
    assert manifest["status"] == "reference_configs"
    assert len(manifest["entries"]) == 8

    seen = set()
    for entry in manifest["entries"]:
        filename = entry["file"]
        assert filename not in seen
        seen.add(filename)

        path = CORPUS_DIR / filename
        assert path.is_file(), filename
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"], filename

        assert entry["source_path"]
        assert entry["source_url"].startswith(
            "https://github.com/c4geeks/ccna-labs/blob/"
        )
        assert entry["article_url"].startswith("https://computingforgeeks.com/")
        assert entry["platform"]

    assert seen == {
        path.name
        for path in CORPUS_DIR.iterdir()
        if path.is_file() and path.suffix in {".txt", ".cfg", ".conf"}
    }
