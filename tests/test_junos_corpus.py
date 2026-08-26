from __future__ import annotations
import hashlib, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/network/junos"

def test_junos_corpus_manifest_hashes_and_redaction():
    manifest=json.loads((CORPUS/"manifest.json").read_text())
    listed=[]
    for source in manifest["sources"]:
        for name,meta in source["files"].items():
            path=CORPUS/name; listed.append(name)
            assert path.exists()
            assert len(meta["sha256"]) == 64
            assert re.fullmatch(r"[0-9a-f]{64}", meta["sha256"])
            assert hashlib.sha256(path.read_bytes()).hexdigest() == meta["fixture_sha256"]
            text=path.read_text()
            assert not re.search(r"encrypted-password|ssh-rsa|\b(?:10|172|192)\.\d+\.\d+\.\d+\b", text, re.I)
            assert not re.search(r"\b(?:public|private)\s+key\b", text, re.I)
            assert not re.search(r"\b(?:password|secret)\s+\S+", text, re.I)
    assert set(listed) == {p.name for p in CORPUS.glob("*.conf")}

def test_junos_corpus_contains_real_pass_and_fail_states():
    texts={p.name:p.read_text() for p in CORPUS.glob("*.conf")}
    checks={
      "junos_service_telnet_absent": lambda t: not re.search(r"^\s*telnet;",t,re.M),
      "junos_service_ftp_absent": lambda t: not re.search(r"^\s*ftp;",t,re.M),
      "junos_syslog_present": lambda t: bool(re.search(r"^\s*syslog\s*\{",t,re.M)),
      "junos_snmp_public_absent": lambda t: not re.search(r"^\s*community\s+public\s*\{",t,re.M),
    }
    expected=json.loads((CORPUS/"manual_expectations.json").read_text())
    for key,predicate in checks.items():
        observed_pass={name for name,text in texts.items() if predicate(text)}
        observed_fail=set(texts)-observed_pass
        assert observed_pass == set(expected[key]["pass"])
        assert observed_fail == set(expected[key]["fail"])
