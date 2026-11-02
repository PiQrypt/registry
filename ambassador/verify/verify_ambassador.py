#!/usr/bin/env python3
"""
verify_ambassador.py - check the PiQrypt ambassador chain from a published snapshot, offline.

One file, Python 3.9+, standard library only. Signatures are checked with the `cryptography`
package or with `pynacl` when one of them is installed (pip install cryptography); without
either, everything else is still checked and the result is PARTIAL.

    python verify_ambassador.py                         # fetch the latest published snapshot
    python verify_ambassador.py --chain latest.pqz      # a file you already hold
    python verify_ambassador.py --comment-file c.txt    # also check a Moltbook comment
    python verify_ambassador.py --expect-agent pq1_...  # agent id you got from another channel
    python verify_ambassador.py --predecessor 2026-05-13.pqz   # the chain that came before

What it checks, and what it does not prove, is written in VERIFY_AMBASSADOR.md.
Exit status: 0 PASS, 1 FAIL, 2 the snapshot could not be read, 3 PARTIAL (a check could not be done:
no signature library installed, or no event in the snapshot carries its signed body).
"""
import argparse
import base64
import hashlib
import json
import math
import re
import sys
import urllib.request

DEFAULT_URL = "https://raw.githubusercontent.com/piqrypt/registry/main/ambassador/chain/latest.pqz"
SUFFIX = re.compile(r"\s*\[sha256:([0-9a-f]{12})\]\s*$")
MAX_BYTES = 200 * 1024 * 1024


# ---------------------------------------------------------------------------
# AISS-1.0 canonical JSON (the form that was signed and hashed)
# ---------------------------------------------------------------------------

def _ser(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN or Infinity cannot be canonicalized")
        text = repr(value)
        return text if any(c in text for c in ".eE") else text + ".0"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_ser(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _ser(v) for k, v in sorted(value.items(), key=lambda kv: kv[0])
        ) + "}"
    raise ValueError("cannot canonicalize " + type(value).__name__)


def canonical(value) -> bytes:
    return _ser(value).encode("utf-8")


# ---------------------------------------------------------------------------
# Ed25519 (optional backends)
# ---------------------------------------------------------------------------

def ed25519_backend():
    """(name, verify(public_key_bytes, message, signature) -> bool), or (None, None)."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def verify(public_key, message, signature):
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
                return True
            except InvalidSignature:
                return False
        return "cryptography", verify
    except ImportError:
        pass
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        def verify(public_key, message, signature):
            try:
                VerifyKey(public_key).verify(message, signature)
                return True
            except BadSignatureError:
                return False
        return "pynacl", verify
    except ImportError:
        return None, None


# ---------------------------------------------------------------------------
# Structure (same rules as services/chain_continuity.py in the server)
# ---------------------------------------------------------------------------

def analyze(events):
    index = {}
    for i, e in enumerate(events):
        if e.get("event_hash"):
            index[e["event_hash"]] = i
    children = {}
    for e in events:
        if e.get("previous_hash"):
            children.setdefault(e["previous_hash"], []).append(e)
    head = None
    for i, e in enumerate(events):
        if (e.get("event_hash") or "") not in children:
            if head is None or (e.get("timestamp") or 0, i) >= (events[head].get("timestamp") or 0, head):
                head = i
    line, seen, cur = [], set(), head
    while cur is not None and cur not in seen:
        seen.add(cur)
        line.append(cur)
        parent = events[cur].get("previous_hash") or ""
        cur = index.get(parent) if parent else None
    reaches = bool(line) and not (events[line[-1]].get("previous_hash") or "")
    forks = {p: kids for p, kids in children.items() if len(kids) >= 2}
    same_second = sum(
        1 for p, kids in forks.items()
        if p in index and any(k.get("timestamp") == events[index[p]].get("timestamp") for k in kids)
    )
    return {
        "events": len(events),
        "head_hash": events[head].get("event_hash") if head is not None else None,
        "genesis_hash": events[line[-1]].get("event_hash") if reaches else None,
        "main_line_events": len(line),
        "main_line_reaches_genesis": reaches,
        "side_events": len(events) - len(line),
        "roots": sum(1 for e in events if not (e.get("previous_hash") or "")),
        "unlinked_events": sum(1 for e in events if e.get("previous_hash") and e["previous_hash"] not in index),
        "fork_pairs": len(forks),
        "fork_pairs_same_second_as_parent": same_second,
        "_main_line": {events[i].get("event_hash") for i in line},
    }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def load(source):
    if re.match(r"https?://", source):
        req = urllib.request.Request(source, headers={"User-Agent": "verify-ambassador/1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(MAX_BYTES + 1)
    else:
        with open(source, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file is larger than %d MB" % (MAX_BYTES // 1024 // 1024))
    chain = json.loads(raw.decode("utf-8"))
    if not isinstance(chain, dict) or not isinstance(chain.get("events"), list):
        raise ValueError("not a chain snapshot (no events list)")
    return chain


def check_identity(chain, expect_agent):
    out = {"agent_id": chain.get("agent_id"), "public_key_ok": False, "agent_id_matches_key": False,
           "expected_agent_ok": None}
    pub = None
    try:
        pub = base64.b64decode(chain.get("public_key") or "", validate=True)
        out["public_key_ok"] = len(pub) == 32
    except Exception:
        pass
    if out["public_key_ok"]:
        out["agent_id_matches_key"] = chain.get("agent_id") == "pq1_" + hashlib.sha256(pub).hexdigest()[:32]
    if expect_agent is not None:
        out["expected_agent_ok"] = chain.get("agent_id") == expect_agent
    return out, (pub if out["public_key_ok"] else None)


def export_hash_ok(chain):
    digest = hashlib.sha256(
        json.dumps(chain["events"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return digest == chain.get("export_hash")


def check_event(row, chain_agent, pub, verify):
    """Problems found in one event that carries its signed body, and whether its signature verified."""
    problems = []
    try:
        body = json.loads(row["event_json"])
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        message = canonical(unsigned)
    except Exception as exc:
        return ["body cannot be read: %s" % str(exc)[:80]], None, None
    if body.get("agent_id") != chain_agent:
        problems.append("agent_id differs from the chain's")
    if hashlib.sha256(message).hexdigest() != row.get("event_hash"):
        problems.append("event_hash does not match the body")
    if (body.get("previous_hash") or "") != (row.get("previous_hash") or ""):
        problems.append("previous_hash differs from the body")
    if body.get("signature") != row.get("signature"):
        problems.append("signature differs from the body")
    if body.get("timestamp") != row.get("timestamp"):
        problems.append("timestamp differs from the body")
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    if payload.get("event_type", "ambassador_interaction") != row.get("event_type"):
        problems.append("event_type differs from the body")
    sig_ok = None
    if verify is not None and pub is not None:
        try:
            sig_ok = bool(verify(pub, message, base64.b64decode(body.get("signature") or "", validate=True)))
        except Exception:
            sig_ok = False
        if not sig_ok:
            problems.append("signature does not verify")
    return problems, sig_ok, body


def check_bodies(chain, pub, verify):
    rows = chain["events"]
    out = {"with_body": 0, "without_body": 0, "signatures_verified": 0, "failed": []}
    bodies = {}
    for row in rows:
        if not row.get("event_json"):
            out["without_body"] += 1
            continue
        out["with_body"] += 1
        problems, sig_ok, body = check_event(row, chain.get("agent_id"), pub, verify)
        if sig_ok:
            out["signatures_verified"] += 1
        if problems:
            out["failed"].append({"event_hash": row.get("event_hash"), "problems": problems})
        elif body is not None:
            bodies[row["event_hash"]] = body
    return out, bodies


def comment_check(text, chain, bodies, structure, failed_hashes):
    m = SUFFIX.search(text)
    if not m:
        return {"found": False, "error": "the text does not end with a [sha256:<12 hex>] suffix"}
    full = hashlib.sha256(text[:m.start()].strip().encode("utf-8")).hexdigest()
    if full[:12] != m.group(1):
        return {"found": False, "suffix": m.group(1), "text_hash": full,
                "error": "the text does not match its own suffix (it was changed, or the suffix is not for this text)"}
    hits = [h for h, b in bodies.items() if (b.get("payload") or {}).get("content_hash") == full]
    out = {"suffix": m.group(1), "text_hash": full, "found": bool(hits), "events": []}
    by_hash = {e.get("event_hash"): e for e in chain["events"]}
    ordered = sorted(chain["events"], key=lambda e: e.get("timestamp") or 0)
    for h in hits:
        later = sum(1 for e in ordered if (e.get("timestamp") or 0) > (by_hash[h].get("timestamp") or 0))
        out["events"].append({
            "event_hash": h, "timestamp": by_hash[h].get("timestamp"),
            "on_main_line": h in structure["_main_line"], "events_stamped_after": later,
            "verified": h not in failed_hashes,
        })
    if not hits:
        out["error"] = ("no event in this snapshot carries this text hash: the comment is newer than the "
                        "snapshot, or older than the date events began to keep their signed body")
    return out


def run(chain, comment=None, predecessor=None, expect_agent=None):
    name, verify = ed25519_backend()
    identity, pub = check_identity(chain, expect_agent)
    structure = analyze(chain["events"])
    bodies_report, bodies = check_bodies(chain, pub, verify)
    failed = {f["event_hash"] for f in bodies_report["failed"]}
    report = {
        "agent_id": chain.get("agent_id"), "exported_at": chain.get("exported_at"),
        "events": len(chain["events"]), "identity": identity, "export_hash_ok": export_hash_ok(chain),
        "structure": {k: v for k, v in structure.items() if not k.startswith("_")},
        "bodies": bodies_report, "signature_backend": name,
        "statements": [], "comment": None, "predecessor": None,
    }
    for h, b in bodies.items():
        payload = b.get("payload") or {}
        if payload.get("event_type") == "chain_continuity_statement":
            report["statements"].append({"event_hash": h, "timestamp": b.get("timestamp"), "facts": payload,
                                         "verified": h not in failed})
    if comment is not None:
        report["comment"] = comment_check(comment, chain, bodies, structure, failed)
    if predecessor is not None:
        pstruct = analyze(predecessor["events"])
        report["predecessor"] = {
            "same_agent": predecessor.get("agent_id") == chain.get("agent_id")
            and predecessor.get("public_key") == chain.get("public_key"),
            "head_hash": pstruct["head_hash"], "events": len(predecessor["events"]),
            "declared_by_statement": [
                s["event_hash"] for s in report["statements"]
                if s["facts"].get("predecessor_head_hash") == pstruct["head_hash"]
                and s["facts"].get("predecessor_events") == len(predecessor["events"])
            ],
        }
    problems = []
    if not identity["public_key_ok"] or not identity["agent_id_matches_key"]:
        problems.append("agent id is not the hash of the public key")
    if identity["expected_agent_ok"] is False:
        problems.append("agent id is not the one you expected")
    if not report["export_hash_ok"]:
        problems.append("export_hash does not match the events")
    if structure["events"] == 0:
        problems.append("the snapshot holds no events")
    if structure["events"] and (structure["roots"] != 1 or structure["unlinked_events"] or not structure["main_line_reaches_genesis"]):
        problems.append("the events do not form one chain (first events: %d, unlinked: %d)"
                        % (structure["roots"], structure["unlinked_events"]))
    if bodies_report["failed"]:
        problems.append("%d event(s) failed their checks" % len(bodies_report["failed"]))
    if report["comment"] is not None and (not report["comment"]["found"] or not all(
            ev["verified"] and ev["on_main_line"] for ev in report["comment"]["events"])):
        problems.append("the comment could not be matched to a verified event on the chain")
    if report["predecessor"] is not None and not (report["predecessor"]["same_agent"]
                                                  and report["predecessor"]["declared_by_statement"]):
        problems.append("the predecessor file is not the one a signed statement declares")
    report["problems"] = problems
    notes = []
    if verify is None and bodies_report["with_body"]:
        notes.append("signatures were not checked: no Ed25519 library is installed (pip install cryptography)")
    if not bodies_report["with_body"]:
        notes.append("no event in this snapshot carries its signed body, so only identity, hash and links were checked")
    report["notes"] = notes
    if problems:
        report["result"], report["exit"] = "FAIL", 1
    elif notes:
        report["result"], report["exit"] = "PARTIAL", 3
    else:
        report["result"], report["exit"] = "PASS", 0
    return report


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render(r):
    s, b, i = r["structure"], r["bodies"], r["identity"]
    lines = [
        "Agent       : %s" % r["agent_id"],
        "  identity  : agent id %s the SHA-256 of the public key" % ("is" if i["agent_id_matches_key"] else "is NOT"),
    ]
    if i["expected_agent_ok"] is not None:
        lines.append("  expected  : %s" % ("matches what you gave" if i["expected_agent_ok"] else "DOES NOT MATCH what you gave"))
    lines += [
        "Snapshot    : exported %s, %d events, export_hash %s" % (r["exported_at"], r["events"], "ok" if r["export_hash_ok"] else "WRONG"),
        "Structure   : main line %d events (first %s, head %s)" % (
            s["main_line_events"], (s["genesis_hash"] or "?")[:12], (s["head_hash"] or "?")[:12]),
        "              %d side events, %d fork pairs (%d where the parent shares its second with a child: "
        "the old head lookup, see VERIFY_AMBASSADOR.md)" % (s["side_events"], s["fork_pairs"], s["fork_pairs_same_second_as_parent"]),
        "Events      : %d with their signed body checked, %d without (linked into the chain, but before the "
        "body was kept: their signatures cannot be re-checked)" % (b["with_body"], b["without_body"]),
        "Signatures  : %s" % (
            "%d verified (%s), %d event(s) failed" % (b["signatures_verified"], r["signature_backend"], len(b["failed"]))
            if r["signature_backend"] else "NOT CHECKED: install cryptography or pynacl (pip install cryptography)"),
    ]
    for f in b["failed"][:10]:
        lines.append("  FAILED    : %s... %s" % (f["event_hash"][:12], "; ".join(f["problems"])))
    for st in r["statements"]:
        facts = st["facts"]
        lines.append("Statement   : signed event %s... at %s%s: %s events, head %s..., registry had %s events"
                     % (st["event_hash"][:12], st["timestamp"], "" if st["verified"] else " (FAILED)", facts.get("chain_events"),
                        (facts.get("chain_head_hash") or "")[:12], facts.get("published_events")))
        if facts.get("predecessor_head_hash"):
            lines.append("              names a previous chain: head %s... (%s events, last snapshot %s)"
                         % (facts["predecessor_head_hash"][:12], facts.get("predecessor_events"), facts.get("predecessor_last_snapshot")))
    c = r["comment"]
    if c is not None:
        if c["found"]:
            for ev in c["events"]:
                lines.append("Comment     : MATCH, signed event %s... stamped at %s, %s, %s, %d event(s) stamped after it"
                             % (ev["event_hash"][:12], ev["timestamp"], "signature and hash verified" if ev["verified"] else "FAILED CHECKS",
                                "on the main line" if ev["on_main_line"] else "NOT on the main line", ev["events_stamped_after"]))
        else:
            lines.append("Comment     : NOT MATCHED - %s" % c.get("error"))
    p = r["predecessor"]
    if p is not None:
        lines.append("Predecessor : head %s... (%d events), %s, %s" % (
            (p["head_hash"] or "?")[:12], p["events"], "same key" if p["same_agent"] else "DIFFERENT KEY",
            "declared by a signed statement" if p["declared_by_statement"] else "not declared by any signed statement"))
    for problem in r["problems"]:
        lines.append("PROBLEM     : %s" % problem)
    for note in r["notes"]:
        lines.append("NOTE        : %s" % note)
    lines.append("RESULT: %s" % r["result"])
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify the PiQrypt ambassador chain from a published snapshot.")
    ap.add_argument("--chain", default=DEFAULT_URL, help="snapshot file or URL (default: the registry's latest.pqz)")
    ap.add_argument("--comment", help="text of a Moltbook comment, ending with its [sha256:<12 hex>] suffix")
    ap.add_argument("--comment-file", help="file holding that text (UTF-8)")
    ap.add_argument("--expect-agent", help="agent id you obtained from another channel (for example the profile)")
    ap.add_argument("--predecessor", help="an older snapshot, to check against the chain a statement says came before")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args(argv)
    try:
        chain = load(args.chain)
        predecessor = load(args.predecessor) if args.predecessor else None
        comment = args.comment
        if args.comment_file:
            with open(args.comment_file, "r", encoding="utf-8") as fh:
                comment = fh.read()
    except Exception as exc:
        print("cannot read: %s" % exc, file=sys.stderr)
        return 2
    report = run(chain, comment, predecessor, args.expect_agent)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return report["exit"]


if __name__ == "__main__":
    sys.exit(main())
