"""Deterministic validation and conformance test suite for Agent Policy Cards."""
import copy, datetime as dt, json, re, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_FILE = HERE.parent / 'agent-policy-card-v0.1.json'
EXAMPLE_FILE = HERE.parent / 'examples' / 'personal-assistant-policy-card.json'


def validate_policy_card(card, now_iso=None):
    """Deterministic validator enforcing fail-closed bounds and schema rules."""
    errs = []
    if not isinstance(card, dict): return ["card must be a dictionary"]
    req = ["schema_version", "card_id", "issued_at", "expires_at", "principal", "runtime_bounds", "human_intervention", "revocation", "signatures"]
    for k in req:
        if k not in card: errs.append(f"missing required key: {k}")
    extra = set(card.keys()) - set(req)
    if extra: errs.append(f"unknown top-level keys: {sorted(extra)}")
    if errs: return errs

    if card["schema_version"] != "0.1.0": errs.append("schema_version must be '0.1.0'")
    cid = card.get("card_id")
    if not isinstance(cid, str) or not re.match(r"^card-[a-zA-Z0-9_-]+$", cid): errs.append("card_id must match pattern")

    try:
        issued = dt.datetime.fromisoformat(card["issued_at"].replace("Z", "+00:00"))
        expires = dt.datetime.fromisoformat(card["expires_at"].replace("Z", "+00:00"))
        if expires <= issued: errs.append("expires_at must be strictly after issued_at")
        if now_iso and dt.datetime.fromisoformat(now_iso.replace("Z", "+00:00")) >= expires: errs.append("policy card has expired")
    except (ValueError, AttributeError) as ex: errs.append(f"malformed ISO timestamp: {ex}")

    p = card.get("principal", {})
    if not isinstance(p, dict) or set(p.keys()) != {"agent_id", "principal_type", "owner_id"}:
        errs.append("principal missing required keys or contains extra keys")
    elif p.get("principal_type") not in ("person", "cooperative"): errs.append("principal_type must be 'person' or 'cooperative'")

    rb = card.get("runtime_bounds", {})
    if not isinstance(rb, dict) or set(rb.keys()) != {"network_egress", "compute_quota", "tools", "data_boundaries"}:
        errs.append("runtime_bounds missing required keys or contains extra keys")
    else:
        net = rb.get("network_egress", {})
        if not isinstance(net, dict) or set(net.keys()) != {"mode", "allowed_hosts"}:
            errs.append("network_egress missing required keys or contains extra keys")
        elif net.get("mode") not in ("isolated", "allowlist_only") or not isinstance(net.get("allowed_hosts"), list):
            errs.append("invalid network_egress specification")
        elif not all(isinstance(h, str) and h.strip() for h in net.get("allowed_hosts", [])):
            errs.append("allowed_hosts must contain non-empty strings")
        elif net.get("mode") == "allowlist_only" and len(net.get("allowed_hosts")) == 0:
            errs.append("allowed_hosts cannot be empty when mode is allowlist_only")

        cq = rb.get("compute_quota", {})
        if not isinstance(cq, dict) or set(cq.keys()) != {"max_steps", "max_tokens", "timeout_seconds"}:
            errs.append("compute_quota extra keys or missing keys")
        else:
            for k, (lo, hi) in [("max_steps", (1, 1000)), ("max_tokens", (1, 1000000)), ("timeout_seconds", (1, 86400))]:
                v = cq.get(k)
                if not isinstance(v, int) or isinstance(v, bool) or v < lo or v > hi: errs.append(f"compute_quota.{k} out of bounds")

        tools = rb.get("tools", {})
        if not isinstance(tools, dict) or set(tools.keys()) != {"permitted_tools", "forbidden_capabilities"}:
            errs.append("tools missing required keys or contains extra keys")
        else:
            pt, fc = tools.get("permitted_tools"), tools.get("forbidden_capabilities")
            if not isinstance(pt, list) or len(pt) == 0 or not all(isinstance(x, str) and x.strip() for x in pt):
                errs.append("permitted_tools must be a non-empty list of non-empty strings")
            if not isinstance(fc, list) or len(fc) == 0 or not all(isinstance(x, str) and x.strip() for x in fc):
                errs.append("forbidden_capabilities must be a non-empty list of non-empty strings")

        db = rb.get("data_boundaries", {})
        if not isinstance(db, dict) or set(db.keys()) != {"file_access_mode", "forbidden_paths"}:
            errs.append("data_boundaries missing required keys or contains extra keys")
        else:
            if db.get("file_access_mode") not in ("read_only", "isolated_workspace", "none"): errs.append("invalid file_access_mode")
            if not isinstance(db.get("forbidden_paths"), list): errs.append("forbidden_paths must be a list")
            else:
                for fp in db.get("forbidden_paths", []):
                    if not isinstance(fp, str) or ".." in fp or "./" in fp or "\\" in fp: errs.append(f"invalid forbidden_path: {fp}")

    hi = card.get("human_intervention", {})
    if not isinstance(hi, dict) or set(hi.keys()) != {"require_approval_actions", "financial_transaction_limit_cents"}:
        errs.append("human_intervention missing required keys or contains extra keys")
    else:
        if not isinstance(hi.get("require_approval_actions"), list): errs.append("require_approval_actions must be a list")
        fin = hi.get("financial_transaction_limit_cents")
        if not isinstance(fin, int) or isinstance(fin, bool) or fin < 0: errs.append("financial_transaction_limit_cents must be int >= 0")

    rev = card.get("revocation", {})
    if not isinstance(rev, dict) or not set(rev.keys()).issubset({"revocable", "is_revoked", "revoked_at"}) or not {"revocable", "is_revoked"}.issubset(set(rev.keys())):
        errs.append("revocation missing required keys or contains extra keys")
    else:
        if rev.get("revocable") is not True: errs.append("revocation.revocable must be true")
        if not isinstance(rev.get("is_revoked"), bool): errs.append("revocation.is_revoked must be a boolean")
        elif rev.get("is_revoked") is True: errs.append("card has been revoked")

    sigs = card.get("signatures", [])
    if not isinstance(sigs, list) or len(sigs) == 0: errs.append("signatures must be a non-empty array")
    else:
        for s in sigs:
            if not isinstance(s, dict) or set(s.keys()) != {"party", "key_id", "algorithm", "signature_hex"}:
                errs.append("signature missing required keys or contains extra keys")
            else:
                if s.get("party") not in ("principal", "agent") or not isinstance(s.get("key_id"), str): errs.append("invalid signature party or key_id")
                shex = s.get("signature_hex")
                if s.get("algorithm") not in ("ed25519", "ecdsa-p256") or not isinstance(shex, str) or not re.match(r"^[0-9a-fA-F]{128}$", shex):
                    errs.append("invalid signature algorithm or hex format")
    return errs


class TestPolicyCardSchema(unittest.TestCase):
    def setUp(self):
        with open(EXAMPLE_FILE, "r", encoding="utf-8") as f: self.example = json.load(f)

    def test_example_validates(self):
        self.assertEqual(validate_policy_card(self.example), [])

    def test_unknown_properties_fail_closed(self):
        for path, key in [([], "extra"), (["runtime_bounds", "compute_quota"], "unmetered"), (["human_intervention"], "override"), (["revocation"], "reopen")]:
            bad = copy.deepcopy(self.example); target = bad
            for p in path: target = target[p]
            target[key] = True
            self.assertTrue(any("extra keys" in e or "unknown top-level" in e for e in validate_policy_card(bad)))
        bad_sig = copy.deepcopy(self.example); bad_sig["signatures"][0]["unknown"] = 1
        self.assertTrue(any("signature missing" in e or "extra keys" in e for e in validate_policy_card(bad_sig)))

    def test_irrevocable_and_revoked_cards_fail(self):
        bad1 = copy.deepcopy(self.example); bad1["revocation"]["revocable"] = False
        self.assertTrue(any("revocable must be true" in e for e in validate_policy_card(bad1)))
        bad2 = copy.deepcopy(self.example); bad2["revocation"]["is_revoked"] = True
        self.assertTrue(any("revoked" in e for e in validate_policy_card(bad2)))

    def test_tool_allowlist_structure_and_types_fail_closed(self):
        bad1 = copy.deepcopy(self.example); bad1["runtime_bounds"]["tools"]["permitted_tools"] = []
        self.assertTrue(any("permitted_tools" in e for e in validate_policy_card(bad1)))
        bad2 = copy.deepcopy(self.example); bad2["runtime_bounds"]["tools"]["permitted_tools"] = "read_calendar"
        self.assertTrue(any("permitted_tools" in e for e in validate_policy_card(bad2)))
        bad3 = copy.deepcopy(self.example); bad3["runtime_bounds"]["tools"]["forbidden_capabilities"] = ["  ", 123]
        self.assertTrue(any("forbidden_capabilities" in e for e in validate_policy_card(bad3)))

    def test_numeric_bounds_fail_closed(self):
        bad1 = copy.deepcopy(self.example); bad1["runtime_bounds"]["compute_quota"]["max_steps"] = 0
        self.assertTrue(any("out of bounds" in e for e in validate_policy_card(bad1)))
        bad2 = copy.deepcopy(self.example); bad2["human_intervention"]["financial_transaction_limit_cents"] = -1
        self.assertTrue(any("financial_transaction_limit_cents" in e for e in validate_policy_card(bad2)))

    def test_expiry_and_window_validation(self):
        self.assertTrue(any("expired" in e for e in validate_policy_card(self.example, now_iso="2026-10-20T00:00:00Z")))
        bad = copy.deepcopy(self.example); bad["expires_at"] = "2026-10-09T00:00:00Z"
        self.assertTrue(any("expires_at must be strictly after" in e for e in validate_policy_card(bad)))

    def test_path_traversal_variants_fail(self):
        for bad_p in ["../secret", "./secret", r"C:\secret"]:
            bad = copy.deepcopy(self.example); bad["runtime_bounds"]["data_boundaries"]["forbidden_paths"] = [bad_p]
            self.assertTrue(any("invalid forbidden_path" in e for e in validate_policy_card(bad)))

    def test_empty_network_allowlist_fails_closed(self):
        bad = copy.deepcopy(self.example)
        bad["runtime_bounds"]["network_egress"]["mode"] = "allowlist_only"
        bad["runtime_bounds"]["network_egress"]["allowed_hosts"] = []
        self.assertTrue(any("allowed_hosts cannot be empty" in e for e in validate_policy_card(bad)))

    def test_revocation_boolean_type_fails_closed(self):
        for bad_val in ["true", 1, None]:
            bad = copy.deepcopy(self.example); bad["revocation"]["is_revoked"] = bad_val
            self.assertTrue(any("is_revoked must be a boolean" in e for e in validate_policy_card(bad)))

    def test_signature_and_identifier_types_fail_closed(self):
        bad_sig = copy.deepcopy(self.example); bad_sig["signatures"][0]["signature_hex"] = "short"
        self.assertTrue(any("invalid signature" in e for e in validate_policy_card(bad_sig)))
        bad_id = copy.deepcopy(self.example); bad_id["card_id"] = 12345
        self.assertTrue(any("card_id" in e for e in validate_policy_card(bad_id)))


if __name__ == '__main__':
    unittest.main()
