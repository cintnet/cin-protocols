#!/usr/bin/env python3
"""Fail-closed validator and verification engine for AgentBindingCredential v0.1.0.

Implements the reference credential checker required by articles/the-second-internet.md
and D-0385. Rejects unknown fields, expired leases, mismatched holders, and invalid lifecycles.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def parse_iso8601(s: str) -> datetime:
    """Parse strict ISO-8601 timestamp with timezone requirement."""
    if not isinstance(s, str):
        raise TypeError("timestamp must be string")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError("timezone_required")
    return dt


class AgentBindingCredentialChecker:
    """Deterministic, fail-closed validator for AgentBindingCredential documents."""

    def __init__(self, schema_path: Optional[str | Path] = None):
        if schema_path is None:
            schema_path = Path(__file__).resolve().parent / "agent-binding-credential-v0.1.json"
        self.schema_path = Path(schema_path)
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    def _validate_node(self, doc: Any, node: dict, path: str) -> tuple[bool, str | None]:
        """Recursive fail-closed type and structure validator."""
        expected_type = node.get("type")
        if expected_type == "object":
            if not isinstance(doc, dict):
                return False, f"{path}:must_be_object"
            required_fields = node.get("required", [])
            for rf in required_fields:
                if rf not in doc:
                    return False, f"{path}:missing_required_property:{rf}"
            props = node.get("properties", {})
            if not node.get("additionalProperties", True):
                extra = set(doc.keys()) - set(props.keys())
                if extra:
                    return False, f"{path}:extra_properties:{','.join(sorted(extra))}"
            for k, v in doc.items():
                if k not in props:
                    continue
                p_schema = props[k]
                sp = f"{path}.{k}" if path else k
                valid, err = self._validate_node(v, p_schema, sp)
                if not valid:
                    return False, err
            return True, None

        if isinstance(expected_type, list):
            # Union types such as ["string", "null"]
            matched = False
            for t in expected_type:
                if t == "string" and isinstance(doc, str):
                    matched = True
                    break
                if t == "null" and doc is None:
                    matched = True
                    break
                if t == "integer" and isinstance(doc, int) and not isinstance(doc, bool):
                    matched = True
                    break
            if not matched:
                return False, f"{path}:union_type_violation"
            # If matched as string and format is specified, validate string format
            if isinstance(doc, str) and "format" in node:
                fmt = node["format"]
                if fmt == "date-time":
                    try:
                        parse_iso8601(doc)
                    except Exception:
                        return False, f"{path}:invalid_date_time_format"
                elif fmt == "uri":
                    if not re.match(r"^https?://[^\s/$.?#].[^\s]*$", doc):
                        return False, f"{path}:invalid_uri_format"
            return True, None

        if expected_type == "string":
            if not isinstance(doc, str):
                return False, f"{path}:must_be_string"
            if "minLength" in node and len(doc) < node["minLength"]:
                return False, f"{path}:min_length_violation"
            if "maxLength" in node and len(doc) > node["maxLength"]:
                return False, f"{path}:max_length_violation"
            if "pattern" in node and not re.match(node["pattern"], doc):
                return False, f"{path}:pattern_mismatch:{doc}"
            if "enum" in node and doc not in node["enum"]:
                return False, f"{path}:enum_violation:{doc}"
            if "const" in node and doc != node["const"]:
                return False, f"{path}:const_mismatch:{doc}!={node['const']}"
            if "format" in node:
                fmt = node["format"]
                if fmt == "date-time":
                    try:
                        parse_iso8601(doc)
                    except Exception:
                        return False, f"{path}:invalid_date_time_format"
                elif fmt == "uri":
                    if not re.match(r"^https?://[^\s/$.?#].[^\s]*$", doc):
                        return False, f"{path}:invalid_uri_format"
            return True, None

        if expected_type == "integer":
            if not isinstance(doc, int) or isinstance(doc, bool):
                return False, f"{path}:must_be_integer"
            if "minimum" in node and doc < node["minimum"]:
                return False, f"{path}:minimum_violation"
            if "maximum" in node and doc > node["maximum"]:
                return False, f"{path}:maximum_violation"
            return True, None

        if expected_type == "boolean":
            if not isinstance(doc, bool):
                return False, f"{path}:must_be_boolean"
            if "const" in node and doc != node["const"]:
                return False, f"{path}:const_mismatch"
            return True, None

        if expected_type == "array":
            if not isinstance(doc, list):
                return False, f"{path}:must_be_array"
            if "minItems" in node and len(doc) < node["minItems"]:
                return False, f"{path}:min_items_violation"
            items_schema = node.get("items", {})
            for i, it in enumerate(doc):
                ip = f"{path}[{i}]"
                valid, err = self._validate_node(it, items_schema, ip)
                if not valid:
                    return False, err
            return True, None

        return True, None

    def check(
        self,
        credential: dict,
        as_of: Optional[datetime] = None,
        expected_holder_id: Optional[str] = None,
    ) -> tuple[bool, str | None]:
        """Validate an AgentBindingCredential document.

        Args:
            credential: The parsed JSON dictionary of the credential.
            as_of: Optional reference datetime. Defaults to datetime.now(timezone.utc)
                   so evaluation without an explicit clock checks whether the credential
                   is active right now.
            expected_holder_id: Optional holder ID presented by the agent to match against credential holder.

        Returns:
            (True, None) if valid and conforming.
            (False, error_description) on any schema or binding violation.
        """
        if not isinstance(credential, dict):
            return False, "root:must_be_object"

        # 1. Structural schema validation (rejects extra/unknown fields)
        valid, err = self._validate_node(credential, self.schema, "root")
        if not valid:
            return False, err

        # 2. Lifecycle timestamps
        try:
            issued_at = parse_iso8601(credential["issued_at"])
            expires_at = parse_iso8601(credential["expires_at"])
        except Exception as e:
            return False, f"invalid_lifecycle_timestamps:{e}"

        if expires_at <= issued_at:
            return False, "lifecycle_violation:expires_at_must_be_after_issued_at"

        ref_time = as_of if as_of is not None else datetime.now(timezone.utc)

        if ref_time < issued_at:
            return False, "credential_not_yet_valid:evaluation_time_before_issued_at"

        if ref_time >= expires_at:
            return False, "credential_expired:evaluation_time_past_credential_expires_at"

        # 3. Revocation status
        rev = credential.get("revocation", {})
        if rev.get("is_revoked") is True:
            return False, "credential_revoked:revocation_flag_is_true"

        # 4. Holder binding validation
        holder = credential.get("holder", {})
        binding_kind = holder.get("binding_kind")
        holder_id = holder.get("holder_id")

        if expected_holder_id and holder_id != expected_holder_id:
            return False, f"holder_mismatch:expected_{expected_holder_id}_got_{holder_id}"

        if binding_kind == "person":
            pref = holder.get("personhood_credential_ref")
            oref = holder.get("organisation_ref")
            if not pref:
                return False, "holder_binding_violation:person_binding_requires_personhood_credential_ref"
            if oref is not None:
                return False, "holder_binding_violation:person_binding_must_not_include_organisation_ref"
        elif binding_kind == "organisation":
            oref = holder.get("organisation_ref")
            pref = holder.get("personhood_credential_ref")
            if not oref:
                return False, "holder_binding_violation:organisation_binding_requires_organisation_ref"
            if pref is not None:
                return False, "holder_binding_violation:organisation_binding_must_not_include_personhood_credential_ref"
        else:
            return False, f"holder_binding_violation:unknown_binding_kind:{binding_kind}"

        # 5. Proof and issuer key binding
        issuer = credential.get("issuer", {})
        proof = credential.get("proof", {})
        issuer_vm = issuer.get("verification_method")
        proof_vm = proof.get("verification_method")
        if not proof_vm or proof_vm != issuer_vm:
            return False, f"proof_verification_method_mismatch:expected_{issuer_vm}_got_{proof_vm}"

        # 6. Permission leases validation
        permissions = credential.get("permissions", [])
        if not permissions:
            return False, "permissions_violation:permissions_list_must_not_be_empty"

        for idx, lease in enumerate(permissions):
            lid = lease.get("lease_id", f"idx_{idx}")
            if lease.get("is_revoked") is True:
                return False, f"lease_revoked:{lid}"
            try:
                g_at = parse_iso8601(lease["granted_at"])
                e_at = parse_iso8601(lease["expires_at"])
            except Exception as e:
                return False, f"lease_invalid_timestamps:{lid}:{e}"

            if e_at <= g_at:
                return False, f"lease_lifecycle_violation:{lid}:expires_at_must_be_after_granted_at"
            if g_at < issued_at:
                return False, f"lease_lifecycle_violation:{lid}:lease_cannot_predate_credential_issuance"
            if e_at > expires_at:
                return False, f"lease_lifecycle_violation:{lid}:lease_cannot_outlive_credential_expiry"
            if ref_time < g_at:
                return False, f"lease_not_yet_valid:{lid}:evaluation_time_before_granted_at"
            if ref_time >= e_at:
                return False, f"lease_expired:{lid}:lease_expires_at_past_evaluation_time"

        # 7. Compute budget bounds
        cb = credential.get("compute_budget", {})
        for field, min_val in [
            ("max_tokens_per_hour", 1000),
            ("max_parallel_threads", 1),
            ("daily_compute_units", 1),
            ("rate_limit_per_minute", 1),
        ]:
            val = cb.get(field)
            if not isinstance(val, int) or isinstance(val, bool) or val < min_val:
                return False, f"compute_budget_violation:{field}_must_be_integer_gte_{min_val}"

        return True, None


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python agent_binding_credential.py <credential.json> [holder_id]")
        return 1

    file_path = Path(sys.argv[1])
    if not file_path.is_file():
        print(f"File not found: {file_path}")
        return 1

    expected_holder = sys.argv[2] if len(sys.argv) > 2 else None
    with open(file_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    checker = AgentBindingCredentialChecker()
    valid, err = checker.check(doc, expected_holder_id=expected_holder)
    if valid:
        print("VERIFY: PASS (AgentBindingCredential conforms to schema and binding constraints)")
        return 0
    else:
        print(f"VERIFY: FAIL ({err})")
        return 2


if __name__ == "__main__":
    sys.exit(main())
