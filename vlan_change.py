"""Explicit laboratory VLAN transactions; no generic or automatic production writes.

Vendor contracts: POST/DELETE layer2-vlan/{vlan}; POST config-assignments;
DELETE config-assignments/{scope}/{function}/{type}/{instance}.
The planner requires exact captured bodies and preserves device effective state.
"""
import argparse
import copy
import getpass
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import quote

from central_tool import (ALPHA, VLAN, PERSONAS, EU_REGIONS, Central, canonical,
    detect_region, scan, vlan_map, profile_body, rows, device_identity,
    read_module_view, svi_vlan_id, probe_operational_vlans, parse_reference_ids,
    write_private)
from consolidation import scope_memberships

SIMPLE_FIELDS = {"vlan", "name", "description", "enable", "voice-enable",
                 "is-l3-vlan", "igmp", "mld", "dhcpv4-snooping", "dhcpv6-snooping"}
OBSERVED_FIELDS = ("name", "taggedPorts", "untaggedPorts", "voice", "ipv4", "status", "type")
ORDER = ("group", "site", "collection", "global")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def writable(body):
    """Only a small explicit VLAN schema; reject unknown fields rather than strip them."""
    require(isinstance(body, dict) and set(body) <= SIMPLE_FIELDS, "Unsupported VLAN body fields")
    require(type(body.get("vlan")) is int and 2 <= body["vlan"] <= 4094, "Default or invalid VLAN")
    require(body.get("is-l3-vlan", False) is False, "SVI-associated VLAN is protected")
    require(isinstance(body.get("name"), str) and 1 <= len(body["name"]) <= 32
            and body["name"] == body["name"].strip(), "Invalid or missing VLAN name")
    for key in ("enable", "voice-enable"):
        require(key not in body or type(body[key]) is bool, "Unqualified VLAN boolean")
    if "description" in body:
        require(isinstance(body["description"], str) and 1 <= len(body["description"]) <= 64,
                "Unqualified VLAN description")
    for key in ("igmp", "mld", "dhcpv4-snooping", "dhcpv6-snooping"):
        if key in body:
            value = body[key]
            allowed = {"snooping"} if key in ("igmp", "mld") else {"enable"}
            require(isinstance(value, dict) and bool(value) and set(value) <= allowed
                    and all(type(v) is bool for v in value.values()), "Unqualified nested VLAN settings")
    return {k: v for k, v in body.items() if k != "is-l3-vlan"}


def explicit_memberships(scopes):
    membership = scope_memberships(scopes)
    by_id = {s["id"]: s for s in scopes}
    def optional_absence(metadata, key, kind):
        return (not any(s["kind"] == kind for s in scopes)
                or key in metadata and metadata[key] in (None, "", 0, "0"))
    for sid, value in membership.items():
        device = by_id[sid].get("metadata") or {}
        site = by_id.get(value["site"], {}).get("metadata") or {}
        value["complete"] = bool(value["global"] and value["site"]
            and (value["group"] or optional_absence(device, "deviceGroupId", "group"))
            and (value["collection"] or optional_absence(site, "collectionId", "collection")))
    return membership


def assignment_tuple(row):
    keys = ("scope-id", "device-function", "profile-type", "profile-instance")
    require(all(type(row.get(k)) in (int, str) and str(row[k]) for k in keys),
            "Unqualified assignment record")
    return [str(row[k]) for k in keys]


def capture(client, persona, vid, sources):
    require(persona in PERSONAS and vid.isdigit() and 2 <= int(vid) <= 4094
            and all(isinstance(s, str) and s.isdigit() for s in sources), "Invalid scope or VLAN selectors")
    snapshot = scan(client, persona)
    scopes = snapshot["scopes"]
    membership = explicit_memberships(scopes)
    state = {"region": snapshot["region"], "persona": persona, "vlan": vid,
             "scope_identity": {}, "memberships": membership, "kinds": {},
             "local": {}, "effective": {}, "annotations": {},
             "library": {k: profile_body(v) for k, v in vlan_map(snapshot["library"]).items()},
             "assignments": sorted(assignment_tuple(r) for r in rows(snapshot["assignments_raw"], ("config-assignment",))),
             "operational": {}, "svis": {}}
    require(len({tuple(a) for a in state["assignments"]}) == len(state["assignments"]), "Duplicate assignment records")
    for scope in scopes:
        sid, kind = scope["id"], scope["kind"]
        require(scope.get("local_response_validation", "not_needed") in
                ("not_needed", "consistent_with_effective_annotations", "no_effective_profiles"),
                "Unqualified committed local response")
        state["kinds"][sid] = kind
        metadata = scope.get("metadata") or {}
        state["scope_identity"][sid] = {
            "entity": metadata.get("id"), "kind": kind,
            **({k: metadata.get(k) for k in ("serialNumber", "serial", "stackId", "conductorSerialNumber")}
               if kind == "device" else {})}
        if kind == "device":
            require(any(state["scope_identity"][sid].get(k) for k in ("serialNumber", "serial", "stackId", "conductorSerialNumber")),
                    "Device identity evidence missing")
        state["local"][sid] = {k: profile_body(v) for k, v in vlan_map(scope["local"]).items()}
        state["effective"][sid] = {k: profile_body(v) for k, v in vlan_map(scope["effective"]).items()}
        annotated = vlan_map(scope["annotated"])
        require(canonical({k: profile_body(v) for k, v in annotated.items()}) == canonical(state["effective"][sid]),
                "Annotated and effective VLAN bodies disagree")
        state["annotations"][sid] = {k: v.get("@", {}) for k, v in annotated.items()}
        if sid not in sources:
            continue
        require(kind == "device", "Only device sources are supported")
        params = {"view-type": "LOCAL", "scope-id": sid, "device-function": persona,
                  "effective": "true", "detailed": "true"}
        svi = read_module_view(client, "vlan-interfaces", "id", params)
        require(svi["status"] == "list_parsed", "SVI evidence unavailable")
        state["svis"][sid] = sorted(svi_vlan_id(v) for v in svi["profiles"].values())
        evidence = probe_operational_vlans(client, metadata)
        require(evidence["status"] == "response_received", "Operational VLAN evidence unavailable")
        payload = evidence["payload"]
        lists = [v for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
        require(len(lists) == 1 and len(lists[0]) < 1000, "Operational VLAN view incomplete")
        records = [r for r in lists[0] if isinstance(r, dict) and parse_reference_ids(r.get("id")) == {vid}]
        require(len(records) == 1 and all(k in records[0] for k in OBSERVED_FIELDS),
                "Required operational VLAN fields unavailable")
        state["operational"][sid] = {k: records[0][k] for k in OBSERVED_FIELDS}
    require(set(sources) == set(state["operational"]), "Source device coverage incomplete")
    return state


def direct_assignment(state, sid, vid):
    return [sid, state["persona"], "layer2-vlan", vid]


def exact(left, right):
    return canonical(left) == canonical(right)


def direct_local(state, sid, vid, body):
    ann = state["annotations"][sid].get(vid, {})
    return (exact(state["local"][sid].get(vid), body) and exact(state["effective"][sid].get(vid), body)
            and ann.get("aruba-annotation:inherited") is False
            and ann.get("aruba-annotation:object_type") == "LOCAL"
            and ann.get("aruba-annotation:is_default") is False)


def inherited_reference(state, sid, vid, body, skip=None):
    """Require every present applicable ancestor body to match exactly.

    This is intentionally stricter than nearest-scope precedence. A direct
    ancestor must be observed, with a confirmed source or assignment.
    """
    membership = state["memberships"][sid]
    require(membership["complete"], "Unresolved source membership")
    found = False
    for kind in ORDER:
        ancestor = membership[kind]
        if not ancestor or ancestor == skip:
            continue
        effective = state["effective"][ancestor].get(vid)
        if effective is None:
            continue
        require(exact(effective, body), "Applicable higher scope contains a different VLAN body")
        ann = state["annotations"][ancestor].get(vid, {})
        if direct_local(state, ancestor, vid, body):
            found = True
        elif (direct_assignment(state, ancestor, vid) in state["assignments"]
              and ann.get("aruba-annotation:object_type") == "SHARED"
              and ann.get("aruba-annotation:inherited") is False
              and ann.get("aruba-annotation:is_default") is False
              and exact(state["library"].get(vid), body)):
            found = True
    return found


def prepare(state, mode, sources, target=None):
    require(mode in ("remove", "promote", "library"), "Unsupported VLAN workflow")
    sources = sorted(set(sources))
    require(bool(sources) and state["persona"] in PERSONAS, "Select source devices and switch function")
    vid = state["vlan"]
    require(vid.isdigit() and 2 <= int(vid) <= 4094, "Invalid or default VLAN")
    require(all(state["kinds"].get(sid) == "device" for sid in sources), "Source is not a captured device")
    body = state["local"][sources[0]].get(vid)
    writable(body)
    require(body["vlan"] == int(vid), "VLAN body identity mismatch")
    for sid in sources:
        require(direct_local(state, sid, vid, body), "Source local/effective body or annotation mismatch")
        require(direct_assignment(state, sid, vid) not in state["assignments"], "Source has direct Library assignment")
        require(state["memberships"][sid]["complete"], "Source membership not established")
        require(sid in state["svis"] and vid not in state["svis"][sid], "SVI dependency cannot be excluded")
        require(sid in state["operational"], "Missing operational baseline")
    ops = []
    if mode == "remove":
        require(target is None, "Remove workflow does not take a destination")
        for sid in sources:
            require(inherited_reference(state, sid, vid, body), "Matching inherited source not established")
    else:
        require(len(sources) >= 2, "Promotion requires repeated device-local profiles")
        kind = state["kinds"].get(target)
        require(kind in ("site", "group", "collection") or mode == "library" and kind == "global",
                "Unsupported destination scope")
        require(all(m["complete"] for m in state["memberships"].values()), "Destination membership incomplete")
        recipients = {sid for sid, m in state["memberships"].items() if m[kind] == target}
        require(recipients == set(sources), "Destination affects additional or missing devices")
        # Other applicable parent profiles must not conflict with the local bodies.
        for sid in sources:
            inherited_reference(state, sid, vid, body, skip=target)
        current = state["effective"][target].get(vid)
        require(current is None or exact(current, body), "Destination effective VLAN conflicts")
        if mode == "promote":
            require(direct_assignment(state, target, vid) not in state["assignments"], "Destination has direct Library assignment")
            if not direct_local(state, target, vid, body):
                require(current is None and vid not in state["local"][target], "Destination is not proven empty")
                ops.append({"kind": "create_local", "scope": target, "body": body})
        else:
            require(vid not in state["local"][target], "Destination already contains a local VLAN")
            existing = state["library"].get(vid)
            require(existing is None or exact(existing, body), "Existing Library VLAN differs")
            if existing is None:
                ops.append({"kind": "create_shared", "body": body})
            if direct_assignment(state, target, vid) not in state["assignments"]:
                require(current is None, "Destination already inherits a VLAN; review assignment precedence manually")
                ops.append({"kind": "assign", "scope": target})
            else:
                require(exact(existing, body) and exact(current, body), "Existing Library assignment is not confirmed")
    ops += [{"kind": "delete_local", "scope": sid, "body": body} for sid in sources]
    return {"schema": 1, "kind": "lab_vlan_plan", "mode": mode, "sources": sources,
            "target": target, "region": state["region"], "persona": state["persona"],
            "vlan": vid, "baseline": state, "operations": ops, "production_qualified": False}


def digest(plan):
    return hashlib.sha256(canonical(plan).encode()).hexdigest()


def direct_state(state):
    return {k: state[k] for k in ("region", "persona", "vlan", "scope_identity", "memberships",
                                  "kinds", "local", "library", "assignments")}


def device_state(state):
    return {"effective": {sid: state["effective"][sid] for sid in state["memberships"]},
            "operational": state["operational"], "svis": state["svis"]}


def transition(state, op):
    expected = copy.deepcopy(state)
    kind, sid, vid = op["kind"], op.get("scope"), state["vlan"]
    if kind == "create_local":
        expected["local"][sid][vid] = op["body"]
    elif kind == "delete_local":
        del expected["local"][sid][vid]
    elif kind == "create_shared":
        expected["library"][vid] = op["body"]
    elif kind == "delete_shared":
        del expected["library"][vid]
    elif kind == "assign":
        expected["assignments"].append(direct_assignment(state, sid, vid))
        expected["assignments"].sort()
    elif kind == "unassign":
        expected["assignments"].remove(direct_assignment(state, sid, vid))
    else:
        raise ValueError("Unknown operation")
    return expected


def inverse(op):
    return {**op, "kind": {"create_local": "delete_local", "delete_local": "create_local",
                          "create_shared": "delete_shared", "assign": "unassign"}[op["kind"]]}


def perform(client, persona, vid, op):
    kind, sid = op["kind"], op.get("scope")
    require(persona in PERSONAS and vid.isdigit() and 2 <= int(vid) <= 4094, "Invalid write selectors")
    if sid is not None:
        require(isinstance(sid, str) and sid.isdigit(), "Invalid scope selector")
    path = VLAN + "/" + quote(vid, safe="")
    if kind in ("create_local", "delete_local"):
        params = {"object-type": "LOCAL", "scope-id": sid, "device-function": persona}
        client.change("POST" if kind == "create_local" else "DELETE", path, params,
                      writable(op["body"]) if kind == "create_local" else None)
    elif kind in ("create_shared", "delete_shared"):
        client.change("POST" if kind == "create_shared" else "DELETE", path, {"object-type": "SHARED"},
                      writable(op["body"]) if kind == "create_shared" else None)
    elif kind == "assign":
        client.change("POST", ALPHA + "/config-assignments", {}, {"config-assignment": [{
            "scope-id": sid, "device-function": persona, "profile-type": "layer2-vlan", "profile-instance": vid}]})
    elif kind == "unassign":
        client.change("DELETE", ALPHA + "/config-assignments/" + "/".join(
            quote(v, safe="") for v in (sid, persona, "layer2-vlan", vid)), {}, None)
    else:
        raise ValueError("Unsupported operation")


class Journal:
    """Exclusive append-only private journal, flushed before and after every mutation."""
    def __init__(self, path):
        self.file = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.file.close()

    def record(self, status, **data):
        self.file.write(canonical({"status": status, **data}) + "\n")
        self.file.flush()
        os.fsync(self.file.fileno())


def execute(client, plan, journal, *, reader=capture, attempts=3, pause=time.sleep):
    """Freshly reconstruct plan, verify after each step and compensate only known writes.

    Unknown outcome, external drift, or missing evidence stops further changes.
    A successful check covers observed Central config/monitoring, not traffic.
    """
    persona, vid, sources = plan["persona"], plan["vlan"], plan["sources"]
    def read():
        return reader(client, persona, vid, sources)
    baseline = read()
    require(canonical(prepare(baseline, plan["mode"], sources, plan["target"])) == canonical(plan),
            "Plan is stale or differs from freshly reconstructed plan")
    expected = baseline
    applied = []
    journal.record("prepared", plan=plan)
    def confirm(expected_state, preserve_devices=True, predicate=None):
        current = None
        for i in range(attempts):
            current = read()
            if exact(direct_state(current), direct_state(expected_state)):
                if (not preserve_devices or exact(device_state(current), device_state(baseline))) and (predicate is None or predicate(current)):
                    return current, True
            if i + 1 < attempts:
                pause(2)
        return current, False
    try:
        for op in plan["operations"]:
            current = read()
            require(exact(direct_state(current), direct_state(expected))
                    and exact(device_state(current), device_state(baseline)), "Drift before mutation")
            if op["kind"] == "delete_local":
                require(direct_local(current, op["scope"], vid, op["body"]),
                        "Source is no longer the expected direct local profile")
                require(inherited_reference(current, op["scope"], vid, op["body"]),
                        "Matching inherited source is not observed")
            after = transition(expected, op)
            journal.record("write_pending", operation=op)
            try:
                perform(client, persona, vid, op)
            except Exception:
                # A lost response may hide a committed operation. Do not retry
                # or attempt compensating changes against an uncertain state.
                journal.record("uncertain_write", operation=op)
                return "manual_recovery_required"
            journal.record("write_acknowledged", operation=op)
            applied.append(op)
            expected = after
            def postcondition(current):
                if op["kind"] == "delete_local":
                    ann = current["annotations"][op["scope"]].get(vid, {})
                    return ann.get("aruba-annotation:inherited") is True
                if op["kind"] == "create_local":
                    return direct_local(current, op["scope"], vid, op["body"])
                if op["kind"] == "assign":
                    ann = current["annotations"][op["scope"]].get(vid, {})
                    return (ann.get("aruba-annotation:object_type") == "SHARED"
                            and ann.get("aruba-annotation:inherited") is False
                            and exact(current["effective"][op["scope"]].get(vid), current["library"].get(vid)))
                return True
            current, ok = confirm(expected, predicate=postcondition)
            if not ok:
                raise RuntimeError("Post-write verification failed")
            journal.record("verified_step", operation=op)
        journal.record("verified_complete", observed=device_state(baseline))
        return "verified_complete"
    except Exception:
        journal.record("verification_failed")
        try:
            for op in reversed(applied):
                current = read()
                require(exact(direct_state(current), direct_state(expected)), "Unknown drift; cannot safely compensate")
                undo = inverse(op)
                after = transition(expected, undo)
                journal.record("rollback_pending", operation=undo)
                perform(client, persona, vid, undo)
                journal.record("rollback_acknowledged", operation=undo)
                current, ok = confirm(after, preserve_devices=False)
                require(ok, "Rollback operation not confirmed")
                expected = after
                journal.record("rollback_verified", operation=undo)
            current, ok = confirm(baseline, predicate=lambda s: all(direct_local(s, sid, vid, baseline["local"][sid][vid]) for sid in sources))
            require(ok, "Original observed state not restored")
            journal.record("restored")
            return "restored"
        except Exception:
            journal.record("manual_recovery_required")
            return "manual_recovery_required"


def main():
    parser = argparse.ArgumentParser(description="Laboratory-only VLAN change qualification; production use not qualified.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--mode", choices=("remove", "promote", "library"), required=True)
    p.add_argument("--persona", choices=sorted(PERSONAS), required=True)
    p.add_argument("--vlan", type=int, required=True)
    p.add_argument("--source", action="append", required=True)
    p.add_argument("--target")
    p.add_argument("--output", type=Path, required=True)
    a = sub.add_parser("apply")
    a.add_argument("plan", type=Path)
    a.add_argument("--approve", required=True, help="Exact SHA256 of reviewed plan")
    a.add_argument("--lab-only", action="store_true", required=True)
    a.add_argument("--journal", type=Path, required=True)
    for cmd in (p, a):
        cmd.add_argument("--region", choices=EU_REGIONS)
    args = parser.parse_args()
    try:
        if args.command == "apply":
            plan = json.loads(args.plan.read_text(encoding="utf-8"))
            require(plan.get("kind") == "lab_vlan_plan" and plan.get("production_qualified") is False,
                    "Invalid laboratory plan")
            require(digest(plan) == args.approve, "Approval digest mismatch")
            require(args.region is None or args.region == plan["region"], "Region mismatch")
            preferred = plan["region"]
            require(preferred in EU_REGIONS, "Invalid plan region")
            require(not args.journal.exists(), "Journal already exists")
        else:
            preferred = args.region
            require(not args.output.exists(), "Plan output already exists")
        client = Central(preferred or EU_REGIONS[0], os.getenv("CENTRAL_ACCESS_TOKEN"),
                         os.getenv("CENTRAL_CLIENT_ID") or (None if os.getenv("CENTRAL_ACCESS_TOKEN") else input("Client ID: ")),
                         os.getenv("CENTRAL_CLIENT_SECRET") or (None if os.getenv("CENTRAL_ACCESS_TOKEN") else getpass.getpass("Client secret: ")))
        try:
            detect_region(client, preferred)
            if args.command == "plan":
                plan = prepare(capture(client, args.persona, str(args.vlan), args.source),
                               args.mode, args.source, args.target)
                write_private(args.output, plan)
                print("Laboratory preview only; no writes. Approval SHA256:", digest(plan))
                return 0
            require(client.base == preferred, "Connected region differs from plan")
            with Journal(args.journal) as journal:
                result = execute(client, plan, journal)
            print("Laboratory transaction:", result)
            return 0 if result == "verified_complete" else 1
        finally:
            client.client_id = client.client_secret = client.token = None
    except (ValueError, KeyError, OSError, RuntimeError):
        print("Operation blocked or failed. Review private plan/journal and qualified API evidence.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
