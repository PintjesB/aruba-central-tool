"""Report supported commands and parsed VLAN evidence for one switch."""
import getpass
import json
import os

from central_tool import APIError, Central, EU_REGIONS, VLAN_FEATURE_COMMANDS, detect_region, supported_show_commands, extract_command_output, parse_vlan_running_config, parse_show_vlan, parse_vlan_feature, VLAN_FEATURE_ALTERNATIVES, parse_multicast_interface_output, probe_operational_vlans


def main():
    print("Read-only VLAN probe. Review diagnostics before sharing.")
    serial = input("Switch serial: ").strip()
    client_id = os.environ.get("CENTRAL_CLIENT_ID") or input("Central client ID: ").strip()
    client_secret = os.environ.get("CENTRAL_CLIENT_SECRET") or getpass.getpass("Central client secret: ")
    region = os.environ.get("CENTRAL_BASE_URL") or input("Regional API URL (blank = detect EU): ").strip()
    client = Central(region or EU_REGIONS[0], client_id=client_id, client_secret=client_secret)
    detect_region(client, region or None)
    allowed = set()
    try:
        allowed = supported_show_commands(client.list_show_commands(serial))
        print("Supported show commands:", json.dumps(sorted(allowed)), flush=True)
    except (RuntimeError, OSError, ValueError):
        print("Command list unavailable", flush=True)
    ids = set()
    commands = ["show vlan", *VLAN_FEATURE_COMMANDS.values(), *VLAN_FEATURE_ALTERNATIVES.values()]
    for command in commands:
        if allowed and command not in allowed:
            print(command + ": not listed", flush=True)
            continue
        try:
            response = client.show_vlan_command(serial, command)
            result = {"status": response["status"]}
            if response["status"] == "completed":
                if command == "show vlan":
                    parsed = parse_show_vlan(response["result"])
                    ids = set(parsed.get("vlans", {}))
                    result = {"status": parsed["status"], "vlans": len(ids)}
                elif command in VLAN_FEATURE_ALTERNATIVES.values():
                    field = next(k for k, v in VLAN_FEATURE_ALTERNATIVES.items() if v == command)
                    values = parse_multicast_interface_output(extract_command_output(response["result"], command), field, ids)
                    result = {"status": ("observed" if set(values) == ids else "partial") if values else "schema_unresolved", "vlans": len(values)}
                else:
                    field = next(k for k, v in VLAN_FEATURE_COMMANDS.items() if v == command)
                    parsed = parse_vlan_feature(response["result"], field, ids)
                    result = {"status": parsed["status"], "vlans": len(parsed.get("vlans", {}))}
            print(command + ": " + json.dumps(result), flush=True)
        except APIError as exc:
            print(command + ": HTTP error " + str(exc.status), flush=True)
        except (RuntimeError, OSError, ValueError):
            print(command + ": read failed", flush=True)
    try:
        monitoring = probe_operational_vlans(client, {"serial": serial})
        payload = monitoring.get("payload", {})
        voice = {}
        for item in payload.get("vlans", []) if isinstance(payload, dict) else []:
            if isinstance(item, dict):
                value = item.get("voice")
                label = str(value).lower() if type(value) is bool or (isinstance(value, str) and value.lower() in ("enabled", "disabled")) else "unknown"
                voice[label] = voice.get(label, 0) + 1
        print("Monitoring voice states:", json.dumps({"status": monitoring["status"], "counts": voice}), flush=True)
    except (RuntimeError, OSError, ValueError):
        print("Monitoring voice states: read failed", flush=True)
    config_command = next((cmd for cmd in ("show running-config all", "show running-config") if cmd in allowed), None)
    if config_command:
        try:
            response = client.show_vlan_command(serial, config_command)
            parsed = parse_vlan_running_config(extract_command_output(response.get("result"), config_command), ids)
            counts = {field: sum(field in v for v in parsed.values()) for field in ("voice-enable", "igmp", "mld")}
            print(config_command + ": " + json.dumps({"status": response["status"], "explicit_fields": counts}), flush=True)
        except (RuntimeError, OSError, ValueError):
            print(config_command + ": read failed", flush=True)


if __name__ == "__main__":
    main()
