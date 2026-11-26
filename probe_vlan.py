"""Print actual Central troubleshooting output for one switch, locally only."""
import getpass
import json
import os

from central_tool import APIError, Central, EU_REGIONS, VLAN_FEATURE_COMMANDS, detect_region


def main():
    print("Read-only VLAN probe. Output can contain customer data. Review before sharing.")
    serial = input("Switch serial: ").strip()
    client_id = os.environ.get("CENTRAL_CLIENT_ID") or input("Central client ID: ").strip()
    client_secret = os.environ.get("CENTRAL_CLIENT_SECRET") or getpass.getpass("Central client secret: ")
    region = os.environ.get("CENTRAL_BASE_URL") or input("Regional API URL (blank = detect EU): ").strip()
    client = Central(region or EU_REGIONS[0], client_id=client_id, client_secret=client_secret)
    detect_region(client, region or None)
    commands = ["show vlan", *VLAN_FEATURE_COMMANDS.values(), "show dhcp-snooping"]
    for command in commands:
        print("\n=== " + command + " ===", flush=True)
        try:
            response = client.show_vlan_command(serial, command, diagnostic=True)
            print(json.dumps(response, indent=2, ensure_ascii=False), flush=True)
        except APIError as exc:
            print("HTTP error:", exc.status, flush=True)
        except (RuntimeError, OSError, ValueError):
            print("Read failed", flush=True)


if __name__ == "__main__":
    main()
