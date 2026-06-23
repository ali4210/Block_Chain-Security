#!/usr/bin/env python3
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "defi-events.json"
OUTPUT_FILE = ROOT / "reports" / "defi" / "defi_alerts.json"

LARGE_TRANSFER_THRESHOLD = 100000
RAPID_WITHDRAWAL_WINDOW_SEC = 60
RAPID_WITHDRAWAL_MIN_COUNT = 3
LIQUIDITY_SPIKE_THRESHOLD = 100000
MULTI_HOP_WINDOW_SEC = 120
MULTI_HOP_MIN_COUNT = 3
EMERGENCY_ACTIONS = {"emergencyDrain", "pause", "rescueFunds"}
SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_events():
    with INPUT_FILE.open("r", encoding="utf-8") as f:
        events = json.load(f)
    for e in events:
        e["parsed_time"] = parse_ts(e["timestamp"])
    return sorted(events, key=lambda x: x["parsed_time"])


def make_alert(rule_id, severity, title, description, events, extra=None):
    extra = extra or {}
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "event_count": len(events),
        "tx_hashes": sorted({e["tx_hash"] for e in events}),
        "addresses": sorted({e["address"] for e in events}),
        "protocols": sorted({e["protocol"] for e in events}),
        "assets": sorted({e["asset"] for e in events}),
        "time_range": {
            "start": min(e["timestamp"] for e in events),
            "end": max(e["timestamp"] for e in events),
        },
        "events": [
            {
                "tx_hash": e["tx_hash"],
                "block_number": e["block_number"],
                "timestamp": e["timestamp"],
                "protocol": e["protocol"],
                "address": e["address"],
                "action": e["action"],
                "asset": e["asset"],
                "amount": e["amount"],
                "counterparty": e.get("counterparty"),
            }
            for e in events
        ],
        **extra,
    }


def detect_large_transfers(events):
    alerts = []
    for e in events:
        if e["amount"] >= LARGE_TRANSFER_THRESHOLD:
            alerts.append(make_alert(
                "large-transfer", "MEDIUM", "Large value movement detected",
                f"Transaction {e['tx_hash']} moved {e['amount']} {e['asset']}, exceeding the configured threshold of {LARGE_TRANSFER_THRESHOLD}.",
                [e], {"threshold": LARGE_TRANSFER_THRESHOLD}
            ))
    return alerts


def detect_rapid_withdrawals(events):
    alerts = []
    grouped = defaultdict(list)
    for e in events:
        if e["action"] == "withdraw":
            grouped[e["address"]].append(e)
    for address, items in grouped.items():
        items.sort(key=lambda x: x["parsed_time"])
        for i in range(len(items) - RAPID_WITHDRAWAL_MIN_COUNT + 1):
            window = items[i:i + RAPID_WITHDRAWAL_MIN_COUNT]
            delta = (window[-1]["parsed_time"] - window[0]["parsed_time"]).total_seconds()
            if delta <= RAPID_WITHDRAWAL_WINDOW_SEC:
                alerts.append(make_alert(
                    "rapid-withdrawals", "HIGH", "Rapid repeated withdrawals detected",
                    f"Address {address} executed {len(window)} withdrawals within {int(delta)} seconds.",
                    window, {"window_seconds": RAPID_WITHDRAWAL_WINDOW_SEC}
                ))
                break
    return alerts


def detect_flash_loan_pattern(events):
    alerts = []
    grouped = defaultdict(list)
    for e in events:
        grouped[e["tx_hash"]].append(e)
    for tx_hash, items in grouped.items():
        actions = [e["action"] for e in items]
        if "borrow" in actions and "swap" in actions and "repay" in actions:
            alerts.append(make_alert(
                "flash-loan-pattern", "HIGH", "Flash-loan-like transaction pattern detected",
                f"Transaction {tx_hash} contains borrow, swap, and repay actions consistent with a flash-loan-style sequence for address {items[0]['address']}.",
                items
            ))
    return alerts


def detect_liquidity_spikes(events):
    alerts = []
    grouped = defaultdict(list)
    for e in events:
        if e["action"].startswith("liquidity_"):
            grouped[(e["protocol"], e["asset"], e.get("counterparty"))].append(e)
    for _, items in grouped.items():
        items.sort(key=lambda x: x["parsed_time"])
        previous = None
        for current in items:
            if previous is not None:
                diff = current["amount"] - previous["amount"]
                if diff >= LIQUIDITY_SPIKE_THRESHOLD:
                    alerts.append(make_alert(
                        "liquidity-spike", "MEDIUM", "Liquidity spike detected",
                        f"Liquidity activity increased by {diff} {current['asset']} between consecutive events in {current['protocol']}.",
                        [previous, current], {"delta": diff, "threshold": LIQUIDITY_SPIKE_THRESHOLD}
                    ))
            previous = current
    return alerts


def detect_multi_hop_transfers(events):
    alerts = []
    transfers = [e for e in events if e["action"] == "transfer"]
    transfers.sort(key=lambda x: x["parsed_time"])
    for i in range(len(transfers) - MULTI_HOP_MIN_COUNT + 1):
        window = transfers[i:i + MULTI_HOP_MIN_COUNT]
        delta = (window[-1]["parsed_time"] - window[0]["parsed_time"]).total_seconds()
        if delta > MULTI_HOP_WINDOW_SEC:
            continue
        chained = True
        for j in range(len(window) - 1):
            if window[j]["counterparty"] != window[j + 1]["address"]:
                chained = False
                break
        if chained:
            alerts.append(make_alert(
                "multi-hop-transfer", "MEDIUM", "Rapid multi-hop transfer chain detected",
                f"Detected {len(window)} linked transfers across multiple addresses within {int(delta)} seconds.",
                window, {"window_seconds": MULTI_HOP_WINDOW_SEC}
            ))
            break
    return alerts


def detect_emergency_actions(events):
    alerts = []
    for e in events:
        if e["action"] in EMERGENCY_ACTIONS:
            alerts.append(make_alert(
                "emergency-function-use", "HIGH", "Emergency administrative action detected",
                f"Administrative action {e['action']} was executed by {e['address']} against {e.get('counterparty', 'unknown target')}.",
                [e]
            ))
    return alerts


def deduplicate_alerts(alerts):
    seen = set()
    unique = []
    for alert in alerts:
        key = (alert["rule_id"], tuple(alert["tx_hashes"]), tuple(alert["addresses"]))
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique


def main():
    events = load_events()
    alerts = []
    alerts.extend(detect_large_transfers(events))
    alerts.extend(detect_rapid_withdrawals(events))
    alerts.extend(detect_flash_loan_pattern(events))
    alerts.extend(detect_liquidity_spikes(events))
    alerts.extend(detect_multi_hop_transfers(events))
    alerts.extend(detect_emergency_actions(events))
    alerts = deduplicate_alerts(alerts)
    alerts.sort(key=lambda a: (-SEVERITY_ORDER[a["severity"]], a["rule_id"], a["time_range"]["start"]))

    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for alert in alerts:
        summary[alert["severity"]] += 1

    output = {
        "tool": "defi-detector",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_file": str(INPUT_FILE.relative_to(ROOT)),
        "rules": {
            "large_transfer_threshold": LARGE_TRANSFER_THRESHOLD,
            "rapid_withdrawal_window_sec": RAPID_WITHDRAWAL_WINDOW_SEC,
            "rapid_withdrawal_min_count": RAPID_WITHDRAWAL_MIN_COUNT,
            "liquidity_spike_threshold": LIQUIDITY_SPIKE_THRESHOLD,
            "multi_hop_window_sec": MULTI_HOP_WINDOW_SEC,
            "multi_hop_min_count": MULTI_HOP_MIN_COUNT,
            "emergency_actions": sorted(EMERGENCY_ACTIONS),
        },
        "summary": {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "severity_counts": summary,
        },
        "alerts": alerts,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output["summary"], indent=2))


if __name__ == "__main__":
    main()
