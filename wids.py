import time
import argparse
import json
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

try:
    from scapy.all import sniff, rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass
class Alert:
    type: str
    severity: str
    timestamp: float
    details: Dict[str, Any]


class AlertSink:
    def emit(self, alert: Alert) -> None:
        payload = {
            "type": alert.type,
            "severity": alert.severity,
            "ts": alert.timestamp,
            "details": alert.details,
        }
        print(json.dumps(payload, ensure_ascii=False))


def get_bssid(pkt) -> Optional[str]:
    if pkt.haslayer(Dot11):
        return pkt[Dot11].addr3
    return None


def get_source(pkt) -> Optional[str]:
    if pkt.haslayer(Dot11):
        return pkt[Dot11].addr2
    return None


def get_ssid(pkt) -> Optional[str]:
    if pkt.haslayer(Dot11Beacon):
        el = pkt[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == 0:
                try:
                    return el.info.decode(errors="ignore")
                except Exception:
                    return None
            el = el.payload.getlayer(Dot11Elt)
    return None


def get_channel(pkt) -> Optional[int]:
    if pkt.haslayer(Dot11Beacon):
        el = pkt[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == 3:
                if isinstance(el.info, bytes) and len(el.info) >= 1:
                    return int(el.info[0])
            el = el.payload.getlayer(Dot11Elt)
    return None


def get_crypto(pkt) -> str:
    if pkt.haslayer(Dot11Beacon):
        beacon = pkt[Dot11Beacon]
        cap = int(beacon.cap)
        privacy = bool(cap & 0x10)
        has_rsn = False
        el = pkt[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == 48:
                has_rsn = True
                break
            el = el.payload.getlayer(Dot11Elt)
        if has_rsn:
            return "WPA2/RSN"
        if privacy:
            return "WEP"
        return "OPEN"
    return "UNKNOWN"


class DeauthDetector:
    def __init__(self, window_seconds: int = 5, count_threshold: int = 30, per_target_threshold: int = 10) -> None:
        self.window_seconds = window_seconds
        self.count_threshold = count_threshold
        self.per_target_threshold = per_target_threshold
        self.global_counts: List[float] = []
        self.by_attacker: Dict[str, List[float]] = {}
        self.by_attacker_target: Dict[str, Dict[str, List[float]]] = {}

    def process(self, pkt) -> Optional[Alert]:
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas)):
            return None
        now = time.time()
        src = get_source(pkt) or "UNKNOWN"
        bssid = get_bssid(pkt) or "UNKNOWN"
        self._append_and_prune(self.global_counts, now)
        self.by_attacker.setdefault(src, [])
        self._append_and_prune(self.by_attacker[src], now)
        self.by_attacker_target.setdefault(src, {})
        self.by_attacker_target[src].setdefault(bssid, [])
        self._append_and_prune(self.by_attacker_target[src][bssid], now)
        g = len(self.global_counts)
        a = len(self.by_attacker[src])
        t = len(self.by_attacker_target[src][bssid])
        if g >= self.count_threshold or a >= self.count_threshold or t >= self.per_target_threshold:
            return Alert(
                type="deauth_attack",
                severity="high" if g >= self.count_threshold else "medium",
                timestamp=now,
                details={
                    "attacker": src,
                    "bssid": bssid,
                    "global_rate": g,
                    "attacker_rate": a,
                    "target_rate": t,
                    "window_seconds": self.window_seconds,
                },
            )
        return None

    def _append_and_prune(self, arr: List[float], now: float) -> None:
        arr.append(now)
        cutoff = now - self.window_seconds
        i = 0
        for ts in arr:
            if ts >= cutoff:
                break
            i += 1
        if i:
            del arr[:i]


class EvilTwinDetector:
    def __init__(self, allowed_bssid_per_ssid: int = 2) -> None:
        self.allowed_bssid_per_ssid = allowed_bssid_per_ssid
        self.ssids: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def process(self, pkt) -> Optional[Alert]:
        if not pkt.haslayer(Dot11Beacon):
            return None
        now = time.time()
        ssid = get_ssid(pkt)
        bssid = get_bssid(pkt) or "UNKNOWN"
        if not ssid:
            return None
        ch = get_channel(pkt)
        crypto = get_crypto(pkt)
        self.ssids.setdefault(ssid, {})
        self.ssids[ssid][bssid] = {"channel": ch, "crypto": crypto, "last_seen": now}
        entries = self.ssids[ssid]
        if len(entries) > self.allowed_bssid_per_ssid:
            return Alert(
                type="evil_twin_multiple_bssid",
                severity="medium",
                timestamp=now,
                details={
                    "ssid": ssid,
                    "count": len(entries),
                    "bssids": list(entries.keys()),
                },
            )
        cryptos = {v.get("crypto") for v in entries.values()}
        if len(cryptos) > 1:
            return Alert(
                type="evil_twin_crypto_mismatch",
                severity="high",
                timestamp=now,
                details={
                    "ssid": ssid,
                    "cryptos": list(cryptos),
                    "bssid_map": {k: v.get("crypto") for k, v in entries.items()},
                },
            )
        return None


class WIDS:
    def __init__(self, detectors: List[Any], sink: AlertSink) -> None:
        self.detectors = detectors
        self.sink = sink

    def handle_packet(self, pkt) -> None:
        for d in self.detectors:
            alert = d.process(pkt)
            if alert:
                self.sink.emit(alert)


def run_live(interface: str, wids: WIDS) -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for live capture")

    def cb(pkt):
        if pkt.haslayer(Dot11):
            wids.handle_packet(pkt)

    sniff(iface=interface, prn=cb, store=False)


def run_pcap(path: str, wids: WIDS) -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for pcap processing")
    pkts = rdpcap(path)
    for pkt in pkts:
        if pkt.haslayer(Dot11):
            wids.handle_packet(pkt)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--pcap", type=str, default=None)
    parser.add_argument("--deauth-window", type=int, default=5)
    parser.add_argument("--deauth-threshold", type=int, default=30)
    parser.add_argument("--per-target-threshold", type=int, default=10)
    parser.add_argument("--allowed-bssid-per-ssid", type=int, default=2)
    args = parser.parse_args()

    sink = AlertSink()
    detectors = [
        DeauthDetector(window_seconds=args.deauth_window, count_threshold=args.deauth_threshold, per_target_threshold=args.per_target_threshold),
        EvilTwinDetector(allowed_bssid_per_ssid=args.allowed_bssid_per_ssid),
    ]
    wids = WIDS(detectors, sink)

    if args.pcap:
        run_pcap(args.pcap, wids)
    elif args.interface:
        run_live(args.interface, wids)
    else:
        print(json.dumps({"error": "provide --interface for live or --pcap for offline"}))


if __name__ == "__main__":
    main()

