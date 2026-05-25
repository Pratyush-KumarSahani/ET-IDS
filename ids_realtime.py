from __future__ import annotations

import asyncio
import functools
import ipaddress
import logging
import subprocess
import statistics
import threading
from collections import deque, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ids_storage import IDSStorage


LOGGER = logging.getLogger(__name__)

ENCRYPTED_PORTS = {443, 465, 563, 853, 993, 995, 8443}

# Ports used by legitimate high-bandwidth P2P / game / VPN / media traffic
# that produce feature distributions identical to attack training data.
# Flows where src or dst port matches these are bypassed before ML inference.
TRUSTED_HIGH_BANDWIDTH_PORTS = {
    12743,                                          # BitTorrent (common local client port)
    6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,  # BitTorrent standard range
    51413,                                          # qBittorrent default
}

ROLLING_WINDOW_SIZE = 50
DEFAULT_LOG_LIMIT = 500
HIGH_PACKET_RATE_THRESHOLD = 1000.0

# FIX: Raised from 8→12 packets and 2.0→3.0s to prevent classification of
# half-assembled, statistically unstable flows.
MIN_FLOW_PACKETS_FOR_ML = 12
MIN_FLOW_DURATION_FOR_ML = 3.0

# FIX: Only re-classify a flow every N new packets to stop per-packet
# BENIGN↔MALICIOUS oscillation on the same flow.
FLOW_CLASSIFY_INTERVAL = 5

# FIX: Skip raw IP fragments with no src/dst port — they look identical to
# port-scanner training data and cause systematic "Other" false positives.
SKIP_PORTLESS_FRAGMENTS = True

# FIX: Binary confidence threshold raised from implicit 50% → 65%.
BINARY_MALICIOUS_THRESHOLD = 65.0

# FIX: Consensus vote — a flow must have MALICIOUS majority across last N
# predictions before it is confirmed as malicious.
FLOW_VOTE_WINDOW = 5
FLOW_MALICIOUS_RATIO = 0.6

# Keep friend's threshold (85) — more conservative than our 80
ML_ATTACK_ALERT_THRESHOLD = 85.0

BENIGN_LABELS = {"benign", "normal"}
# Friend's addition: ambiguous labels treated as warnings not alerts
AMBIGUOUS_ATTACK_LABELS = {"other", "unknown", "suspicious", "none"}
# Friend's addition: auto-block and recon warning keywords
BLOCK_IMMEDIATELY_KEYWORDS = {"ddos", "dos", "brute", "bruteforce", "brute force"}
RECON_WARNING_KEYWORDS = {"recon", "reconnaissance", "scan", "portscan", "port scan"}
RECON_WARNING_THRESHOLD = 3
CRITICAL_LABEL_KEYWORDS = {"ddos", "dos", "botnet", "infiltration", "ransomware"}
HIGH_LABEL_KEYWORDS = {"brute", "exploit", "web attack", "sql", "xss", "portscan", "scan"}
MEDIUM_LABEL_KEYWORDS = {"suspicious", "attack", "malware", "anomaly"}

# Stop-confirm constants
STOP_CONFIRM_TIMEOUT_S = 5.0
STOP_POLL_INTERVAL_S = 0.05


@dataclass(frozen=True)
class PacketLog:
    id: int
    timestamp: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    flow_id: str
    flow_packet_count: int
    flow_byte_count: int
    flow_duration: float
    length: int
    time_diff: float
    packet_rate: float
    avg_length: float
    encrypted_likely: bool
    prediction: str
    ml_confidence: float | None
    binary_label: str | None
    attack_label: str | None
    severity: str
    signature: str
    rule_id: str
    action: str
    reason: str
    response_note: str | None  # friend's addition


class BlockManager:
    def __init__(
        self,
        mode: str = "memory",
        blocked_ips: list[str] | None = None,
        on_block: Callable[[str, str], None] | None = None,
        on_unblock: Callable[[str], None] | None = None,
    ) -> None:
        self.mode = mode.strip().lower()
        self._blocked_ips: set[str] = set(blocked_ips or [])
        self._on_block = on_block
        self._on_unblock = on_unblock
        self._lock = threading.Lock()

    def list_blocked(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    # Friend's addition: switch between memory and windows_firewall modes at runtime
    def set_mode(self, mode: str) -> dict[str, str]:
        normalized_mode = mode.strip().lower()
        if normalized_mode not in {"memory", "windows_firewall"}:
            raise ValueError("Unsupported block mode. Use 'memory' or 'windows_firewall'.")

        with self._lock:
            previous_mode = self.mode
            blocked_ips = sorted(self._blocked_ips)
            self.mode = normalized_mode

        if previous_mode == normalized_mode:
            return {"mode": normalized_mode}

        if previous_mode == "windows_firewall":
            for blocked_ip in blocked_ips:
                self._remove_windows_firewall_block(blocked_ip)

        if normalized_mode == "windows_firewall":
            for blocked_ip in blocked_ips:
                self._apply_windows_firewall_block(blocked_ip)

        return {"mode": normalized_mode}

    def is_blocked(self, ip_address_value: str | None) -> bool:
        if not ip_address_value:
            return False
        with self._lock:
            return ip_address_value in self._blocked_ips

    def block(self, ip_address_value: str, reason: str = "Manual block from IDS log") -> dict[str, str]:
        normalized_ip = self._validate_ip(ip_address_value)
        with self._lock:
            self._blocked_ips.add(normalized_ip)

        if self.mode == "windows_firewall":
            self._apply_windows_firewall_block(normalized_ip)
            action = "firewall_blocked"
        else:
            action = "memory_blocked"

        if self._on_block is not None:
            self._on_block(normalized_ip, reason)

        LOGGER.warning("Blocked IP %s: %s", normalized_ip, reason)
        return {"ip": normalized_ip, "action": action, "reason": reason}

    def unblock(self, ip_address_value: str) -> dict[str, str]:
        normalized_ip = self._validate_ip(ip_address_value)
        with self._lock:
            self._blocked_ips.discard(normalized_ip)

        if self.mode == "windows_firewall":
            self._remove_windows_firewall_block(normalized_ip)
            action = "firewall_unblocked"
        else:
            action = "memory_unblocked"

        if self._on_unblock is not None:
            self._on_unblock(normalized_ip)

        LOGGER.info("Unblocked IP %s", normalized_ip)
        return {"ip": normalized_ip, "action": action}

    @staticmethod
    def _validate_ip(ip_address_value: str) -> str:
        try:
            return str(ipaddress.ip_address(ip_address_value))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip_address_value}") from exc

    # Friend's addition: blocks both inbound AND outbound
    @staticmethod
    def _apply_windows_firewall_block(ip_address_value: str) -> None:
        for direction in ("in", "out"):
            rule_name = BlockManager._firewall_rule_name(ip_address_value, direction)
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", f"dir={direction}", "action=block",
                 f"remoteip={ip_address_value}"],
                check=True, capture_output=True, text=True,
            )

    @staticmethod
    def _remove_windows_firewall_block(ip_address_value: str) -> None:
        for direction in ("in", "out"):
            rule_name = BlockManager._firewall_rule_name(ip_address_value, direction)
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                check=True, capture_output=True, text=True,
            )

    # Friend's addition
    @staticmethod
    def _firewall_rule_name(ip_address_value: str, direction: str) -> str:
        direction_label = "Inbound" if direction == "in" else "Outbound"
        return f"ET-IDS Block {ip_address_value} {direction_label}"


class RealtimeIDS:
    def __init__(
        self,
        *,
        detector: Any | None = None,
        block_manager: BlockManager | None = None,
        storage: IDSStorage | None = None,
        log_limit: int = DEFAULT_LOG_LIMIT,
    ) -> None:
        self.detector = detector
        self.block_manager = block_manager or BlockManager()
        self.storage = storage

        # Session-only log deque — cleared on every start_capture()
        # so WebSocket snapshot never shows old-run data.
        self.logs: deque[PacketLog] = deque(maxlen=log_limit)

        # Separate buffer for logs loaded from DB on startup (history).
        # Kept isolated so self.logs stays session-only.
        self._history_logs: deque[PacketLog] = deque(maxlen=log_limit)

        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._subscribers_lock = threading.Lock()
        self._recent_lengths: deque[int] = deque(maxlen=ROLLING_WINDOW_SIZE)
        self._recent_timestamps: deque[float] = deque(maxlen=ROLLING_WINDOW_SIZE)
        self._flows: dict[tuple[str | None, str | None, int | str | None], dict[str, Any]] = {}
        self._previous_timestamp: float | None = None
        self._packet_counter = 0

        # _session_counter resets to 0 on every start_capture() — used for
        # "packets this run" display, independent of DB-persisted IDs.
        self._session_counter: int = 0

        # FIX: threading.Event for atomic stop signalling (replaces plain bool)
        self._stop_event = threading.Event()

        self._sniffer: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._interface: str | None = None
        self._filter: str | None = None
        self._simulation_active = False
        self._simulation_thread: threading.Thread | None = None

        # Friend's additions
        self._warning_counts: dict[str, int] = {}
        self._capture_lock = threading.Lock()

        # FIX: per-flow consensus vote buffer
        self._flow_votes: dict[str, deque[str]] = defaultdict(
            lambda: deque(maxlen=FLOW_VOTE_WINDOW)
        )

        self._load_persisted_logs()

    @property
    def is_running(self) -> bool:
        return (
            bool(self._sniffer and getattr(self._sniffer, "running", False))
            or self._simulation_active
        )

    def set_detector(self, detector: Any | None) -> None:
        self.detector = detector

    @staticmethod
    def list_interfaces() -> list[str]:
        try:
            from scapy.all import get_if_list
        except ImportError as exc:
            raise RuntimeError("Scapy is required to list capture interfaces.") from exc
        return sorted(get_if_list())

    async def start_capture(
        self, interface: str | None = None, packet_filter: str | None = None
    ) -> dict[str, Any]:
        try:
            from scapy.all import AsyncSniffer
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live packet capture.") from exc

        with self._capture_lock:
            if self.is_running:
                return self.status()

            # FIX: Reset all session state so each new run starts clean.
            # self.logs cleared so WebSocket snapshot is empty on reconnect.
            self._stop_event.clear()
            self._session_counter = 0
            self.logs.clear()
            self._flows.clear()
            self._flow_votes.clear()
            self._recent_lengths.clear()
            self._recent_timestamps.clear()
            self._previous_timestamp = None
            self._simulation_active = False
            self._simulation_thread = None

            self._loop = asyncio.get_running_loop()
            self._interface = interface or None
            self._filter = packet_filter or None

            try:
                self._sniffer = AsyncSniffer(
                    iface=self._interface,
                    filter=self._filter,
                    prn=self._handle_packet,
                    store=False,
                )
                sniffer = self._sniffer
            except Exception as exc:
                LOGGER.warning(
                    "Live capture sniff start failed: %s. Falling back to simulation.", exc
                )
                self._sniffer = None
                self._simulation_active = True
                self._simulation_thread = threading.Thread(
                    target=self._run_packet_simulation,
                    daemon=True,
                    name="PacketSimulationThread",
                )
                self._simulation_thread.start()
                return self.status()

        sniffer.start()
        LOGGER.info("Started live capture interface=%s filter=%s", self._interface, self._filter)
        return self.status()

    async def stop_capture(self) -> dict[str, Any]:
        # Step 1: Signal everything atomically
        self._stop_event.set()
        self._simulation_active = False

        # Step 2: Wait for simulation thread to fully exit
        if self._simulation_thread is not None:
            self._simulation_thread.join(timeout=3.0)
            self._simulation_thread = None

        # Step 3: Stop AsyncSniffer and join its internal thread.
        # AsyncSniffer.stop() returns immediately but the capture thread
        # may still be running for ~1s (select() timeout). We join it
        # to get a hard guarantee that is_running is False on return.
        with self._capture_lock:
            sniffer = self._sniffer
            self._sniffer = None

        if sniffer is not None:
            try:
                sniffer.stop()
                sniffer_thread = getattr(sniffer, "_thread", None)
                if sniffer_thread is not None and sniffer_thread.is_alive():
                    sniffer_thread.join(timeout=3.0)
                    if sniffer_thread.is_alive():
                        LOGGER.warning("AsyncSniffer thread did not exit within 3s")
            except Exception:
                LOGGER.exception("Failed to stop packet capture cleanly")

        # Step 4: Reset stop event for next start_capture
        self._stop_event.clear()
        LOGGER.info("Stopped live capture. is_running=%s", self.is_running)
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.is_running,
            "interface": (
                self._interface if not self._simulation_active else "Simulation Mode"
            ),
            "filter": self._filter,
            "log_count": len(self.logs),
            "flow_count": len(self._flows),
            "ml_min_packets": MIN_FLOW_PACKETS_FOR_ML,
            "ml_min_duration": MIN_FLOW_DURATION_FOR_ML,
            "ml_attack_threshold": ML_ATTACK_ALERT_THRESHOLD,
            "block_mode": self.block_manager.mode,
            "blocked_ips": self.block_manager.list_blocked(),
            "blocked_entries": self.storage.list_blocked_entries() if self.storage is not None else [],
            "warning_counts": dict(sorted(self._warning_counts.items())),
            "simulation_active": self._simulation_active,
            # FIX: session_packets resets to 0 on every new capture start.
            # Frontend uses this for "packets this run", not log_count.
            "session_packets": self._session_counter,
        }

    def _run_packet_simulation(self) -> None:
        """Background simulation — checks _stop_event for atomic stop."""
        import time
        import random

        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            LOGGER.error("Scapy layers not available for simulation.")
            return

        LOGGER.info("Started packet simulation background thread.")

        benign_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.22",
            "192.168.1.100", "10.0.0.8", "10.0.0.12",
        ]
        dest_ips = [
            "104.244.42.1", "172.217.16.142", "13.224.225.12",
            "142.250.190.46", "34.197.10.22", "52.206.120.1",
        ]
        protocols = [TCP, UDP]
        ports = [80, 443, 8080, 53, 123]

        while not self._stop_event.is_set():
            try:
                is_attack = random.random() < 0.12
                if is_attack:
                    attack_type = random.choice(["BRUTEFORCE", "PORT_SCAN", "DOS"])
                    if attack_type == "DOS":
                        target_ip = "192.168.1.50"
                        attacker_ip = f"10.0.99.{random.randint(1, 254)}"
                        for _ in range(12):
                            if self._stop_event.is_set():
                                break
                            pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
                                sport=random.randint(1024, 65535), dport=80, flags="S"
                            ) / ("X" * 64)
                            self._handle_packet(pkt)
                            time.sleep(0.05)
                    elif attack_type == "PORT_SCAN":
                        attacker_ip = "10.0.50.88"
                        target_ip = "192.168.1.22"
                        for port in range(20, 30):
                            if self._stop_event.is_set():
                                break
                            pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
                                sport=random.randint(1024, 65535), dport=port, flags="S"
                            ) / ("X" * 40)
                            self._handle_packet(pkt)
                            time.sleep(0.1)
                    else:
                        attacker_ip = "198.51.100.12"
                        target_ip = "192.168.1.15"
                        for _ in range(10):
                            if self._stop_event.is_set():
                                break
                            pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
                                sport=random.randint(1024, 65535), dport=22, flags="PA"
                            ) / ("SSH_MOCK_LOGIN_ATTEMPT" * 4)
                            self._handle_packet(pkt)
                            time.sleep(0.2)
                else:
                    src = random.choice(benign_ips)
                    dst = random.choice(dest_ips)
                    proto = random.choice(protocols)
                    sport = random.randint(49152, 65535)
                    dport = random.choice(ports)
                    if proto == TCP:
                        payload_size = random.randint(64, 1460)
                        flags = "PA" if dport == 443 else "A"
                        pkt = IP(src=src, dst=dst) / TCP(
                            sport=sport, dport=dport, flags=flags
                        ) / ("B" * payload_size)
                    else:
                        payload_size = random.randint(20, 512)
                        pkt = IP(src=src, dst=dst) / UDP(
                            sport=sport, dport=dport
                        ) / ("U" * payload_size)
                    self._handle_packet(pkt)

                time.sleep(random.uniform(0.5, 1.5))
            except Exception:
                LOGGER.exception("Error in background packet simulation thread")
                time.sleep(2)

        LOGGER.info("Stopped packet simulation background thread.")

    def recent_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Returns session logs only (current run). Empty between runs."""
        bounded_limit = max(1, min(limit, self.logs.maxlen or DEFAULT_LOG_LIMIT))
        return [asdict(log) for log in list(self.logs)[-bounded_limit:]]

    def recent_history_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Returns logs from the previous run loaded from DB on startup."""
        bounded_limit = max(1, min(limit, self._history_logs.maxlen or DEFAULT_LOG_LIMIT))
        return [asdict(log) for log in list(self._history_logs)[-bounded_limit:]]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._subscribers_lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._subscribers_lock:
            self._subscribers.discard(queue)

    def block_ip(self, ip_address_value: str, reason: str = "Manual block from IDS log") -> dict[str, str]:
        result = self.block_manager.block(ip_address_value, reason)
        self._warning_counts.pop(result["ip"], None)
        self._publish({"type": "blocklist", "data": self.status()})
        return result

    def unblock_ip(self, ip_address_value: str) -> dict[str, str]:
        result = self.block_manager.unblock(ip_address_value)
        self._publish({"type": "blocklist", "data": self.status()})
        return result

    # Friend's addition
    def set_block_mode(self, mode: str) -> dict[str, Any]:
        result = self.block_manager.set_mode(mode)
        self._publish({"type": "blocklist", "data": self.status()})
        return result

    def analyze_pcap(
        self,
        pcap_file: str | Path,
        packet_limit: int = 5000,
        batch_size: int = 50,
    ) -> dict[str, Any]:
        """
        Replay a PCAP file through the IDS pipeline.

        FIX: Resets flow state before replay so stale live-capture stats
        don't bleed in and bypass the flow maturity gate.
        Publishes incremental progress events so dashboard counter rises
        smoothly instead of spiking all at once.
        """
        try:
            from scapy.all import PcapReader
        except ImportError as exc:
            raise RuntimeError("Scapy is required to analyze PCAP files.") from exc

        resolved_path = Path(pcap_file).expanduser().resolve()
        if not resolved_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {resolved_path}")

        # Reset session state for clean replay
        self._flows.clear()
        self._flow_votes.clear()
        self._recent_lengths.clear()
        self._recent_timestamps.clear()
        self._previous_timestamp = None
        self._session_counter = 0
        saved_counter = self._packet_counter
        self._packet_counter = 0

        processed_packets = 0
        alert_count = 0
        bounded_limit = max(1, min(packet_limit, 50000))

        try:
            with PcapReader(str(resolved_path)) as reader:
                for packet in reader:
                    if processed_packets >= bounded_limit:
                        break
                    packet_log = self.process_packet(packet)
                    processed_packets += 1
                    if packet_log.severity in {"critical", "high", "medium", "low"} or packet_log.action in {"alert", "blocked"}:
                        alert_count += 1

                    # Publish incremental progress for smooth dashboard counter
                    if processed_packets % batch_size == 0:
                        self._publish({
                            "type": "pcap_progress",
                            "data": {
                                "processed": processed_packets,
                                "alerts": alert_count,
                                "limit": bounded_limit,
                            },
                        })
        finally:
            self._packet_counter = saved_counter + processed_packets

        return {
            "processed_packets": processed_packets,
            "alert_count": alert_count,
            "packet_limit": bounded_limit,
            "logs": self.recent_logs(100),
        }

    def process_packet(self, packet: Any) -> PacketLog:
        packet_log = self._build_packet_log(packet)
        self._record_log(packet_log)
        return packet_log

    def _handle_packet(self, packet: Any) -> None:
        try:
            self.process_packet(packet)
        except Exception:
            LOGGER.exception("Failed to process captured packet")

    # Friend's addition: separate method for logging
    def _record_log(self, packet_log: PacketLog) -> None:
        self.logs.append(packet_log)
        packet_log_data = asdict(packet_log)
        if self.storage is not None:
            self.storage.save_packet_log(packet_log_data)
        self._publish({"type": "packet_log", "data": packet_log_data})

    def _build_packet_log(self, packet: Any) -> PacketLog:
        timestamp = float(getattr(packet, "time", datetime.now(timezone.utc).timestamp()))
        time_diff = (
            0.0 if self._previous_timestamp is None
            else max(timestamp - self._previous_timestamp, 0.0)
        )
        packet_length = int(len(packet))

        self._previous_timestamp = timestamp
        self._recent_lengths.append(packet_length)
        self._recent_timestamps.append(timestamp)
        packet_rate = self._rolling_packet_rate()
        avg_length = sum(self._recent_lengths) / len(self._recent_lengths)
        self._packet_counter += 1
        self._session_counter += 1

        metadata = self._extract_metadata(packet)
        detection_features = self._build_detection_features(
            metadata, packet_length, time_diff, packet_rate, avg_length, timestamp
        )
        encrypted_likely = self._is_encrypted_likely(metadata)
        decision = self._predict(detection_features, encrypted_likely, metadata)
        severity, signature, rule_id = self._classify_detection(
            decision["prediction"],
            decision["reason"],
            decision["ml_confidence"],
        )
        action, response_note = self._select_action(
            metadata=metadata,
            prediction=decision["prediction"],
            attack_label=decision["attack_label"],
            severity=severity,
            reason=decision["reason"],
        )

        return PacketLog(
            id=self._packet_counter,
            timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            source_ip=metadata["source_ip"],
            destination_ip=metadata["destination_ip"],
            source_port=metadata["source_port"],
            destination_port=metadata["destination_port"],
            protocol=metadata["protocol"],
            flow_id=str(detection_features["flow_id"]),
            flow_packet_count=int(detection_features["total_packets"]),
            flow_byte_count=int(detection_features["total_bytes"]),
            flow_duration=round(float(detection_features["flow_duration"]), 3),
            length=packet_length,
            time_diff=round(time_diff, 6),
            packet_rate=round(packet_rate, 3),
            avg_length=round(avg_length, 3),
            encrypted_likely=encrypted_likely,
            prediction=decision["prediction"],
            ml_confidence=decision["ml_confidence"],
            binary_label=decision["binary_label"],
            attack_label=decision["attack_label"],
            severity=severity,
            signature=signature,
            rule_id=rule_id,
            action=action,
            reason=decision["reason"],
            response_note=response_note,
        )

    def _extract_metadata(self, packet: Any) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": packet.lastlayer().name if hasattr(packet, "lastlayer") else "UNKNOWN",
            "protocol_number": 0,
            "ttl": 0,
            "syn_flag": 0,
            "ack_flag": 0,
            "rst_flag": 0,
            "psh_flag": 0,
        }

        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
        except ImportError:
            return metadata

        if packet.haslayer(IP):
            metadata["source_ip"] = packet[IP].src
            metadata["destination_ip"] = packet[IP].dst
            metadata["protocol"] = "IP"
            metadata["protocol_number"] = int(packet[IP].proto)
            metadata["ttl"] = int(packet[IP].ttl)
        elif packet.haslayer(IPv6):
            metadata["source_ip"] = packet[IPv6].src
            metadata["destination_ip"] = packet[IPv6].dst
            metadata["protocol"] = "IPv6"
            metadata["protocol_number"] = int(packet[IPv6].nh)
            metadata["ttl"] = int(packet[IPv6].hlim)

        if packet.haslayer(TCP):
            metadata["source_port"] = int(packet[TCP].sport)
            metadata["destination_port"] = int(packet[TCP].dport)
            metadata["protocol"] = "TCP"
            flags = int(packet[TCP].flags)
            metadata["syn_flag"] = int(bool(flags & 0x02))
            metadata["ack_flag"] = int(bool(flags & 0x10))
            metadata["rst_flag"] = int(bool(flags & 0x04))
            metadata["psh_flag"] = int(bool(flags & 0x08))
        elif packet.haslayer(UDP):
            metadata["source_port"] = int(packet[UDP].sport)
            metadata["destination_port"] = int(packet[UDP].dport)
            metadata["protocol"] = "UDP"
        elif packet.haslayer(ICMP):
            metadata["protocol"] = "ICMP"

        return metadata

    def _is_encrypted_likely(self, metadata: Mapping[str, Any]) -> bool:
        ports = {metadata.get("source_port"), metadata.get("destination_port")}
        return bool(ENCRYPTED_PORTS.intersection(port for port in ports if port is not None))

    def _is_trusted_bandwidth_flow(self, metadata: Mapping[str, Any]) -> bool:
        """True if either port is a known legitimate high-bandwidth port (P2P etc.)."""
        ports = {metadata.get("source_port"), metadata.get("destination_port")}
        return bool(
            TRUSTED_HIGH_BANDWIDTH_PORTS.intersection(
                int(p) for p in ports if p is not None
            )
        )

    def _build_detection_features(
        self,
        metadata: Mapping[str, Any],
        length: int,
        time_diff: float,
        packet_rate: float,
        avg_length: float,
        observed_at: float | None = None,
    ) -> dict[str, float | int | str]:
        now = observed_at if observed_at is not None else datetime.now(timezone.utc).timestamp()
        flow_key = (
            metadata.get("source_ip"),
            metadata.get("destination_ip"),
            metadata.get("protocol_number") or metadata.get("protocol"),
        )
        flow_id = self._stable_rule_suffix("|".join(str(part) for part in flow_key))
        flow = self._flows.setdefault(
            flow_key,
            {
                "start_time": now,
                "last_seen": now,
                "total_packets": 0,
                "total_bytes": 0,
                "lengths": deque(maxlen=ROLLING_WINDOW_SIZE),
                "classify_counter": 0,
            },
        )
        flow["total_packets"] += 1
        flow["total_bytes"] += length
        flow["last_seen"] = now
        flow["lengths"].append(length)
        flow["classify_counter"] += 1

        flow_duration = max(now - float(flow["start_time"]), 0.000001)
        lengths = list(flow["lengths"])
        min_pkt_len = min(lengths) if lengths else length
        max_pkt_len = max(lengths) if lengths else length
        avg_pkt_len = sum(lengths) / len(lengths) if lengths else avg_length
        pkt_len_std = statistics.pstdev(lengths) if len(lengths) > 1 else 0.0
        total_packets = int(flow["total_packets"])
        total_bytes = int(flow["total_bytes"])
        bytes_per_packet = total_bytes / (total_packets + 0.000001)
        packets_per_second = total_packets / (flow_duration + 0.000001)
        byte_rate = total_bytes / (flow_duration + 0.000001)
        burstiness = pkt_len_std / (avg_pkt_len + 0.000001)
        flag_sum = (
            int(metadata.get("syn_flag") or 0)
            + int(metadata.get("ack_flag") or 0)
            + int(metadata.get("rst_flag") or 0)
            + int(metadata.get("psh_flag") or 0)
        )

        return {
            "flow_id": flow_id,
            "classify_counter": flow["classify_counter"],
            "dst_port": int(metadata.get("destination_port") or 0),
            "protocol": int(metadata.get("protocol_number") or 0),
            "flow_duration": flow_duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "min_pkt_len": min_pkt_len,
            "max_pkt_len": max_pkt_len,
            "avg_pkt_len": avg_pkt_len,
            "pkt_len_std": pkt_len_std,
            "flow_rate": byte_rate,
            "iat": time_diff,
            "syn_flag": int(metadata.get("syn_flag") or 0),
            "ack_flag": int(metadata.get("ack_flag") or 0),
            "rst_flag": int(metadata.get("rst_flag") or 0),
            "psh_flag": int(metadata.get("psh_flag") or 0),
            "ttl": int(metadata.get("ttl") or 0),
            "bytes_per_packet": bytes_per_packet,
            "packets_per_second": packets_per_second,
            "avg_packet_size": bytes_per_packet,
            "byte_rate": byte_rate,
            "burstiness": burstiness,
            "flag_sum": flag_sum,
            "length": length,
            "time_diff": time_diff,
            "packet_rate": packet_rate,
            "avg_length": avg_length,
            # Internal routing keys — stripped before reaching the model
            "_src_port": metadata.get("source_port"),
            "_dst_port_raw": metadata.get("destination_port"),
        }

    def _predict(
        self,
        features: Mapping[str, Any],
        encrypted_likely: bool,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        # FIX: Skip raw IP fragments (no port on either side)
        if SKIP_PORTLESS_FRAGMENTS:
            if features.get("_src_port") is None and features.get("_dst_port_raw") is None:
                return self._decision(
                    prediction="Normal",
                    reason="ip_fragment_skipped",
                )

        # FIX: Bypass ML for known high-bandwidth legitimate ports (P2P, etc.)
        if metadata is not None and self._is_trusted_bandwidth_flow(metadata):
            return self._decision(
                prediction="Normal",
                reason="trusted_port_bypass",
            )

        # FIX: Only run ML every FLOW_CLASSIFY_INTERVAL packets
        classify_counter = int(features.get("classify_counter") or 1)
        if not self._is_flow_ready_for_ml(features):
            return self._decision(prediction="Normal", reason="flow_warmup")

        if classify_counter % FLOW_CLASSIFY_INTERVAL != 0:
            return self._decision(prediction="Normal", reason="flow_interval_skip")

        if self.detector is not None:
            expected_features = self.detector.expected_features()
            if expected_features is None or set(expected_features).issubset(features):
                if hasattr(self.detector, "predict_details"):
                    result = self.detector.predict_details(features)
                    confidence = result.confidence
                    prediction = result.prediction
                    normalized_prediction = prediction.strip().lower()
                    normalized_attack_label = (result.attack_label or "").strip().lower()

                    # Friend's addition: ambiguous labels → warning, not alert
                    if (normalized_prediction in AMBIGUOUS_ATTACK_LABELS
                            or normalized_attack_label in AMBIGUOUS_ATTACK_LABELS):
                        warning_label = result.attack_label or result.prediction or "Other"
                        return self._decision(
                            prediction=warning_label,
                            reason="model_uncertain_attack",
                            ml_confidence=confidence,
                            binary_label=result.binary_label,
                            attack_label=result.attack_label,
                        )

                    # FIX: Apply raised binary threshold
                    if normalized_prediction not in BENIGN_LABELS and confidence is not None:
                        if confidence < BINARY_MALICIOUS_THRESHOLD:
                            return self._decision(
                                prediction="Normal",
                                reason="model_low_confidence",
                                ml_confidence=confidence,
                                binary_label=result.binary_label,
                                attack_label=result.attack_label,
                            )

                    # FIX: Consensus vote before confirming MALICIOUS
                    flow_id = str(features.get("flow_id", ""))
                    if flow_id:
                        vote = "MALICIOUS" if normalized_prediction not in BENIGN_LABELS else "BENIGN"
                        self._flow_votes[flow_id].append(vote)
                        votes = list(self._flow_votes[flow_id])
                        malicious_ratio = votes.count("MALICIOUS") / len(votes)
                        if vote == "MALICIOUS" and malicious_ratio < FLOW_MALICIOUS_RATIO:
                            return self._decision(
                                prediction="Normal",
                                reason="model_low_confidence",
                                ml_confidence=confidence,
                                binary_label=result.binary_label,
                                attack_label=result.attack_label,
                            )

                    return self._decision(
                        prediction=prediction,
                        reason="model_prediction",
                        ml_confidence=confidence,
                        binary_label=result.binary_label,
                        attack_label=result.attack_label,
                    )

                return self._decision(
                    prediction=self.detector.predict(features),
                    reason="model_prediction",
                )

        if float(features.get("packet_rate") or 0.0) > HIGH_PACKET_RATE_THRESHOLD:
            return self._decision(prediction="Suspicious", reason="high_packet_rate")
        if encrypted_likely:
            return self._decision(prediction="Normal", reason="encrypted_metadata_only")
        return self._decision(prediction="Normal", reason="metadata_baseline")

    @staticmethod
    def _is_flow_ready_for_ml(features: Mapping[str, Any]) -> bool:
        total_packets = int(features.get("total_packets") or 0)
        flow_duration = float(features.get("flow_duration") or 0.0)
        return (
            total_packets >= MIN_FLOW_PACKETS_FOR_ML
            and flow_duration >= MIN_FLOW_DURATION_FOR_ML
        )

    @staticmethod
    def _decision(
        *,
        prediction: str,
        reason: str,
        signature_label: str | None = None,
        ml_confidence: float | None = None,
        binary_label: str | None = None,
        attack_label: str | None = None,
    ) -> dict[str, Any]:
        return {
            "prediction": prediction,
            "reason": reason,
            "signature_label": signature_label,
            "ml_confidence": ml_confidence,
            "binary_label": binary_label,
            "attack_label": attack_label,
        }

    def _rolling_packet_rate(self) -> float:
        if len(self._recent_timestamps) < 2:
            return 0.0
        elapsed = self._recent_timestamps[-1] - self._recent_timestamps[0]
        if elapsed <= 0:
            return 0.0
        return (len(self._recent_timestamps) - 1) / elapsed

    def _classify_detection(
        self,
        prediction: str,
        reason: str,
        ml_confidence: float | None = None,
    ) -> tuple[str, str, str]:
        label = prediction.strip()
        normalized_label = label.lower()

        if reason == "model_prediction":
            return (
                self._severity_from_model_label(normalized_label, ml_confidence),
                f"ML classification: {label}",
                f"ML-{self._stable_rule_suffix(normalized_label)}",
            )
        if reason == "model_low_confidence":
            return "info", "ML monitoring: low confidence", "ML-MONITOR"
        if reason == "model_uncertain_attack":  # friend's addition
            return "low", "ML warning: uncertain attack class", "ML-WARN"
        if reason in {"flow_warmup", "flow_interval_skip", "ip_fragment_skipped",
                      "trusted_port_bypass"}:
            return "info", "Flow warmup: collecting evidence", "FLOW-WARMUP"
        if reason == "high_packet_rate":
            return "critical", "Sustained packet-rate anomaly", "META-1001"
        if reason == "encrypted_metadata_only":
            return "info", "Encrypted service metadata", "META-1002"
        return "info", "Metadata baseline", "META-0000"

    @staticmethod
    def _severity_from_model_label(normalized_label: str, confidence: float | None = None) -> str:
        if normalized_label in BENIGN_LABELS:
            return "info"
        # FIX: "suspicious" is sub-threshold Stage 2 output — treat as info not medium
        if normalized_label == "suspicious":
            return "info"
        if normalized_label in AMBIGUOUS_ATTACK_LABELS:  # friend's addition
            return "low"
        if confidence is not None and confidence < ML_ATTACK_ALERT_THRESHOLD:
            return "info"
        if confidence is not None and confidence < 90.0:
            return "medium"
        if any(keyword in normalized_label for keyword in CRITICAL_LABEL_KEYWORDS):
            return "critical"
        if any(keyword in normalized_label for keyword in HIGH_LABEL_KEYWORDS):
            return "high"
        if any(keyword in normalized_label for keyword in MEDIUM_LABEL_KEYWORDS):
            return "medium"
        return "medium"

    @staticmethod
    def _stable_rule_suffix(value: str) -> str:
        import hashlib
        digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
        return digest[:8].upper()

    def _select_action(
        self,
        *,
        metadata: Mapping[str, Any],
        prediction: str,
        attack_label: str | None,
        severity: str,
        reason: str,
    ) -> tuple[str, str | None]:
        source_ip = metadata.get("source_ip")
        destination_ip = metadata.get("destination_ip")
        if self.block_manager.is_blocked(source_ip) or self.block_manager.is_blocked(destination_ip):
            return "blocked", "Matched existing blocklist rule"

        normalized_prediction = prediction.strip().lower()
        normalized_label = (attack_label or prediction).strip().lower()

        # Friend's addition: uncertain attack → warning action
        if reason == "model_uncertain_attack":
            return "warning", "ML warning: uncertain class, review before treating as attack"

        if normalized_prediction in {"normal", "benign"} or severity == "info":
            return "allow", None

        # Friend's addition: auto-block on confirmed high-confidence attacks
        if source_ip and any(keyword in normalized_label for keyword in BLOCK_IMMEDIATELY_KEYWORDS):
            block_reason = f"Auto-blocked {prediction} traffic"
            self.block_ip(source_ip, block_reason)
            return "blocked", block_reason

        # Friend's addition: recon warning counter → auto-block after threshold
        if source_ip and any(keyword in normalized_label for keyword in RECON_WARNING_KEYWORDS):
            warning_count = self._warning_counts.get(source_ip, 0) + 1
            if warning_count >= RECON_WARNING_THRESHOLD:
                self._warning_counts.pop(source_ip, None)
                block_reason = f"Auto-blocked after {RECON_WARNING_THRESHOLD} reconnaissance warnings"
                self.block_ip(source_ip, block_reason)
                return "blocked", block_reason
            self._warning_counts[source_ip] = warning_count
            return "warning", f"Recon warning {warning_count}/{RECON_WARNING_THRESHOLD}"

        return "alert", None

    def _publish(self, event: dict[str, Any]) -> None:
        with self._subscribers_lock:
            subscribers = list(self._subscribers)

        if not subscribers or self._loop is None:
            return

        for queue in subscribers:
            self._loop.call_soon_threadsafe(self._enqueue_event, queue, event)

    @staticmethod
    def _enqueue_event(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(event)
            except asyncio.QueueEmpty:
                pass

    def _load_persisted_logs(self) -> None:
        """
        Load historical logs from DB into _history_logs (NOT self.logs).
        self.logs stays empty until start_capture() so the WebSocket snapshot
        on fresh connect is empty and never inflates the session counter.
        _packet_counter IS updated to avoid DB primary key collisions.
        """
        if self.storage is None:
            return

        for log_data in self.storage.recent_logs(self.logs.maxlen or DEFAULT_LOG_LIMIT):
            log_data.setdefault("flow_id", "LEGACY")
            log_data.setdefault("flow_packet_count", 0)
            log_data.setdefault("flow_byte_count", 0)
            log_data.setdefault("flow_duration", 0.0)
            log_data.setdefault("ml_confidence", None)
            log_data.setdefault("binary_label", None)
            log_data.setdefault("attack_label", None)
            log_data.setdefault(
                "severity",
                self._severity_from_model_label(str(log_data.get("prediction", "")).lower()),
            )
            log_data.setdefault("signature", str(log_data.get("prediction") or "Metadata baseline"))
            log_data.setdefault("rule_id", "LEGACY-0000")
            log_data.setdefault("response_note", None)
            packet_log = PacketLog(**log_data)
            self._history_logs.append(packet_log)
            self._packet_counter = max(self._packet_counter, packet_log.id)


def export_logs_to_csv(logs: list[dict[str, Any]], output_path: str | Path) -> Path:
    import pandas as pd

    resolved_path = Path(output_path).expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(logs).to_csv(resolved_path, index=False)
    return resolved_path
