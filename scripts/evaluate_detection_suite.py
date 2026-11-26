"""Labelled synthetic PCAP generator and detection evaluation harness.

Generates deterministic PCAPs for 8 traffic scenarios and measures actual
Precision, Recall, F1-score, False-Positive Rate, processing time, and memory.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import Settings  # noqa: E402
from app.core.database import DatabaseManager  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services.analyzer import AnalysisOrchestrator  # noqa: E402
from app.services.ingestion import PcapIngestor  # noqa: E402

BASE_TS = 1735689600.0
SRC_MAC = "02:11:22:33:44:55"
DST_MAC = "02:aa:bb:cc:dd:ee"


@dataclass(slots=True)
class ScenarioSpec:
    name: str
    pcap_path: Path
    expected_suspicious_dsts: set[str]
    expected_benign_dsts: set[str]


def _tcp_exchange(
    packets: list[Packet],
    ts: float,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    out_chunks: list[bytes],
    in_chunks: list[bytes],
) -> None:
    syn = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags="S", seq=1000
    )
    syn.time = ts
    packets.append(syn)

    synack = Ether(src=DST_MAC, dst=SRC_MAC) / IP(src=dst_ip, dst=src_ip) / TCP(
        sport=dport, dport=sport, flags="SA", seq=5000, ack=1001
    )
    synack.time = ts + 0.01
    packets.append(synack)

    ack = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=1001, ack=5001
    )
    ack.time = ts + 0.02
    packets.append(ack)

    cur = ts + 0.03
    seq_c = 1001
    for c in out_chunks:
        pkt = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=5001)
            / Raw(load=c)
        )
        pkt.time = cur
        packets.append(pkt)
        seq_c += len(c)
        cur += 0.005

    seq_s = 5001
    for c in in_chunks:
        pkt = (
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
            / Raw(load=c)
        )
        pkt.time = cur
        packets.append(pkt)
        seq_s += len(c)
        cur += 0.005


def build_labelled_scenarios(out_dir: Path) -> list[ScenarioSpec]:
    out_dir.mkdir(parents=True, exist_ok=True)
    client = "10.0.20.15"
    specs: list[ScenarioSpec] = []

    # 1. Normal web browsing
    p1: list[Packet] = []
    for idx, dom in enumerate(("www.example.com", "static.example.org")):
        q = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=client, dst="8.8.8.8")
            / UDP(sport=51000 + idx, dport=53)
            / DNS(id=10 + idx, qr=0, qd=DNSQR(qname=dom, qtype="A"))
        )
        q.time = BASE_TS + idx
        r = (
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src="8.8.8.8", dst=client)
            / UDP(sport=53, dport=51000 + idx)
            / DNS(id=10 + idx, qr=1, rcode=0, qd=DNSQR(qname=dom, qtype="A"),
                  an=DNSRR(rrname=dom, type="A", rdata="93.184.216.34"))
        )
        r.time = BASE_TS + idx + 0.02
        p1.extend([q, r])
    _tcp_exchange(
        p1, BASE_TS + 3.0, client, "93.184.216.34", 52001, 80,
        [b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"],
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n" + b"A" * 1200],
    )
    path1 = out_dir / "01_normal_web_browsing.pcap"
    wrpcap(str(path1), p1)
    specs.append(ScenarioSpec("normal_web_browsing", path1, set(), {"93.184.216.34", "8.8.8.8"}))

    # 2. Large outbound upload
    p2: list[Packet] = []
    hdr = (
        b"POST /backup/dump HTTP/1.1\r\nHost: 198.51.100.70\r\n"
        b"Content-Length: 300000\r\n\r\n"
    )
    chunks = [hdr + b"Z" * 1200] + [b"Z" * 1300 for _ in range(230)]
    _tcp_exchange(
        p2, BASE_TS, client, "198.51.100.70", 52010, 80, chunks,
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"],
    )
    path2 = out_dir / "02_large_outbound_upload.pcap"
    wrpcap(str(path2), p2)
    specs.append(ScenarioSpec("large_outbound_upload", path2, {"198.51.100.70"}, set()))

    # 3. DNS tunnelling
    p3: list[Packet] = []
    for i in range(10):
        sub = f"9f8e7d6c5b4a3210fedcba9876543210abcdef{i:02x}1122334455"
        q = (
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=client, dst="8.8.4.4")
            / UDP(sport=53000 + i, dport=53)
            / DNS(id=200 + i, qr=0, qd=DNSQR(qname=f"{sub}.tunnel-c2.example", qtype="TXT"))
        )
        q.time = BASE_TS + i * 0.25
        p3.append(q)
    path3 = out_dir / "03_dns_tunnelling.pcap"
    wrpcap(str(path3), p3)
    specs.append(ScenarioSpec("dns_tunnelling", path3, {"8.8.4.4"}, set()))

    # 4. Beaconing (including one missed beat gap)
    p4: list[Packet] = []
    for idx, off in enumerate((0.0, 12.0, 24.0, 48.0, 60.0)):
        _tcp_exchange(
            p4, BASE_TS + off, client, "203.0.113.88", 54000 + idx, 8443,
            [b"\x16\x03\x01\x00\x20" + b"\x00" * 32], [b"\x17\x03\x03\x00\x05hello"],
        )
    path4 = out_dir / "04_beaconing.pcap"
    wrpcap(str(path4), p4)
    specs.append(ScenarioSpec("beaconing", path4, {"203.0.113.88"}, set()))

    # 5. Suspicious HTTP communication
    p5: list[Packet] = []
    req5 = (
        b"PUT /stage/payload.bin HTTP/1.1\r\n"
        b"Host: 203.0.113.91:8081\r\n"
        b"User-Agent: python-requests/2.31.0\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 75000\r\n\r\n" + b"B" * 1200
    )
    _tcp_exchange(p5, BASE_TS, client, "203.0.113.91", 54100, 8081, [req5], [b"HTTP/1.1 201 Created\r\n\r\n"])
    path5 = out_dir / "05_suspicious_http.pcap"
    wrpcap(str(path5), p5)
    specs.append(ScenarioSpec("suspicious_http", path5, {"203.0.113.91"}, set()))

    # 6. Unusual port usage (4444)
    p6: list[Packet] = []
    _tcp_exchange(
        p6, BASE_TS, client, "198.51.100.99", 54200, 4444,
        [b"CMD_OUT_" * 200 for _ in range(15)], [b"OK"],
    )
    path6 = out_dir / "06_unusual_port.pcap"
    wrpcap(str(path6), p6)
    specs.append(ScenarioSpec("unusual_port", path6, {"198.51.100.99"}, set()))

    # 7. Benign unusual traffic (large inbound CDN software download + 1 high-entropy query)
    p7: list[Packet] = []
    q_cdn = (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=client, dst="1.1.1.1")
        / UDP(sport=55000, dport=53)
        / DNS(id=300, qr=0, qd=DNSQR(qname="4a7f9c2e8b1d.cdn-assets.example", qtype="A"))
    )
    q_cdn.time = BASE_TS
    p7.append(q_cdn)
    _tcp_exchange(
        p7, BASE_TS + 1.0, client, "93.184.216.50", 55001, 80,
        [b"GET /installer.pkg HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n"],
        [b"D" * 1400 for _ in range(120)],  # Large INBOUND download, tiny outbound
    )
    path7 = out_dir / "07_benign_unusual_traffic.pcap"
    wrpcap(str(path7), p7)
    specs.append(ScenarioSpec("benign_unusual_traffic", path7, set(), {"1.1.1.1", "93.184.216.50"}))

    # 8. Mixed normal and suspicious traffic
    p8 = list(p1) + [pkt.copy() for pkt in p3] + [pkt.copy() for pkt in p5]
    p8.sort(key=lambda pkt: float(pkt.time))
    path8 = out_dir / "08_mixed_normal_and_suspicious.pcap"
    wrpcap(str(path8), p8)
    specs.append(
        ScenarioSpec(
            "mixed_normal_and_suspicious",
            path8,
            {"8.8.4.4", "203.0.113.91"},
            {"93.184.216.34", "8.8.8.8"},
        )
    )
    return specs


def evaluate_suite(out_dir: Path | None = None) -> dict[str, object]:
    """Run all 8 scenarios through the full orchestrator and compute metrics."""
    cleanup_dir = out_dir is None
    work_dir = out_dir or Path(tempfile.mkdtemp(prefix="pcap_eval_"))
    try:
        pcap_dir = work_dir / "pcaps"
        specs = build_labelled_scenarios(pcap_dir)

        rules_dir = work_dir / "rules"
        if not rules_dir.exists():
            shutil.copytree(BACKEND_DIR / "rules", rules_dir)

        settings = Settings(
            environment="test",
            upload_dir=work_dir / "uploads",
            analyses_dir=work_dir / "analyses",
            reports_dir=work_dir / "reports",
            rules_dir=rules_dir,
            database_path=work_dir / "eval.db",
        )
        create_app(custom_settings=settings)
        db = DatabaseManager(settings.database_path)
        db.init_schema()
        ingestor = PcapIngestor(settings=settings, db=db)
        orch = AnalysisOrchestrator(settings=settings, db=db)

        tp = fp = fn = tn = 0
        scenario_results: list[dict[str, object]] = []
        total_ms = 0.0
        max_peak_kib = 0.0

        for spec in specs:
            tracemalloc.start()
            t0 = time.perf_counter()
            meta = ingestor.ingest_existing_file(spec.pcap_path)
            bundle = orch.run_analysis(meta.analysis_id)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            _cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peak_kib = round(peak / 1024.0, 1)

            total_ms += elapsed_ms
            max_peak_kib = max(max_peak_kib, peak_kib)

            flagged_dsts = {
                a.get("destination_ip")
                for a in bundle.get("active_alerts", [])
                if a.get("destination_ip")
            }

            s_tp = len(spec.expected_suspicious_dsts & flagged_dsts)
            s_fn = len(spec.expected_suspicious_dsts - flagged_dsts)
            s_fp = len(spec.expected_benign_dsts & flagged_dsts)
            s_tn = len(spec.expected_benign_dsts - flagged_dsts)

            tp += s_tp
            fn += s_fn
            fp += s_fp
            tn += s_tn

            scenario_results.append(
                {
                    "scenario": spec.name,
                    "packets": bundle["summary"]["total_packets"],
                    "active_alerts": bundle["summary"]["suspicious_events"],
                    "active_incidents": bundle["summary"].get("active_incidents", 0),
                    "tp": s_tp,
                    "fp": s_fp,
                    "fn": s_fn,
                    "tn": s_tn,
                    "processing_ms": elapsed_ms,
                    "peak_memory_kib": peak_kib,
                }
            )

        precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        f1 = (
            round(2 * precision * recall / (precision + recall), 4)
            if (precision + recall)
            else 0.0
        )
        fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "total_processing_ms": round(total_ms, 2),
            "peak_memory_kib": max_peak_kib,
            "scenarios": scenario_results,
        }
    finally:
        if cleanup_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    import json

    summary = evaluate_suite()
    print(json.dumps(summary, indent=2))
