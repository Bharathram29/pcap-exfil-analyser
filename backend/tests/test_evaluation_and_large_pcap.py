"""Tests for Phase 12: 8-scenario labelled detection evaluation & large PCAP handling."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.main import create_app


def test_detection_evaluation_metrics_across_8_labelled_scenarios(tmp_path: Path) -> None:
    scripts_dir = PROJECT_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from evaluate_detection_suite import evaluate_suite

    metrics = evaluate_suite(out_dir=tmp_path / "eval_run")
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert len(metrics["scenarios"]) == 8  # type: ignore[arg-type]


def test_large_pcap_handling_and_packet_pagination(tmp_path: Path) -> None:
    # Build a 3,000-packet synthetic capture to verify streaming, flow aggregation, & pagination
    pcap_path = tmp_path / "large_3000.pcap"
    t0 = 1735700000.0
    pkts = []
    for i in range(3000):
        sport = 40000 + (i % 20)
        pkt = (
            Ether()
            / IP(src="10.1.0.5", dst="93.184.216.34")
            / TCP(sport=sport, dport=443, flags="PA", seq=1000 + i * 100, ack=1)
            / Raw(load=b"A" * 80)
        )
        pkt.time = t0 + i * 0.002
        pkts.append(pkt)
    wrpcap(str(pcap_path), pkts)

    rules_dir = tmp_path / "rules"
    shutil.copytree(BACKEND_DIR / "rules", rules_dir)
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "uploads",
        analyses_dir=tmp_path / "analyses",
        reports_dir=tmp_path / "reports",
        rules_dir=rules_dir,
        database_path=tmp_path / "data" / "large.db",
    )
    app = create_app(custom_settings=settings)
    with TestClient(app) as client:
        with pcap_path.open("rb") as fh:
            up = client.post(
                "/api/pcap/upload",
                files={"file": ("large_3000.pcap", fh, "application/octet-stream")},
            )
        assert up.status_code == 201
        analysis_id = up.json()["analysis_id"]

        start = client.post(
            "/api/analysis/start",
            json={"analysis_id": analysis_id, "run_async": False},
        )
        assert start.status_code == 200
        assert start.json()["status"] == "COMPLETED"

        p1 = client.get(f"/api/analysis/{analysis_id}/packets?limit=100&offset=0").json()
        p2 = client.get(f"/api/analysis/{analysis_id}/packets?limit=100&offset=2900").json()
        assert p1["total"] == 3000
        assert len(p1["packets"]) == 100
        assert len(p2["packets"]) == 100
        assert p2["packets"][-1]["packet_index"] == 3000
