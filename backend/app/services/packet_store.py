"""SQLite-backed paginated packet-level forensic evidence store."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from app.core.database import DatabaseManager
from app.models.alert import SecurityAlert
from app.models.packet import NormalizedPacket


def _decoded_fields(pkt: NormalizedPacket) -> dict[str, Any]:
    """Build compact decoded metadata dict without dumping raw payload bytes."""
    fields: dict[str, Any] = {
        "ttl": pkt.ttl,
        "ip_version": pkt.ip_version,
        "is_malformed": pkt.is_malformed,
        "missing_fields": pkt.missing_fields,
    }
    if pkt.tcp is not None:
        fields["tcp"] = {
            "seq": pkt.tcp.seq,
            "ack": pkt.tcp.ack,
            "flags": pkt.tcp.flag_names,
            "window_size": pkt.tcp.window_size,
            "payload_size": pkt.tcp.payload_size,
            "is_retransmission": pkt.tcp.is_retransmission,
        }
    if pkt.dns is not None:
        fields["dns"] = pkt.dns.to_dict()
    if pkt.http is not None:
        fields["http"] = pkt.http.to_dict()
    if pkt.tls is not None:
        fields["tls"] = pkt.tls.to_dict()
    return fields


class PacketStore:
    """Persist and query bounded packet-level forensic evidence with pagination."""

    def save_packets(
        self,
        db: DatabaseManager,
        analysis_id: str,
        packets: list[NormalizedPacket],
        packet_flow_map: dict[int, str],
        alerts: list[SecurityAlert],
        max_store: int = 100_000,
    ) -> int:
        """Persist packet metadata rows in batches, linking flow_id and alert_ids."""
        pkt_to_alerts: dict[int, list[str]] = defaultdict(list)
        flow_to_alerts: dict[str, list[str]] = defaultdict(list)
        for alert in alerts:
            for pidx in alert.packet_indices:
                if alert.alert_id not in pkt_to_alerts[pidx]:
                    pkt_to_alerts[pidx].append(alert.alert_id)
            if alert.flow_id:
                flow_to_alerts[alert.flow_id].append(alert.alert_id)

        capped = packets[:max_store] if max_store > 0 else packets
        rows: list[tuple[Any, ...]] = []
        for pkt in capped:
            fid = packet_flow_map.get(pkt.packet_index)
            aids = list(pkt_to_alerts.get(pkt.packet_index, []))
            if fid and fid in flow_to_alerts:
                for aid in flow_to_alerts[fid]:
                    if aid not in aids:
                        aids.append(aid)

            rows.append(
                (
                    analysis_id,
                    pkt.packet_index,
                    pkt.timestamp,
                    pkt.timestamp_utc,
                    pkt.src_ip,
                    pkt.dst_ip,
                    pkt.src_port,
                    pkt.dst_port,
                    pkt.protocol,
                    pkt.transport_protocol,
                    pkt.length,
                    pkt.ttl,
                    pkt.ip_version,
                    fid,
                    json.dumps(aids),
                    json.dumps(_decoded_fields(pkt)),
                    pkt.raw_summary[:512],
                )
            )

        with db.connection() as conn:
            conn.execute("DELETE FROM packets WHERE analysis_id = ?", (analysis_id,))
            batch_size = 2000
            for start in range(0, len(rows), batch_size):
                conn.executemany(
                    """
                    INSERT INTO packets (
                        analysis_id, packet_index, timestamp_epoch, timestamp_utc,
                        src_ip, dst_ip, src_port, dst_port, protocol, transport_protocol,
                        length, ttl, ip_version, flow_id, alert_ids_json,
                        decoded_fields_json, raw_summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows[start : start + batch_size],
                )
        return len(rows)

    def query_packets(
        self,
        db: DatabaseManager,
        analysis_id: str,
        *,
        ip: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        port: int | None = None,
        protocol: str | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
        alert_id: str | None = None,
        flow_id: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search and filter persisted packets with static parameterized SQLite queries."""
        ip_v = ip.strip() if ip else None
        src_v = src_ip.strip() if src_ip else None
        dst_v = dst_ip.strip() if dst_ip else None
        proto_v = protocol.strip() if protocol else None
        flow_v = flow_id.strip() if flow_id else None
        alert_like = f'%"{alert_id.strip()}"%' if alert_id else None
        search_like = f"%{search.strip()}%" if search else None

        filter_params = (
            analysis_id,
            ip_v, ip_v, ip_v,
            src_v, src_v,
            dst_v, dst_v,
            port, port, port,
            proto_v, proto_v, proto_v,
            start_time, start_time,
            end_time, end_time,
            flow_v, flow_v,
            alert_like, alert_like,
            search_like, search_like, search_like, search_like, search_like, search_like,
        )

        with db.connection() as conn:
            total_row = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM packets
                WHERE analysis_id = ?
                  AND (? IS NULL OR src_ip = ? OR dst_ip = ?)
                  AND (? IS NULL OR src_ip = ?)
                  AND (? IS NULL OR dst_ip = ?)
                  AND (? IS NULL OR src_port = ? OR dst_port = ?)
                  AND (
                    ? IS NULL
                    OR UPPER(protocol) = UPPER(?)
                    OR UPPER(transport_protocol) = UPPER(?)
                  )
                  AND (? IS NULL OR timestamp_epoch >= ?)
                  AND (? IS NULL OR timestamp_epoch <= ?)
                  AND (? IS NULL OR flow_id = ?)
                  AND (? IS NULL OR alert_ids_json LIKE ?)
                  AND (
                    ? IS NULL
                    OR src_ip LIKE ?
                    OR dst_ip LIKE ?
                    OR protocol LIKE ?
                    OR decoded_fields_json LIKE ?
                    OR raw_summary LIKE ?
                  )
                """,
                filter_params,
            ).fetchone()
            total = int(total_row["cnt"]) if total_row else 0

            rows = conn.execute(
                """
                SELECT packet_index, timestamp_epoch, timestamp_utc, src_ip, dst_ip,
                       src_port, dst_port, protocol, transport_protocol, length,
                       ttl, ip_version, flow_id, alert_ids_json, decoded_fields_json,
                       raw_summary
                FROM packets
                WHERE analysis_id = ?
                  AND (? IS NULL OR src_ip = ? OR dst_ip = ?)
                  AND (? IS NULL OR src_ip = ?)
                  AND (? IS NULL OR dst_ip = ?)
                  AND (? IS NULL OR src_port = ? OR dst_port = ?)
                  AND (
                    ? IS NULL
                    OR UPPER(protocol) = UPPER(?)
                    OR UPPER(transport_protocol) = UPPER(?)
                  )
                  AND (? IS NULL OR timestamp_epoch >= ?)
                  AND (? IS NULL OR timestamp_epoch <= ?)
                  AND (? IS NULL OR flow_id = ?)
                  AND (? IS NULL OR alert_ids_json LIKE ?)
                  AND (
                    ? IS NULL
                    OR src_ip LIKE ?
                    OR dst_ip LIKE ?
                    OR protocol LIKE ?
                    OR decoded_fields_json LIKE ?
                    OR raw_summary LIKE ?
                  )
                ORDER BY packet_index ASC
                LIMIT ? OFFSET ?
                """,
                (*filter_params, limit, offset),
            ).fetchall()

        items = [self._row_to_dict(r) for r in rows]
        return {
            "analysis_id": analysis_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "packets": items,
        }

    def get_packet(
        self,
        db: DatabaseManager,
        analysis_id: str,
        packet_index: int,
    ) -> dict[str, Any] | None:
        """Return a single packet's full decoded forensic metadata."""
        with db.connection() as conn:
            row = conn.execute(
                """
                SELECT packet_index, timestamp_epoch, timestamp_utc, src_ip, dst_ip,
                       src_port, dst_port, protocol, transport_protocol, length,
                       ttl, ip_version, flow_id, alert_ids_json, decoded_fields_json,
                       raw_summary
                FROM packets
                WHERE analysis_id = ? AND packet_index = ?
                """,
                (analysis_id, packet_index),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        return {
            "packet_number": row["packet_index"],
            "packet_index": row["packet_index"],
            "timestamp": row["timestamp_epoch"],
            "timestamp_utc": row["timestamp_utc"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "protocol": row["protocol"],
            "transport_protocol": row["transport_protocol"],
            "length": row["length"],
            "ttl": row["ttl"],
            "ip_version": row["ip_version"],
            "flow_id": row["flow_id"],
            "alert_ids": json.loads(row["alert_ids_json"]),
            "decoded_fields": json.loads(row["decoded_fields_json"]),
            "raw_summary": row["raw_summary"],
        }
