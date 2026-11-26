"""Configurable YAML detection rule loader, validator, and evaluator."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from app.core.logging import get_logger
from app.models.detection import DetectionContext, DetectionFinding
from app.models.flow import NetworkFlow
from app.models.packet import NormalizedPacket
from app.utils.entropy import shannon_entropy
from app.utils.network import is_external_ip
from app.utils.network import is_raw_ip_host as _is_raw_ip

logger = get_logger("detectors.rule_engine")

SUPPORTED_PROTOCOLS = {"HTTP", "DNS", "TLS", "TCP", "UDP", "ICMP", "FLOW", "ANY"}
SUPPORTED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


class DetectionRuleSchema(BaseModel):
    """Validated schema for an individual YAML detection rule."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    enabled: bool = True
    protocol: str = "ANY"
    operator: Literal["AND", "OR"] = "AND"
    condition: dict[str, Any] = Field(default_factory=dict)
    severity: str = "MEDIUM"
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    mitre_id: str | None = None
    mitre_ids: list[str] = Field(default_factory=list)
    description: str = Field(min_length=1)
    recommended_steps: list[str] = Field(default_factory=list)

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in SUPPORTED_PROTOCOLS:
            raise ValueError(
                f"Unsupported protocol {value!r}; expected one of {sorted(SUPPORTED_PROTOCOLS)}"
            )
        return upper

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in SUPPORTED_SEVERITIES:
            raise ValueError(
                f"Unsupported severity {value!r}; expected one of {sorted(SUPPORTED_SEVERITIES)}"
            )
        return upper

    @field_validator("operator", mode="before")
    @classmethod
    def normalize_operator(cls, value: Any) -> str:
        if isinstance(value, str):
            return value.strip().upper()
        return str(value)

    def resolved_mitre_ids(self) -> list[str]:
        ids = list(self.mitre_ids)
        if self.mitre_id and self.mitre_id not in ids:
            ids.insert(0, self.mitre_id)
        return ids


@dataclass(slots=True)
class RuleLoadResult:
    """Result of parsing and validating a YAML rules file."""

    version: str
    rules: list[DetectionRuleSchema] = field(default_factory=list)
    disabled_count: int = 0
    errors: list[str] = field(default_factory=list)


class YamlRuleEngine:
    """Load, validate, and evaluate YAML-defined detection rules safely."""

    def load_rules(self, rules_path: Path) -> RuleLoadResult:
        """Load rules from YAML without crashing on malformed files or individual rules."""
        if not rules_path.is_file():
            return RuleLoadResult(
                version="0.0",
                errors=[f"Rules file not found: {rules_path}"],
            )

        try:
            raw_text = rules_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw_text)
        except (OSError, yaml.YAMLError) as exc:
            msg = f"Failed to parse YAML rules file {rules_path.name}: {exc}"
            logger.error(msg)
            return RuleLoadResult(version="0.0", errors=[msg])

        if not isinstance(parsed, dict) or not isinstance(parsed.get("rules"), list):
            msg = f"Invalid rules structure in {rules_path.name}: top-level 'rules' list required."
            logger.error(msg)
            return RuleLoadResult(version="0.0", errors=[msg])

        version = str(parsed.get("version", "1.0"))
        valid_rules: list[DetectionRuleSchema] = []
        errors: list[str] = []
        disabled_count = 0

        for idx, raw_rule in enumerate(parsed["rules"]):
            if not isinstance(raw_rule, dict):
                errors.append(f"Rule entry #{idx} is not a mapping object.")
                continue
            try:
                rule = DetectionRuleSchema.model_validate(raw_rule)
            except ValidationError as exc:
                rule_ref = raw_rule.get("id", f"index#{idx}")
                err_msg = f"Invalid rule {rule_ref}: {exc.errors()[0]['msg']}"
                logger.warning(err_msg)
                errors.append(err_msg)
                continue

            if not rule.enabled:
                disabled_count += 1
            valid_rules.append(rule)

        return RuleLoadResult(
            version=version,
            rules=valid_rules,
            disabled_count=disabled_count,
            errors=errors,
        )

    def evaluate(
        self,
        context: DetectionContext,
        rules_path: Path | None = None,
        loaded_rules: list[DetectionRuleSchema] | None = None,
    ) -> list[DetectionFinding]:
        """Evaluate enabled YAML rules against packets and flows in DetectionContext."""
        if loaded_rules is None:
            if rules_path is None:
                return []
            load_result = self.load_rules(rules_path)
            rules = load_result.rules
        else:
            rules = loaded_rules

        findings: list[DetectionFinding] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if not rule.condition:
                continue
            findings.extend(self._evaluate_rule(rule, context))

        findings.sort(key=lambda f: (f.timestamp_epoch, f.rule_id or ""))
        return findings

    def _evaluate_rule(
        self,
        rule: DetectionRuleSchema,
        context: DetectionContext,
    ) -> list[DetectionFinding]:
        if rule.protocol == "FLOW":
            return self._evaluate_flow_rule(rule, context.flows)
        if rule.protocol in {"HTTP", "DNS", "TLS", "ICMP"}:
            return self._evaluate_packet_rule(rule, context)
        # TCP / UDP / ANY: evaluate flows first if condition has flow keys, else packets
        if any(
            k in rule.condition
            for k in (
                "min_outbound_bytes",
                "min_inbound_bytes",
                "min_total_bytes",
                "min_outbound_ratio",
                "min_duration_seconds",
                "min_packets",
                "connection_state",
            )
        ):
            return self._evaluate_flow_rule(rule, context.flows)
        return self._evaluate_packet_rule(rule, context)

    def _evaluate_packet_rule(
        self,
        rule: DetectionRuleSchema,
        context: DetectionContext,
    ) -> list[DetectionFinding]:
        pkt_flow_map = dict(context.packet_flow_map)
        if not pkt_flow_map:
            for flow in context.flows:
                for pidx in flow.packet_indices:
                    pkt_flow_map.setdefault(pidx, flow.flow_id)
        flow_by_id = {flow.flow_id: flow for flow in context.flows}

        matched_groups: dict[tuple[str | None, str | None, int | None], list[NormalizedPacket]] = (
            defaultdict(list)
        )
        for pkt in context.packets:
            if not self._packet_matches_protocol(pkt, rule.protocol):
                continue
            attrs = self._packet_attributes(pkt)
            if self._eval_condition_tree(rule.condition, rule.operator, attrs):
                matched_groups[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)

        findings: list[DetectionFinding] = []
        for (src_ip, dst_ip, dst_port), pkts in sorted(matched_groups.items()):
            earliest = min(pkts, key=lambda p: p.timestamp)
            matched_fids = sorted(
                {pkt_flow_map[p.packet_index] for p in pkts if p.packet_index in pkt_flow_map}
            )
            primary_flow_id = matched_fids[0] if len(matched_fids) == 1 else None
            det_hash = hashlib.sha256(
                f"yaml:{rule.id}:{src_ip}:{dst_ip}:{dst_port}".encode()
            ).hexdigest()[:12]
            steps = rule.recommended_steps or [
                f"Validate traffic matching {rule.id} ({rule.name}) from {src_ip} to {dst_ip}."
            ]
            evidence_dict: dict[str, Any] = {
                "rule_id": rule.id,
                "matched_packet_count": len(pkts),
                "condition": rule.condition,
                "operator": rule.operator,
                "flow_ids": matched_fids,
                "sample_packet_indices": [p.packet_index for p in pkts[:15]],
                "sample_attributes": self._packet_attributes(earliest),
            }
            explanation = f"[{rule.id}] {rule.description}"
            if rule.protocol == "HTTP":
                declared_http_bytes = sum(
                    max(p.http.payload_size, p.http.content_length or 0)
                    for p in pkts
                    if p.http
                )
                captured_http_bytes = sum(p.http.payload_size for p in pkts if p.http)
                flow_wire_out = sum(
                    flow_by_id[fid].bytes_initiator_to_responder
                    for fid in matched_fids
                    if fid in flow_by_id
                )
                evidence_dict["http_declared_body_bytes"] = declared_http_bytes
                evidence_dict["http_captured_body_bytes"] = captured_http_bytes
                evidence_dict["flow_observed_outbound_bytes"] = flow_wire_out
                explanation = (
                    f"[{rule.id}] {rule.description} Matched {len(pkts)} HTTP packet(s) "
                    f"(HTTP body declared={declared_http_bytes:,} B, captured segment payload="
                    f"{captured_http_bytes:,} B; "
                    f"flow-observed network outbound={flow_wire_out:,} B)."
                )
            findings.append(
                DetectionFinding(
                    detection_id=f"det-rule-{det_hash}",
                    detection_name=rule.name,
                    detector_type="yaml_rule",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    timestamp=earliest.timestamp_utc,
                    timestamp_epoch=earliest.timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=earliest.src_port,
                    destination_port=dst_port,
                    protocol=earliest.protocol,
                    flow_id=primary_flow_id,
                    rule_id=rule.id,
                    packet_indices=[p.packet_index for p in pkts[:200]],
                    evidence=evidence_dict,
                    explanation=explanation,
                    recommended_investigation_steps=steps,
                    candidate_mitre_ids=rule.resolved_mitre_ids(),
                )
            )
        return findings

    def _evaluate_flow_rule(
        self,
        rule: DetectionRuleSchema,
        flows: list[NetworkFlow],
    ) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for flow in flows:
            if rule.protocol in {"TCP", "UDP"} and flow.transport_protocol != rule.protocol:
                continue
            attrs = self._flow_attributes(flow)
            if not self._eval_condition_tree(rule.condition, rule.operator, attrs):
                continue
            det_hash = hashlib.sha256(
                f"yamlflow:{rule.id}:{flow.flow_id}".encode()
            ).hexdigest()[:12]
            steps = rule.recommended_steps or [
                f"Investigate flow {flow.flow_id} matching {rule.id} ({rule.name})."
            ]
            findings.append(
                DetectionFinding(
                    detection_id=f"det-rule-{det_hash}",
                    detection_name=rule.name,
                    detector_type="yaml_rule",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    timestamp=flow.first_seen_utc,
                    timestamp_epoch=flow.first_seen,
                    source_ip=flow.initiator_ip,
                    destination_ip=flow.responder_ip,
                    source_port=flow.initiator_port,
                    destination_port=flow.responder_port,
                    protocol=flow.application_protocol,
                    flow_id=flow.flow_id,
                    rule_id=rule.id,
                    packet_indices=list(flow.packet_indices[:200]),
                    evidence={
                        "rule_id": rule.id,
                        "flow_id": flow.flow_id,
                        "condition": rule.condition,
                        "operator": rule.operator,
                        "flow_metrics": attrs,
                        "packet_indices": list(flow.packet_indices[:100]),
                    },
                    explanation=f"[{rule.id}] {rule.description}",
                    recommended_investigation_steps=steps,
                    candidate_mitre_ids=rule.resolved_mitre_ids(),
                )
            )
        return findings

    def _packet_matches_protocol(self, pkt: NormalizedPacket, rule_protocol: str) -> bool:
        if rule_protocol == "ANY":
            return True
        if rule_protocol == "HTTP":
            return pkt.http is not None
        if rule_protocol == "DNS":
            return pkt.dns is not None
        if rule_protocol == "TLS":
            return pkt.tls is not None or pkt.protocol == "TLS"
        if rule_protocol in {"TCP", "UDP", "ICMP"}:
            return pkt.transport_protocol == rule_protocol or pkt.protocol == rule_protocol
        return pkt.protocol == rule_protocol

    def _packet_attributes(self, pkt: NormalizedPacket) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "protocol": pkt.protocol,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "packet_length": pkt.length,
            "external_destination": is_external_ip(pkt.dst_ip),
        }
        if pkt.http is not None:
            observed_body = max(pkt.http.payload_size, pkt.http.content_length or 0)
            attrs.update(
                {
                    "is_request": pkt.http.is_request,
                    "method": pkt.http.method,
                    "host": pkt.http.host,
                    "uri": pkt.http.uri,
                    "user_agent": pkt.http.user_agent,
                    "payload_bytes": observed_body,
                    "content_length": pkt.http.content_length,
                    "direction": pkt.http.direction,
                    "raw_ip_host": _is_raw_ip(pkt.http.host),
                }
            )
        if pkt.dns is not None:
            sub_str = ".".join(pkt.dns.subdomain_labels)
            attrs.update(
                {
                    "is_response": pkt.dns.is_response,
                    "query_name": pkt.dns.query_name,
                    "query_type": pkt.dns.query_type,
                    "response_code": pkt.dns.response_code,
                    "query_length": pkt.dns.query_length,
                    "subdomain_length": pkt.dns.subdomain_length,
                    "entropy": shannon_entropy(sub_str or (pkt.dns.query_name or "")),
                }
            )
        if pkt.tls is not None:
            attrs.update(
                {
                    "sni": pkt.tls.sni,
                    "sni_present": bool(pkt.tls.sni),
                    "handshake_version": pkt.tls.handshake_version,
                }
            )
        return attrs

    def _flow_attributes(self, flow: NetworkFlow) -> dict[str, Any]:
        return {
            "protocol": flow.application_protocol,
            "src_ip": flow.initiator_ip,
            "dst_ip": flow.responder_ip,
            "src_port": flow.initiator_port,
            "dst_port": flow.responder_port,
            "direction": flow.direction,
            "external_destination": is_external_ip(flow.responder_ip),
            "outbound_bytes": flow.bytes_initiator_to_responder,
            "inbound_bytes": flow.bytes_responder_to_initiator,
            "total_bytes": flow.total_bytes,
            "outbound_ratio": flow.outbound_to_inbound_ratio or 0.0,
            "duration_seconds": flow.duration_seconds,
            "packets": flow.total_packets,
            "connection_state": flow.connection_state,
        }

    def _eval_condition_tree(
        self,
        condition: dict[str, Any],
        operator: str,
        attrs: dict[str, Any],
    ) -> bool:
        if "all" in condition and isinstance(condition["all"], list):
            return all(
                self._eval_condition_tree(sub, "AND", attrs)
                for sub in condition["all"]
                if isinstance(sub, dict)
            )
        if "any" in condition and isinstance(condition["any"], list):
            return any(
                self._eval_condition_tree(sub, "AND", attrs)
                for sub in condition["any"]
                if isinstance(sub, dict)
            )

        if not condition:
            return False

        results = [
            self._eval_clause(key, expected, attrs)
            for key, expected in condition.items()
        ]
        return all(results) if operator == "AND" else any(results)

    def _eval_clause(self, key: str, expected: Any, attrs: dict[str, Any]) -> bool:
        # Threshold comparisons
        min_map = {
            "min_payload_bytes": "payload_bytes",
            "min_content_length": "content_length",
            "min_query_length": "query_length",
            "min_subdomain_length": "subdomain_length",
            "min_entropy": "entropy",
            "min_packet_length": "packet_length",
            "min_outbound_bytes": "outbound_bytes",
            "min_inbound_bytes": "inbound_bytes",
            "min_total_bytes": "total_bytes",
            "min_outbound_ratio": "outbound_ratio",
            "min_duration_seconds": "duration_seconds",
            "min_packets": "packets",
        }
        max_map = {
            "max_payload_bytes": "payload_bytes",
            "max_query_length": "query_length",
            "max_entropy": "entropy",
        }
        if key in min_map:
            val = attrs.get(min_map[key])
            return val is not None and float(val) >= float(expected)
        if key in max_map:
            val = attrs.get(max_map[key])
            return val is not None and float(val) <= float(expected)

        # Membership & exclusion clauses
        if key == "dst_ports" and isinstance(expected, list):
            return attrs.get("dst_port") in expected
        if key == "excluded_dst_ports" and isinstance(expected, list):
            port = attrs.get("dst_port")
            return port is not None and port not in expected
        if key == "uri_contains":
            uri = str(attrs.get("uri") or "").lower()
            return str(expected).lower() in uri
        if key == "user_agent_contains":
            ua = str(attrs.get("user_agent") or "").lower()
            return str(expected).lower() in ua
        if key == "domain_contains":
            qname = str(attrs.get("query_name") or "").lower()
            return str(expected).lower() in qname
        if key == "sni_contains":
            sni = str(attrs.get("sni") or "").lower()
            return str(expected).lower() in sni

        # Direct equality / list-of-values match (case-insensitive for strings)
        actual = attrs.get(key)
        if isinstance(expected, list):
            return any(self._scalar_equal(actual, item) for item in expected)
        return self._scalar_equal(actual, expected)

    def _scalar_equal(self, actual: Any, expected: Any) -> bool:
        if actual is None:
            return False
        if isinstance(expected, bool):
            return bool(actual) is expected
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.strip().lower() == expected.strip().lower()
        return bool(actual == expected)
