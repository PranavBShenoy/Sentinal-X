"""
Security Report Generation Engine.

Produces:
1. Standard JSON report (comprehensive, structured assessment data)
2. OASIS SARIF 2.1.0 standard export (compatible with GitHub Code Scanning, VS Code, CI)
3. CSV findings summary
4. Professional PDF report (rendered via HTML/WeasyPrint)

Enforces secret redaction: passwords, tokens, and raw keys are never placed in report exports.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.core.secret_redactor import redact
from app.models import (
    Assessment,
    Finding,
    Report,
    RuntimeEnvironment,
    SbomArtifact,
    ScanJob,
)

logger = get_logger(__name__)
settings = get_settings()


class ReportGenerator:
    """Generates standardized security assessment reports in multiple formats."""

    def __init__(self, output_dir: Optional[str] = None) -> None:
        self.output_dir = Path(output_dir or f"{settings.ASSESSMENT_WORKSPACE_BASE}/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, assessment_id: str, format: str = "json") -> Dict[str, Any]:
        """Generate report in requested format (json, sarif, csv, pdf)."""
        data = self._gather_report_data(assessment_id)
        fmt = format.lower()

        if fmt == "json":
            file_path = self._generate_json(data, assessment_id)
        elif fmt == "sarif":
            file_path = self._generate_sarif(data, assessment_id)
        elif fmt == "csv":
            file_path = self._generate_csv(data, assessment_id)
        elif fmt == "pdf":
            file_path = self._generate_pdf(data, assessment_id)
        else:
            raise ValueError(f"Unsupported report format: {format}")

        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        # Persist report record in DB
        with db_session() as db:
            assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            user_id = assessment.created_by_id if assessment else "system"

            report = Report(
                assessment_id=assessment_id,
                generated_by_id=user_id,
                format=fmt,
                file_path=str(file_path),
                file_size_bytes=file_size,
            )
            db.add(report)
            db.flush()
            report_id = str(report.id)

        return {
            "report_id": report_id,
            "assessment_id": assessment_id,
            "format": fmt,
            "file_path": str(file_path),
            "file_size_bytes": file_size,
        }

    def _gather_report_data(self, assessment_id: str) -> Dict[str, Any]:
        """Collect all assessment data, finding details, and runtime information."""
        with db_session() as db:
            assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            if not assessment:
                raise ValueError(f"Assessment {assessment_id} not found")

            findings = (
                db.query(Finding)
                .filter(Finding.assessment_id == assessment_id)
                .order_by(Finding.risk_score.desc().nullslast())
                .all()
            )

            jobs = (
                db.query(ScanJob)
                .filter(ScanJob.assessment_id == assessment_id)
                .all()
            )

            runtime = (
                db.query(RuntimeEnvironment)
                .filter(RuntimeEnvironment.assessment_id == assessment_id)
                .first()
            )

            sboms = (
                db.query(SbomArtifact)
                .filter(SbomArtifact.assessment_id == assessment_id)
                .all()
            )

            repo_name = assessment.repository.full_name if assessment.repository else "Unknown"

            # Severity counts
            sev_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            for f in findings:
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

            # Checks coverage
            checks = []
            for j in jobs:
                checks.append({
                    "tool": j.tool_name,
                    "status": j.status.value,
                    "check_status": j.check_status.value if j.check_status else None,
                    "tool_version": j.tool_version,
                    "findings_count": j.findings_count,
                    "error_message": j.error_message,
                })

            serialized_findings = []
            for f in findings:
                serialized_findings.append({
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "category": f.category.value,
                    "subcategory": f.subcategory,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "confidence": f.confidence.value,
                    "source_tool": f.source_tool,
                    "rule_id": f.rule_id,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "endpoint": f.endpoint,
                    "component": f.component,
                    "cve_ids": f.cve_ids or [],
                    "cvss_score": f.cvss_score,
                    "affected_version": f.affected_version,
                    "fixed_version": f.fixed_version,
                    "risk_score": f.risk_score,
                    "risk_rationale": f.risk_rationale,
                    "ai_explanation": f.ai_explanation,
                    "ai_impact": f.ai_impact,
                    "ai_remediation_steps": f.ai_remediation_steps or [],
                    "code_snippet": redact(f.code_snippet) if f.code_snippet else None,
                })

            return {
                "platform": "SENTINEL-X AI Security Assessment Platform",
                "assessment_id": assessment_id,
                "repository": repo_name,
                "commit_sha": assessment.commit_sha,
                "branch": assessment.branch,
                "target_url": assessment.target_url,
                "status": assessment.status.value,
                "risk_score": assessment.risk_score,
                "risk_level": assessment.risk_level,
                "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
                "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
                "severity_counts": sev_counts,
                "total_findings": len(findings),
                "checks_coverage": checks,
                "sbom_artifacts_count": len(sboms),
                "runtime": {
                    "status": runtime.status.value if runtime else "NOT_ATTEMPTED",
                    "target_url": runtime.target_url if runtime else None,
                    "adapter": runtime.adapter_type if runtime else None,
                    "health_check_passed": runtime.health_check_passed if runtime else None,
                },
                "findings": serialized_findings,
            }

    def _generate_json(self, data: Dict[str, Any], assessment_id: str) -> Path:
        """Write JSON report file."""
        out_path = self.output_dir / f"sentinelx_report_{assessment_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return out_path

    def _generate_sarif(self, data: Dict[str, Any], assessment_id: str) -> Path:
        """Generate OASIS SARIF 2.1.0 standard format."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for f in data.get("findings", []):
            rule_id = f.get("rule_id") or "SENTINELX-FINDING"
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f.get("title", ""),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "defaultConfiguration": {
                        "level": self._map_sarif_level(f.get("severity", "MEDIUM"))
                    },
                }

            loc = {}
            if f.get("file_path"):
                loc = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file_path"]},
                        "region": {
                            "startLine": f.get("line_start") or 1,
                            "endLine": f.get("line_end") or 1,
                        },
                    }
                }

            sarif_results.append({
                "ruleId": rule_id,
                "level": self._map_sarif_level(f.get("severity", "MEDIUM")),
                "message": {"text": f.get("description") or f.get("title", "")},
                "locations": [loc] if loc else [],
            })

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SENTINEL-X",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/SENTINEL-X",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        out_path = self.output_dir / f"sentinelx_report_{assessment_id}.sarif"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(sarif_payload, f, indent=2)
        return out_path

    def _generate_csv(self, data: Dict[str, Any], assessment_id: str) -> Path:
        """Write findings summary in CSV format."""
        out_path = self.output_dir / f"sentinelx_findings_{assessment_id}.csv"
        fields = [
            "id",
            "title",
            "category",
            "severity",
            "status",
            "risk_score",
            "source_tool",
            "rule_id",
            "file_path",
            "line_start",
            "component",
            "affected_version",
            "fixed_version",
            "cve_ids",
        ]

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for finding in data.get("findings", []):
                row = {k: finding.get(k) for k in fields}
                if isinstance(row["cve_ids"], list):
                    row["cve_ids"] = ";".join(row["cve_ids"])
                writer.writerow(row)

        return out_path

    def _generate_pdf(self, data: Dict[str, Any], assessment_id: str) -> Path:
        """Generate PDF report using WeasyPrint if available, or HTML fallback."""
        html_content = self._render_html_report(data)
        out_pdf_path = self.output_dir / f"sentinelx_report_{assessment_id}.pdf"
        out_html_path = self.output_dir / f"sentinelx_report_{assessment_id}.html"

        # Save HTML file
        with open(out_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Attempt WeasyPrint conversion
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(str(out_pdf_path))
            return out_pdf_path
        except Exception as e:
            logger.warning("WeasyPrint conversion failed, using HTML report", error=str(e))
            return out_html_path

    def _render_html_report(self, data: Dict[str, Any]) -> str:
        """Render high-contrast, professional cybersecurity report HTML."""
        findings_rows = ""
        for f in data.get("findings", []):
            sev = f.get("severity", "INFO")
            color = "#ef4444" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#eab308" if sev == "MEDIUM" else "#3b82f6"
            findings_rows += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; font-weight: bold; color: {color};">{sev}</td>
                <td style="padding: 10px; font-weight: 600;">{f.get('title')}</td>
                <td style="padding: 10px; color: #94a3b8;">{f.get('source_tool')}</td>
                <td style="padding: 10px; font-family: monospace;">{f.get('file_path') or f.get('endpoint') or 'N/A'}:{f.get('line_start') or ''}</td>
                <td style="padding: 10px; font-weight: bold;">{f.get('risk_score', 'N/A')}</td>
            </tr>
            """

        checks_rows = ""
        for c in data.get("checks_coverage", []):
            st = c.get("check_status") or c.get("status")
            st_color = "#10b981" if st == "PASSED" else "#ef4444" if st == "FAILED" else "#f59e0b"
            checks_rows += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 8px; font-weight: 600;">{c.get('tool')}</td>
                <td style="padding: 8px; font-weight: bold; color: {st_color};">{st}</td>
                <td style="padding: 8px;">{c.get('findings_count', 0)}</td>
                <td style="padding: 8px; color: #94a3b8;">{c.get('tool_version') or 'N/A'}</td>
            </tr>
            """

        counts = data.get("severity_counts", {})
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SENTINEL-X Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: bold; display: inline-block; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #0f172a; padding: 10px; color: #94a3b8; border-bottom: 2px solid #334155; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SENTINEL-X SECURITY ASSESSMENT</h1>
        <p style="color: #94a3b8;">AI-Powered Application & Software Supply-Chain Security Assessment</p>
        <p><strong>Target Repository:</strong> {data.get('repository')} | <strong>Commit SHA:</strong> {data.get('commit_sha') or 'N/A'} | <strong>Status:</strong> {data.get('status')}</p>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <p>Overall Assessment Risk Score: <strong style="font-size: 20px; color: #38bdf8;">{data.get('risk_score', '0.0')}/10 ({data.get('risk_level', 'MINIMAL')})</strong></p>
        <p>
            <span class="badge" style="background: #ef4444; color: white;">Critical: {counts.get('CRITICAL', 0)}</span>
            <span class="badge" style="background: #f97316; color: white;">High: {counts.get('HIGH', 0)}</span>
            <span class="badge" style="background: #eab308; color: black;">Medium: {counts.get('MEDIUM', 0)}</span>
            <span class="badge" style="background: #3b82f6; color: white;">Low: {counts.get('LOW', 0)}</span>
            <span class="badge" style="background: #64748b; color: white;">Info: {counts.get('INFO', 0)}</span>
        </p>
    </div>

    <div class="card">
        <h2>Security Checks & Scanner Execution Coverage</h2>
        <table>
            <thead>
                <tr>
                    <th>Security Check / Tool</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {checks_rows}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Detailed Security Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Finding Title</th>
                    <th>Source Tool</th>
                    <th>Location</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows if findings_rows else '<tr><td colspan="5" style="padding: 15px; text-align: center; color: #94a3b8;">No security findings detected.</td></tr>'}
            </tbody>
        </table>
    </div>

    <div style="margin-top: 40px; font-size: 12px; color: #64748b; text-align: center;">
        <p>Generated by SENTINEL-X. This assessment report is grounded strictly in executed scanner and dynamic testing evidence. Clean scans do not prove absolute absence of zero-day vulnerabilities.</p>
    </div>
</body>
</html>
"""

    def _map_sarif_level(self, severity: str) -> str:
        sev = severity.upper()
        if sev in ("CRITICAL", "HIGH"):
            return "error"
        elif sev == "MEDIUM":
            return "warning"
        else:
            return "note"
