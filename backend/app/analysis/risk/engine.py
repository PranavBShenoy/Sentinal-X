"""
Deterministic and Explainable Risk Scoring Engine.

Computes mathematically grounded, transparent risk scores (0.0 - 10.0 scale)
for individual findings and whole assessments without delegating calculations to an LLM.
Produces human-readable rationale statements based strictly on available evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.core.database import db_session
from app.core.logging import get_logger
from app.models import (
    Assessment,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    SbomComponent,
)

logger = get_logger(__name__)


class RiskEngine:
    """Calculates explainable risk scores and rationales."""

    # Base severity mapping
    SEVERITY_BASE_SCORES: Dict[FindingSeverity, float] = {
        FindingSeverity.CRITICAL: 9.0,
        FindingSeverity.HIGH: 7.0,
        FindingSeverity.MEDIUM: 5.0,
        FindingSeverity.LOW: 3.0,
        FindingSeverity.INFO: 1.0,
        FindingSeverity.UNKNOWN: 4.0,
    }

    # Confidence multipliers
    CONFIDENCE_WEIGHTS: Dict[ConfidenceLevel, float] = {
        ConfidenceLevel.HIGH: 1.0,
        ConfidenceLevel.MEDIUM: 0.9,
        ConfidenceLevel.LOW: 0.75,
        ConfidenceLevel.UNKNOWN: 0.6,
    }

    def score_finding(self, finding: Finding, is_direct_dep: Optional[bool] = None) -> Tuple[float, str]:
        """
        Calculate a deterministic risk score (0.0 - 10.0) and generate an evidence-grounded rationale.

        Returns (score, rationale_text).
        """
        # 1. Base score from CVSS or scanner severity
        if finding.cvss_score is not None and 0.0 <= finding.cvss_score <= 10.0:
            base_score = float(finding.cvss_score)
            base_source = f"CVSS v3 base score ({finding.cvss_score})"
        else:
            base_score = self.SEVERITY_BASE_SCORES.get(finding.severity, 5.0)
            base_source = f"nominal {finding.severity.value} severity baseline ({base_score})"

        multipliers: List[Tuple[str, float]] = []

        # 2. Category-specific context
        if finding.category == FindingCategory.SECRET:
            multipliers.append(("Exposed plaintext secret in repository source", 1.25))

        # 3. Direct vs Transitive Dependency
        if finding.category == FindingCategory.DEPENDENCY:
            if is_direct_dep is True:
                multipliers.append(("Direct application dependency", 1.0))
            elif is_direct_dep is False:
                multipliers.append(("Transitive dependency (reduced surface)", 0.8))

        # 4. Runtime / DAST confirmation
        if finding.category == FindingCategory.DAST:
            multipliers.append(("Confirmed via dynamic testing on running endpoint", 1.15))

        # 5. Fix availability
        if finding.fixed_version:
            multipliers.append((f"Actionable remediation fix available ({finding.fixed_version})", 0.95))

        # 6. Confidence weighting
        conf_weight = self.CONFIDENCE_WEIGHTS.get(finding.confidence, 0.8)

        # Compute product
        total_multiplier = 1.0
        for _, factor in multipliers:
            total_multiplier *= factor

        raw_score = base_score * total_multiplier * conf_weight
        final_score = min(10.0, max(0.1, round(raw_score, 1)))

        # 7. Generate human-readable rationale
        reasons_text = "; ".join(desc for desc, _ in multipliers) if multipliers else "Standard baseline evaluation"
        rationale = (
            f"Risk score {final_score}/10 derived from {base_source}. "
            f"Factors evaluated: {reasons_text}. "
            f"Confidence multiplier: {conf_weight} ({finding.confidence.value} confidence)."
        )

        return final_score, rationale

    def score_all(self, assessment_id: str) -> Dict[str, Any]:
        """Score all findings and calculate aggregate assessment risk level."""
        with db_session() as db:
            assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            if not assessment:
                return {"error": "Assessment not found"}

            findings = (
                db.query(Finding)
                .filter(Finding.assessment_id == assessment_id)
                .all()
            )

            # Map package names to is_direct flag
            components = (
                db.query(SbomComponent)
                .filter(SbomComponent.assessment_id == assessment_id)
                .all()
            )
            direct_map = {c.name.lower(): c.is_direct for c in components if c.name}

            scores: List[float] = []
            for f in findings:
                is_dir = direct_map.get(f.component.lower()) if f.component else None
                score, rationale = self.score_finding(f, is_direct_dep=is_dir)
                f.risk_score = score
                f.risk_rationale = rationale
                scores.append(score)

            # Overall assessment risk score:
            # Weighted average heavily favoring highest critical risks
            if not scores:
                overall_score = 0.0
                risk_level = "MINIMAL"
            else:
                sorted_scores = sorted(scores, reverse=True)
                top_scores = sorted_scores[:5]
                # Peak risk with diminishing weight for lower items
                weights = [0.4, 0.25, 0.15, 0.1, 0.1][:len(top_scores)]
                norm_weights = [w / sum(weights) for w in weights]
                overall_score = round(sum(s * w for s, w in zip(top_scores, norm_weights)), 1)

                if overall_score >= 8.5:
                    risk_level = "CRITICAL"
                elif overall_score >= 6.5:
                    risk_level = "HIGH"
                elif overall_score >= 4.0:
                    risk_level = "MEDIUM"
                elif overall_score >= 1.0:
                    risk_level = "LOW"
                else:
                    risk_level = "MINIMAL"

            assessment.risk_score = overall_score
            assessment.risk_level = risk_level

            return {
                "assessment_id": assessment_id,
                "overall_risk_score": overall_score,
                "risk_level": risk_level,
                "findings_scored": len(findings),
            }
