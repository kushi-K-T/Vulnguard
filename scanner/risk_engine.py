class RiskEngine:
    """Calculates an educational risk score based on finding severities."""

    DEDUCTIONS = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 7.0,
        "Low": 2.0,
        "Informational": 0.0
    }

    @classmethod
    def calculate_score(cls, findings: list[dict]) -> dict:
        total_deduction = 0.0
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for finding in findings:
            sev = finding.get("severity", "Informational")
            if sev in counts:
                counts[sev] += 1
                total_deduction += cls.DEDUCTIONS.get(sev, 0.0)

        final_score = max(0.0, min(100.0, 100.0 - total_deduction))
        
        return {
            "score": round(final_score, 1),
            "counts": counts,
            "grade": cls._get_grade(final_score)
        }

    @staticmethod
    def _get_grade(score: float) -> str:
        if score >= 90: return "A (Strong Security Posture)"
        if score >= 75: return "B (Moderate Risks Present)"
        if score >= 50: return "C (Significant Remediations Needed)"
        return "F (Critical Exposures Detected)"
