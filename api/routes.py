from flask import Blueprint, jsonify, request, send_file
import requests
import os
from datetime import datetime

from database.models import db, Target, Scan, Finding
from scanner.target_validator import TargetValidator
from scanner.port_scanner import PortScanner
from scanner.header_scanner import HeaderScanner
from scanner.cookie_scanner import CookieScanner
from scanner.tls_scanner import TLSScanner
from scanner.owasp_checks import SafeOWASPScanner
from scanner.risk_engine import RiskEngine
from reports.pdf_generator import SecurityReportGenerator

api_bp = Blueprint("api", __name__)

@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "engine": "VulnGuard v1.0.0"})

@api_bp.route("/targets", methods=["GET", "POST"])
def manage_targets():
    if request.method == "POST":
        data = request.get_json() or {}
        name = data.get("name", "Lab Target").strip()
        url_or_ip = data.get("url_or_ip", "").strip()

        is_safe, msg = TargetValidator.is_safe_target(url_or_ip)
        if not is_safe:
            return jsonify({"error": "Target validation rejected", "details": msg}), 400

        # Check if target already exists; reuse if present
        existing_target = Target.query.filter_by(url_or_ip=url_or_ip).first()
        if existing_target:
            if name and existing_target.name != name:
                existing_target.name = name
                db.session.commit()
            return jsonify({
                "message": "Target verified (existing)",
                "target_id": existing_target.id,
                "validation": msg
            }), 200

        target = Target(name=name, url_or_ip=url_or_ip, target_type=data.get("target_type", "Web App"))
        db.session.add(target)
        db.session.commit()
        return jsonify({
            "message": "Target added",
            "target_id": target.id,
            "validation": msg
        }), 201

    targets = Target.query.all()
    return jsonify([{"id": t.id, "name": t.name, "url": t.url_or_ip, "type": t.target_type} for t in targets])

@api_bp.route("/scans", methods=["POST"])
def execute_scan():
    data = request.get_json() or {}
    target_id = data.get("target_id")
    target = Target.query.get_or_404(target_id)

    is_safe, _ = TargetValidator.is_safe_target(target.url_or_ip)
    if not is_safe:
        return jsonify({"error": "Unauthorized target host detected"}), 403

    target_url = target.url_or_ip if "://" in target.url_or_ip else f"http://{target.url_or_ip}"
    all_findings = []

    # 1. Port Discovery
    open_ports = PortScanner.scan_host(target_url)
    all_findings.extend(open_ports)

    # 2. HTTP Security & Headers
    try:
        resp = requests.get(target_url, timeout=3.0, verify=False)
        all_findings.extend(HeaderScanner.scan(target_url, resp))
        all_findings.extend(CookieScanner.scan(target_url, resp))
        all_findings.extend(SafeOWASPScanner.scan_debug_indicators(resp))
    except Exception as e:
        all_findings.append({
            "id": "CONN-ERR",
            "title": "HTTP Connection Inactive or Blocked",
            "category": "Availability",
            "severity": "Informational",
            "evidence": str(e),
            "description": "Standard HTTP requests could not be completed.",
            "impact": "Web analysis routines were bypassed.",
            "recommendation": "Ensure target laboratory service is listening.",
            "status": "Open"
        })

    # 3. TLS & OWASP Path Misconfigurations
    all_findings.extend(TLSScanner.scan(target_url))
    all_findings.extend(SafeOWASPScanner.scan_misconfigurations(target_url))

    # 4. Risk Engine Calculation
    risk_summary = RiskEngine.calculate_score(all_findings)

    scan = Scan(target_id=target.id, security_score=risk_summary["score"], status="Completed")
    db.session.add(scan)
    db.session.flush()

    for idx, f in enumerate(all_findings):
        db_finding = Finding(
            scan_id=scan.id,
            finding_id=f.get("id", f"VULN-{idx+1:03d}"),
            title=f.get("title", "Detected Issue"),
            category=f.get("category", "General"),
            severity=f.get("severity", "Low"),
            evidence=f.get("evidence", ""),
            description=f.get("description", ""),
            impact=f.get("impact", ""),
            recommendation=f.get("recommendation", ""),
            status="Open"
        )
        db.session.add(db_finding)

    db.session.commit()

    return jsonify({
        "scan_id": scan.id,
        "score": risk_summary["score"],
        "counts": risk_summary["counts"],
        "findings_count": len(all_findings)
    }), 201

@api_bp.route("/scans/<int:scan_id>/report", methods=["GET"])
def export_pdf_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    target = Target.query.get(scan.target_id)
    findings = Finding.query.filter_by(scan_id=scan.id).all()

    report_data = {
        "target_name": target.name,
        "target_url": target.url_or_ip,
        "date": scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "score": scan.security_score,
        "findings": [{
            "finding_id": f.finding_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "evidence": f.evidence,
            "impact": f.impact,
            "recommendation": f.recommendation,
            "status": f.status
        } for f in findings]
    }

    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"../report_{scan_id}.pdf")
    SecurityReportGenerator.generate(report_data, report_path)
    return send_file(report_path, as_attachment=True, download_name=f"VulnGuard_Scan_{scan_id}.pdf")
