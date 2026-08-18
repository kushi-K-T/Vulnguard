import os
import urllib3
from flask import Flask, render_template
from config import Config
from database.models import db, Target, Scan, Finding
from api.routes import api_bp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    app.register_blueprint(api_bp, url_prefix="/api")

    with app.app_context():
        db.create_all()

    @app.route("/")
    def dashboard():
        total_scans = Scan.query.count()
        total_findings = Finding.query.count()
        criticals = Finding.query.filter_by(severity="Critical").count()
        highs = Finding.query.filter_by(severity="High").count()
        mediums = Finding.query.filter_by(severity="Medium").count()
        lows = Finding.query.filter_by(severity="Low").count()
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
        targets = Target.query.all()

        return render_template(
            "dashboard.html",
            total_scans=total_scans,
            total_findings=total_findings,
            criticals=criticals,
            highs=highs,
            mediums=mediums,
            lows=lows,
            recent_scans=recent_scans,
            targets=targets
        )

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
