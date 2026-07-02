#!/usr/bin/env python3
"""
SPY-THREAT-HUNT V2
Developed by SPYDIRBYTE — idea created by hAckDHD

Flask backend. Run `python cli.py serve` or `python app.py` to launch.
"""
import re
import urllib.request
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core import storage, extractor, classifier, hunting, reporting, enrichment, attack, export as export_mod, feeds


def create_app():
    app = Flask(__name__)
    storage.migrate()

    # ---------------------------------------------------------- page routes
    @app.route("/")
    def index():
        return render_template("index.html")

    # ----------------------------------------------------------- API: stats
    @app.route("/api/stats")
    def api_stats():
        return jsonify(storage.get_stats())

    # -------------------------------------------------------- API: IOC list
    @app.route("/api/iocs")
    def api_list():
        types = request.args.get("type")
        classes = request.args.get("classification")
        hunt_status = request.args.get("huntStatus")
        search = request.args.get("search")
        limit = int(request.args.get("limit", 500))
        iocs = storage.list_iocs(
            type_=types.split(",") if types else None,
            classification=classes.split(",") if classes else None,
            hunt_status=hunt_status.split(",") if hunt_status else None,
            search=search or None,
            limit=limit,
        )
        return jsonify({"iocs": iocs, "count": len(iocs)})

    @app.route("/api/iocs/<ioc_id>", methods=["PATCH"])
    def api_update(ioc_id):
        fields = request.get_json(force=True) or {}
        ok = storage.update_ioc(ioc_id, fields)
        return jsonify({"ok": ok})

    @app.route("/api/iocs/<ioc_id>", methods=["DELETE"])
    def api_delete(ioc_id):
        storage.delete_ioc(ioc_id)
        return jsonify({"ok": True})

    @app.route("/api/iocs/clear", methods=["POST"])
    def api_clear():
        storage.clear_all()
        return jsonify({"ok": True})

    # ------------------------------------------------------- API: extraction
    @app.route("/api/extract/paste", methods=["POST"])
    def api_extract_paste():
        body = request.get_json(force=True) or {}
        text = body.get("text", "")
        include_hostnames = bool(body.get("includeHostnames", False))
        tags = body.get("tags", [])
        if not text.strip():
            return jsonify({"error": "empty input"}), 400

        result = extractor.extract(text, source="manual", include_hostnames=include_hostnames, tags=tags)
        iocs = [i.to_dict() for i in result["iocs"]]
        for i in iocs:
            i["classification"] = classifier.classify_heuristic(i)
        inserted = storage.bulk_upsert(iocs)
        return jsonify({
            "extracted": len(iocs),
            "inserted": inserted,
            "duplicates": len(iocs) - inserted,
            "byType": result["stats"]["by_type"],
            "iocs": iocs,
        })

    @app.route("/api/extract/url", methods=["POST"])
    def api_extract_url():
        body = request.get_json(force=True) or {}
        url = body.get("url", "").strip()
        if not url:
            return jsonify({"error": "missing url"}), 400
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SPY-THREAT-HUNT/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
            text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
            text = re.sub(r"<[^>]+>", " ", text)
        except Exception as e:
            return jsonify({"error": f"fetch failed: {e}"}), 400

        result = extractor.extract(text, source="scraper", source_url=url)
        iocs = [i.to_dict() for i in result["iocs"]]
        for i in iocs:
            i["classification"] = classifier.classify_heuristic(i)
        inserted = storage.bulk_upsert(iocs)
        return jsonify({
            "extracted": len(iocs),
            "inserted": inserted,
            "duplicates": len(iocs) - inserted,
            "byType": result["stats"]["by_type"],
            "iocs": iocs,
        })

    @app.route("/api/extract/file", methods=["POST"])
    def api_extract_file():
        if "file" not in request.files:
            return jsonify({"error": "no file"}), 400
        f = request.files["file"]
        filename = f.filename or "upload"
        raw = f.read()

        text = _extract_file_text(filename, raw)
        if text is None:
            return jsonify({"error": "unsupported file type"}), 400

        result = extractor.extract(text, source="file", source_file=filename)
        iocs = [i.to_dict() for i in result["iocs"]]
        for i in iocs:
            i["classification"] = classifier.classify_heuristic(i)
        inserted = storage.bulk_upsert(iocs)
        return jsonify({
            "extracted": len(iocs),
            "inserted": inserted,
            "duplicates": len(iocs) - inserted,
            "byType": result["stats"]["by_type"],
            "iocs": iocs,
        })

    # ------------------------------------------------------------ API: hunt
    @app.route("/api/hunt", methods=["POST"])
    def api_hunt():
        body = request.get_json(force=True) or {}
        platform = body.get("platform", "splunk")
        types = body.get("types")
        time_range = body.get("timeRange")
        ioc_ids = body.get("iocIds")

        if ioc_ids:
            iocs = storage.get_by_ids(ioc_ids)
        else:
            iocs = storage.list_iocs(type_=types, limit=2000)

        grouped = {}
        for i in iocs:
            grouped.setdefault(i["type"], []).append(i)

        queries = []
        for type_, group in grouped.items():
            q = hunting.generate(platform, type_, group, time_range)
            if q:
                queries.append(q)
        return jsonify({"queries": queries})

    # ----------------------------------------------------------- API: feeds
    @app.route("/api/feeds")
    def api_feeds_list():
        return jsonify(feeds.feed_status())

    @app.route("/api/feeds/<feed_id>/pull", methods=["POST"])
    def api_feeds_pull(feed_id):
        body = request.get_json(silent=True) or {}
        hunt_name = body.get("huntName")
        result, error = feeds.pull_feed(feed_id)
        if error:
            return jsonify({"error": error}), 400

        text = result["iocs_text"]
        if not text.strip():
            return jsonify({"extracted": 0, "inserted": 0, "duplicates": 0, "byType": {}, "iocs": []})

        extraction = extractor.extract(text, source="feed", source_url=feed_id, tags=["feed:" + feed_id])
        iocs = [i.to_dict() for i in extraction["iocs"]]
        for i in iocs:
            i["classification"] = classifier.classify_heuristic(i)
            if hunt_name:
                i["hunt_name"] = hunt_name
        inserted = storage.bulk_upsert(iocs)
        return jsonify({
            "extracted": len(iocs), "inserted": inserted, "duplicates": len(iocs) - inserted,
            "byType": extraction["stats"]["by_type"], "iocs": iocs,
        })

    @app.route("/api/feeds/custom/pull", methods=["POST"])
    def api_feeds_custom_pull():
        body = request.get_json(force=True) or {}
        url = body.get("url", "").strip()
        api_key = body.get("apiKey", "").strip() or None
        hunt_name = body.get("huntName")
        if not url:
            return jsonify({"error": "missing url"}), 400
        try:
            result = feeds.fetch_custom(url, api_key)
        except Exception as e:
            return jsonify({"error": str(e)}), 400

        extraction = extractor.extract(result["iocs_text"], source="feed", source_url=url, tags=["feed:custom"])
        iocs = [i.to_dict() for i in extraction["iocs"]]
        for i in iocs:
            i["classification"] = classifier.classify_heuristic(i)
            if hunt_name:
                i["hunt_name"] = hunt_name
        inserted = storage.bulk_upsert(iocs)
        return jsonify({
            "extracted": len(iocs), "inserted": inserted, "duplicates": len(iocs) - inserted,
            "byType": extraction["stats"]["by_type"], "iocs": iocs,
        })

    # --------------------------------------------------------- API: enrich
    @app.route("/api/enrich/status")
    def api_enrich_status():
        return jsonify(enrichment.config_status())

    @app.route("/api/enrich", methods=["POST"])
    def api_enrich():
        body = request.get_json(force=True) or {}
        ids = body.get("iocIds") or []
        iocs = storage.get_by_ids(ids) if ids else storage.list_iocs(limit=200)

        results = []
        for ioc in iocs:
            data = enrichment.enrich_ioc(ioc["type"], ioc["value"])
            if data:
                cls = enrichment.score_to_classification(data.get("reputation_score"))
                storage.update_ioc(ioc["id"], {
                    "enrichment": data,
                    "enriched_at": datetime.now(timezone.utc).isoformat(),
                    "classification": cls,
                })
                results.append({"id": ioc["id"], "value": ioc["value"], "enrichment": data, "classification": cls})
            else:
                results.append({"id": ioc["id"], "value": ioc["value"], "enrichment": None, "classification": ioc["classification"]})

        return jsonify({"enriched": len([r for r in results if r["enrichment"]]), "results": results})

    # ---------------------------------------------------------- API: attck
    @app.route("/api/attack-summary")
    def api_attack_summary():
        iocs = storage.list_iocs(limit=5000)
        return jsonify({"techniques": attack.summarize_techniques(iocs)})

    # ---------------------------------------------------------- API: bulk
    @app.route("/api/iocs/bulk", methods=["POST"])
    def api_bulk():
        body = request.get_json(force=True) or {}
        ids = body.get("iocIds") or []
        fields = body.get("fields") or {}
        if not ids or not fields:
            return jsonify({"error": "iocIds and fields required"}), 400

        if "tagsAdd" in fields:
            tag = fields.pop("tagsAdd")
            for ioc in storage.get_by_ids(ids):
                tags = set(ioc.get("tags") or [])
                tags.add(tag)
                storage.update_ioc(ioc["id"], {"tags": list(tags)})

        count = storage.bulk_update(ids, fields) if fields else len(ids)
        return jsonify({"updated": count})

    # --------------------------------------------------------- API: export
    @app.route("/api/export/<fmt>")
    def api_export(fmt):
        fmt = fmt.lower()
        if fmt not in export_mod.EXPORTERS:
            return jsonify({"error": "unsupported format"}), 400
        ids = request.args.get("ids")
        iocs = storage.get_by_ids(ids.split(",")) if ids else storage.list_iocs(limit=5000)
        content = export_mod.EXPORTERS[fmt](iocs)
        mimetype = {"csv": "text/csv", "json": "application/json", "stix": "application/json"}[fmt]
        ext = {"csv": "csv", "json": "json", "stix": "json"}[fmt]
        from flask import Response
        return Response(
            content, mimetype=mimetype,
            headers={"Content-Disposition": f"attachment; filename=spy-threat-hunt-export.{ext}"},
        )

    # --------------------------------------------------------- API: reports
    @app.route("/api/report/<kind>")
    def api_report(kind):
        iocs = storage.list_iocs(limit=5000)
        hunt_name = request.args.get("name", "").strip() or None
        if kind == "exec":
            return jsonify(reporting.executive_report(iocs, hunt_name=hunt_name))
        if kind == "analyst":
            return jsonify(reporting.analyst_report(iocs, hunt_name=hunt_name))
        return jsonify({"error": "unknown report kind"}), 400

    return app


def _extract_file_text(filename, raw: bytes):
    lower = filename.lower()
    try:
        if lower.endswith((".txt", ".csv", ".log", ".json", ".md", ".html", ".htm")):
            text = raw.decode("utf-8", errors="ignore")
            if lower.endswith((".html", ".htm")):
                text = re.sub(r"<[^>]+>", " ", text)
            return text
        if lower.endswith(".pdf"):
            return _extract_pdf_text(raw)
        if lower.endswith(".docx"):
            return _extract_docx_text(raw)
        # fallback: try utf-8 decode anyway
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _extract_pdf_text(raw: bytes) -> str:
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(raw))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return ""


def _extract_docx_text(raw: bytes) -> str:
    try:
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
        return re.sub(r"<[^>]+>", " ", xml)
    except Exception:
        return ""


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8847, debug=True)
