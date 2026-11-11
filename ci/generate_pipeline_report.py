#!/usr/bin/env python3
"""SecureBank - rapport CI/CD PDF et livraison Telegram.
Les statuts proviennent de l'API GitLab, pas d'une estimation.
"""
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ENV = os.environ
OUTPUT = Path("securebank_pipeline_report.pdf")
BLUE = colors.HexColor("#17324F")
BLUE2 = colors.HexColor("#26638D")
LIGHT = colors.HexColor("#E8F0F6")
GREY = colors.HexColor("#526174")
GREEN = colors.HexColor("#137653")
RED = colors.HexColor("#B62E3C")
AMBER = colors.HexColor("#9B660A")
PAGE_WIDTH, PAGE_HEIGHT = landscape(A4)
CONTENT_WIDTH = PAGE_WIDTH - 3.2 * cm

STAGES = [
    ("test", "Tests unitaires"),
    ("bandit", "SAST - Bandit"),
    ("dependency_audit", "Audit des dependances"),
    ("secret_scan", "Detection de secrets"),
    ("semgrep", "SAST - Semgrep"),
    ("container", "Construction Docker"),
    ("trivy", "Analyse image - Trivy"),
    ("dast", "DAST - OWASP ZAP"),
    ("deploy", "Deploiement staging"),
]
REMEDIATION = {
    "unit_tests": "Examiner les assertions pytest, les dependances et les fixtures de test.",
    "bandit": "Consulter les lignes signalees par Bandit, corriger les problemes et relancer.",
    "dependency_audit": "Consulter pip-audit.json, identifier les CVE et mettre a jour les paquets.",
    "secret_scan": "Supprimer les secrets detectes, revoquer les identifiants exposes et nettoyer l'historique si necessaire.",
    "semgrep": "Analyser la regle declenchee et corriger le flux de donnees concerne.",
    "container_build": "Verifier Dockerfile, contexte de construction, reseau et daemon Docker-in-Docker.",
    "trivy_scan": "Consulter trivy-ci.json, actualiser les images de base et les dependances vulnerables.",
    "zap_api_scan": "Verifier /api/health, la specification OpenAPI et les alertes du rapport ZAP.",
    "staging_deploy": "Verifier le Runner staging, Docker, SECRET_KEY, les ports et /api/health.",
}
ACTIVE = {
    "created",
    "pending",
    "preparing",
    "running",
    "waiting_for_resource",
    "scheduled",
}


class ReportAPIError(Exception):
    """Erreur API exprimable sans inclure de secrets."""


def api_endpoint():
    token = ENV.get("GITLAB_REPORT_TOKEN", "").strip()
    if not token:
        raise ReportAPIError("GITLAB_REPORT_TOKEN absent ou vide dans ce job.")
    base = (
        (ENV.get("GITLAB_API_URL") or ENV.get("CI_API_V4_URL") or "")
        .strip()
        .rstrip("/")
    )
    if not base:
        raise ReportAPIError("GITLAB_API_URL et CI_API_V4_URL absents.")
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ReportAPIError("Adresse de l'API GitLab invalide : URL http(s) attendue.")
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        raise ReportAPIError(
            "L'API utilise localhost : dans le conteneur Runner, localhost ne designe pas le serveur GitLab."
        )
    if base.endswith("/api/v4"):
        pass
    elif "/api/" not in parsed.path:
        base += "/api/v4"
    else:
        raise ReportAPIError("GITLAB_API_URL doit se terminer par /api/v4.")
    project, pipeline = ENV.get("CI_PROJECT_ID"), ENV.get("CI_PIPELINE_ID")
    if not project or not pipeline:
        raise ReportAPIError("CI_PROJECT_ID ou CI_PIPELINE_ID absent.")
    return f"{base}/projects/{project}/pipelines/{pipeline}/jobs", token


def retrieve_jobs():
    url, token = api_endpoint()
    jobs = []
    with requests.Session() as session:
        for page in range(1, 51):
            try:
                response = session.get(
                    url,
                    headers={"PRIVATE-TOKEN": token},
                    params={"per_page": 100, "page": page, "include_retried": "false"},
                    timeout=(8, 25),
                )
            except requests.exceptions.ConnectTimeout as exc:
                raise ReportAPIError(
                    "Connexion API expiree. Verifier adresse, port et reseau Docker."
                ) from exc
            except requests.exceptions.ConnectionError as exc:
                raise ReportAPIError(
                    "Connexion API refusee ou nom DNS inaccessible depuis le Runner."
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise ReportAPIError(
                    "Erreur de transport pendant la requete API GitLab."
                ) from exc
            if response.status_code == 401:
                raise ReportAPIError(
                    "HTTP 401 : token API manquant, invalide ou expire."
                )
            if response.status_code == 403:
                raise ReportAPIError(
                    "HTTP 403 : permissions insuffisantes (read_api / role)."
                )
            if response.status_code == 404:
                raise ReportAPIError(
                    "HTTP 404 : API/projet/pipeline introuvable ou non autorise."
                )
            if not response.ok:
                raise ReportAPIError(f"Erreur API GitLab HTTP {response.status_code}.")
            try:
                chunk = response.json()
            except ValueError as exc:
                raise ReportAPIError(
                    "L'API renvoie du contenu non JSON (URL incorrecte ?)."
                ) from exc
            if not isinstance(chunk, list):
                raise ReportAPIError(
                    "Reponse inattendue : une liste de jobs est attendue."
                )
            jobs.extend(chunk)
            next_page = response.headers.get("X-Next-Page", "")
            if not next_page and len(chunk) < 100:
                break
            if not next_page and len(chunk) == 100:
                continue
            if next_page and int(next_page) != page + 1:
                raise ReportAPIError("Pagination GitLab inattendue.")
        else:
            raise ReportAPIError("Trop de pages de jobs GitLab.")
    own_id = str(ENV.get("CI_JOB_ID", ""))
    excluded = {"telegram_pdf_report", "telegram_success", "telegram_failure"}
    return [
        j for j in jobs if str(j.get("id")) != own_id and j.get("name") not in excluded
    ]


def enrich_failures(jobs):
    """Identifie la cause d'erreur sans exposer les traces brutes ou les secrets."""
    try:
        url, token = api_endpoint()
    except ReportAPIError:
        return
    root = url.split("/pipelines/")[0]
    with requests.Session() as session:
        for job in jobs:
            if job.get("status") != "failed" or not job.get("id"):
                continue
            job["safe_error"] = classify_error(job, "")
            try:
                resp = session.get(
                    f"{root}/jobs/{job['id']}/trace",
                    headers={"PRIVATE-TOKEN": token},
                    timeout=(5, 12),
                    stream=True,
                )
                if resp.ok:
                    # Ne pas inclure de contenu brut de logs dans le PDF.
                    raw = b""
                    for chunk in resp.iter_content(chunk_size=8192):
                        raw = (raw + chunk)[-120000:]
                    job["safe_error"] = classify_error(
                        job, raw.decode("utf-8", errors="replace")
                    )
                resp.close()
            except requests.RequestException:
                pass


def classify_error(job, trace):
    """Retient une categorie documentee ; aucune trace brute n'est recopiee."""
    t = trace.lower()
    name = job.get("name", "")
    if "unexpected eof" in t and ("vulnerability db" in t or name == "trivy_scan"):
        return (
            "Base Trivy : telechargement interrompu (unexpected EOF)",
            "Verifier acces GHCR, utiliser cache DB et relancer le telechargement.",
        )
    if "failed to download vulnerability db" in t:
        return (
            "Base de vulnerabilites Trivy indisponible",
            "Verifier registre OCI, connectivite et cache de Trivy, puis relancer.",
        )
    if "cannot connect to the docker daemon" in t or "error during connect" in t:
        return (
            "Connexion au daemon Docker impossible",
            "Verifier le Runner, Docker-in-Docker, DOCKER_HOST et le mode privilegie.",
        )
    if "no matching files" in t and "image.tar" in t:
        return (
            "Artifact Docker image.tar manquant",
            "Verifier container_build et la transmission de son artifact image.tar.",
        )
    if "connection refused" in t or "connection timed out" in t:
        return (
            "Service ou reseau injoignable",
            "Verifier service cible, nom DNS, port, reseau Docker et disponibilite.",
        )
    if "no such file or directory" in t:
        return (
            "Fichier requis introuvable",
            "Verifier le chemin, la presence du fichier dans le depot et les artifacts.",
        )
    if name == "dependency_audit" and ("vulnerability" in t or "found" in t):
        return (
            "Dependance vulnerable detectee",
            "Consulter le rapport pip-audit, mettre a jour les dependances et retester.",
        )
    if name == "secret_scan" and ("leak" in t or "finding" in t):
        return (
            "Secret potentiel detecte",
            "Revoquer les identifiants exposes et supprimer les secrets du depot.",
        )
    if name == "trivy_scan":
        return (
            "Trivy a echoue ; cause precise non confirmee",
            "Verifier si erreur DB ou CVE HIGH/CRITICAL dans le log et le JSON.",
        )
    if name == "zap_api_scan":
        return (
            "Analyse ZAP en echec",
            "Verifier demarrage API, /api/health, reseau Docker et rapport ZAP.",
        )
    reason = job.get("failure_reason")
    return (
        (
            f"Job en echec (categorie GitLab : {reason})"
            if reason
            else "Job en echec ; cause non confirmee"
        ),
        REMEDIATION.get(
            name, "Lire le log du job et corriger la premiere erreur bloquante."
        ),
    )


def stage_correction(items, issue, state):
    if issue:
        return "Verifier GITLAB_REPORT_TOKEN et GITLAB_API_URL accessibles depuis le Runner."
    failed = [x for x in items if x.get("status") == "failed"]
    if failed:
        return " ; ".join(
            dict.fromkeys(x.get("safe_error", classify_error(x, ""))[1] for x in failed)
        )
    if state in ("SUCCES", "REUSSI", "SUCCES (AVEC ECHECS TOLERES)"):
        return "Aucune correction requise pour execution ; consulter les alertes des scans."
    if state == "NON PLANIFIE / ABSENT":
        return "Aucune : verifier les rules du job si son execution etait attendue."
    if state == "IGNORE":
        return "Corriger le stage precedent qui a bloque le pipeline."
    return "Verifier le statut et les logs avant toute correction."


def job_status(job):
    raw = job.get("status", "unknown")
    return {
        "success": "REUSSI",
        "failed": "ECHEC",
        "skipped": "IGNORE",
        "canceled": "ANNULE",
        "manual": "MANUEL",
        "running": "EN COURS",
        "pending": "EN ATTENTE",
        "created": "EN ATTENTE",
        "preparing": "EN ATTENTE",
        "waiting_for_resource": "EN ATTENTE",
    }.get(raw, str(raw).upper())


def aggregate(jobs):
    if not jobs:
        return "INDETERMINE"
    if any(
        j.get("status") == "failed" and not j.get("allow_failure", False) for j in jobs
    ):
        return "ECHEC"
    if any(j.get("status") in ACTIVE for j in jobs):
        return "EN COURS"
    if any(j.get("status") == "canceled" for j in jobs):
        return "ANNULE"
    if all(j.get("status") == "skipped" for j in jobs):
        return "IGNORE"
    if any(j.get("status") == "failed" for j in jobs):
        return "SUCCES (AVEC ECHECS TOLERES)"
    if any(j.get("status") == "success" for j in jobs):
        return "SUCCES"
    return "INDETERMINE"


def status_color(text):
    if text.startswith(("SUCCES", "REUSSI")):
        return GREEN
    if text.startswith("ECHEC"):
        return RED
    return AMBER


def para(text, style):
    return Paragraph(escape(str(text)), style)


def page_footer(canvas, doc):
    canvas.setStrokeColor(colors.HexColor("#D7E2EB"))
    canvas.line(1.6 * cm, 1.24 * cm, PAGE_WIDTH - 1.6 * cm, 1.24 * cm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(1.6 * cm, 0.97 * cm, "SECUREBANK  |  RAPPORT CI/CD AUTOMATIQUE")
    canvas.drawRightString(PAGE_WIDTH - 1.6 * cm, 0.97 * cm, f"Page {doc.page}")


def create_pdf(jobs, issue):
    ss = getSampleStyleSheet()
    ss.add(
        ParagraphStyle(
            name="SBTitle",
            parent=ss["Title"],
            fontSize=19,
            leading=24,
            textColor=BLUE,
            spaceAfter=7,
            alignment=TA_LEFT,
        )
    )
    ss.add(
        ParagraphStyle(
            name="SBSubtitle",
            parent=ss["Normal"],
            fontSize=10,
            leading=14,
            textColor=GREY,
            spaceAfter=12,
        )
    )
    ss.add(
        ParagraphStyle(
            name="SBSection",
            parent=ss["Heading2"],
            fontSize=12,
            textColor=BLUE2,
            spaceBefore=14,
            spaceAfter=8,
        )
    )
    ss.add(ParagraphStyle(name="SBBody", parent=ss["Normal"], fontSize=8.7, leading=13))
    ss.add(ParagraphStyle(name="SBCell", parent=ss["Normal"], fontSize=8, leading=11))
    ss.add(ParagraphStyle(name="SBCenter", parent=ss["SBCell"], alignment=TA_CENTER))
    ss.add(
        ParagraphStyle(
            name="SBBanner",
            parent=ss["Normal"],
            fontSize=13,
            leading=18,
            alignment=TA_CENTER,
            spaceBefore=5,
            spaceAfter=5,
        )
    )
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=landscape(A4),
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.45 * cm,
        bottomMargin=1.65 * cm,
    )
    story = [
        Paragraph("SECUREBANK  /  RAPPORT CI/CD", ss["SBTitle"]),
        Paragraph(
            "Execution automatique | Stages, statuts et actions correctives",
            ss["SBSubtitle"],
        ),
    ]
    meta = [
        ("Projet", ENV.get("CI_PROJECT_PATH", "-")),
        ("Pipeline", "#" + ENV.get("CI_PIPELINE_ID", "-")),
        ("Branche", ENV.get("CI_COMMIT_REF_NAME", "-")),
        ("Commit", ENV.get("CI_COMMIT_SHORT_SHA", "-")),
        ("Date UTC", datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")),
        ("Lien GitLab", ENV.get("CI_PIPELINE_URL", "-")),
    ]
    data = [[para(k, ss["SBCell"]), para(v, ss["SBCell"])] for k, v in meta]
    meta_table = Table(
        data, colWidths=[3.1 * cm, CONTENT_WIDTH - 3.1 * cm], hAlign="LEFT"
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#D6E1EB")),
            ]
        )
    )
    story.extend([meta_table, Spacer(1, 0.35 * cm)])
    overall = "INDETERMINE - API NON ACCESSIBLE" if issue else aggregate(jobs)
    color = status_color(overall)
    banner = Table(
        [
            [
                Paragraph(
                    f'<font color="{color.hexval()}"><b>ETAT GLOBAL : {escape(overall)}</b></font>',
                    ss["SBBanner"],
                )
            ]
        ],
        colWidths=[CONTENT_WIDTH],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#C7D9E7")),
            ]
        )
    )
    story.append(banner)
    if issue:
        story.append(Spacer(1, 0.12 * cm))
        story.append(para("Diagnostic API : " + issue, ss["SBBody"]))
        story.append(
            para(
                "Les statuts ci-dessous ne peuvent pas etre verifies tant que l'API est inaccessible.",
                ss["SBBody"],
            )
        )

    story.append(Paragraph("1. Tableau de bord des stages", ss["SBSection"]))
    groups = defaultdict(list)
    for job in jobs:
        groups[job.get("stage") or "inconnu"].append(job)
    ordered = STAGES + [(x, x) for x in sorted(groups) if x not in dict(STAGES)]
    rows = [
        [
            Paragraph(f'<font color="white"><b>{x}</b></font>', ss["SBCell"])
            for x in ("STAGE", "ETAT", "JOBS / DETAILS", "COMMENT CORRIGER L'ERREUR")
        ]
    ]
    state_rows = []
    for idx, (stage, label) in enumerate(ordered, 1):
        items = sorted(groups.get(stage, []), key=lambda x: x.get("name", ""))
        state = (
            "NON VERIFIE"
            if issue
            else aggregate(items) if items else "NON PLANIFIE / ABSENT"
        )
        details = (
            "API indisponible"
            if issue
            else (
                "Aucun job observe (regles/branche ou jobs non crees)"
                if not items
                else " ; ".join(
                    f"{j.get('name', '?')}: {job_status(j)}"
                    + (
                        " [tolere]"
                        if j.get("status") == "failed" and j.get("allow_failure")
                        else ""
                    )
                    for j in items
                )
            )
        )
        rows.append(
            [
                para(f"{idx:02d}  {label}", ss["SBCell"]),
                Paragraph(
                    f'<font color="{status_color(state).hexval()}"><b>{escape(state)}</b></font>',
                    ss["SBCell"],
                ),
                para(details, ss["SBCell"]),
                para(stage_correction(items, issue, state), ss["SBCell"]),
            ]
        )
        state_rows.append((stage, state))
    table = Table(
        rows,
        colWidths=[4.0 * cm, 3.0 * cm, 6.0 * cm, CONTENT_WIDTH - 13.0 * cm],
        hAlign="LEFT",
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F2F6FA")],
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, 0), 0.7, BLUE),
                ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#DFE7EE")),
            ]
        )
    )
    story.append(table)

    story.append(Paragraph("2. Erreurs et recommandations", ss["SBSection"]))
    failures = [j for j in jobs if j.get("status") == "failed"]
    if issue:
        story.append(
            para(
                "Action prioritaire : corriger la connexion API GitLab avant d'interpreter les resultats.",
                ss["SBBody"],
            )
        )
    elif not failures:
        story.append(
            para(
                "Aucun job en echec parmi les jobs recuperes. Consulter les rapports de scanners pour les alertes non bloquantes.",
                ss["SBBody"],
            )
        )
    else:
        for j in failures:
            name = j.get("name", "?")
            diagnostic, details = j.get("safe_error", classify_error(j, ""))
            note = " | echec tolere par GitLab" if j.get("allow_failure") else ""
            story.append(
                KeepTogether(
                    [
                        Paragraph(f"<b>{escape(name)}</b>{escape(note)}", ss["SBBody"]),
                        para("Diagnostic : " + diagnostic, ss["SBBody"]),
                        para("Correction suggeree : " + details, ss["SBBody"]),
                        Spacer(1, 0.18 * cm),
                    ]
                )
            )
    story.append(Paragraph("3. Notes de lecture", ss["SBSection"]))
    story.append(
        para(
            '"IGNORE" signifie que le job n\'a pas ete execute (par exemple apres un echec precedent). '
            "\"NON PLANIFIE / ABSENT\" signifie qu'aucun job correspondant ne figure dans les resultats de l'API. "
            "Sur cette branche demo, le deploiement staging peut etre absent car il est reserve a main.",
            ss["SBBody"],
        )
    )
    story.append(Spacer(1, 0.12 * cm))
    story.append(
        para(
            "Le job Telegram/PDF est exclu du calcul : il est encore en cours lors de la collecte. "
            "La reussite d'un job de scan n'implique pas l'absence totale de vulnerabilites.",
            ss["SBBody"],
        )
    )
    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return overall


def send_telegram(overall):
    token = ENV.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = ENV.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID absent.")
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    caption = f'SecureBank | {overall} | Pipeline #{ENV.get("CI_PIPELINE_ID", "?")} | {ENV.get("CI_COMMIT_REF_NAME", "?")}'
    try:
        with OUTPUT.open("rb") as file:
            response = requests.post(
                url,
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"document": (OUTPUT.name, file, "application/pdf")},
                timeout=(10, 60),
            )
    except requests.RequestException as exc:
        raise RuntimeError("Connexion a Telegram impossible.") from exc
    if not response.ok:
        raise RuntimeError(
            f"Telegram a refuse le rapport : HTTP {response.status_code}."
        )
    if not response.json().get("ok"):
        raise RuntimeError("Telegram a refuse le rapport.")


def main():
    jobs, issue = [], None
    try:
        jobs = retrieve_jobs()
        enrich_failures(jobs)
        print(f"API GitLab OK : {len(jobs)} jobs recuperes.")
    except ReportAPIError as exc:
        issue = str(exc)
        print(f"ERREUR API GitLab : {issue}", file=sys.stderr)
    except Exception as exc:
        issue = "Erreur API inattendue (" + type(exc).__name__ + ")."
        print("ERREUR API GitLab : " + issue, file=sys.stderr)
    overall = create_pdf(jobs, issue)
    print(f"PDF genere : {OUTPUT}")
    try:
        send_telegram(overall)
        print("PDF envoye sur Telegram.")
    except (RuntimeError, ValueError) as exc:
        print(f"ERREUR Telegram : {exc}", file=sys.stderr)
        return 1
    # Ne pas masquer un diagnostic indisponible par un job vert (allow_failure peut etre configure).
    return 1 if issue else 0


if __name__ == "__main__":
    sys.exit(main())
