from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from app.core.config import Settings, get_settings
from app.enrichers.registry import build_enrichers
from app.export.markdown import case_note, iocs_csv
from app.models.schemas import IndicatorRequest, Report, ReportSummary, SourceInfo
from app.services.analyzer import InvalidInput, analyze_eml, analyze_value

router = APIRouter(prefix="/api")


def _deps(request: Request):
    return request.app.state.client, request.app.state.cache, request.app.state.store


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/analyze/indicator", response_model=Report)
async def analyze_indicator(body: IndicatorRequest, request: Request, settings: Settings = Depends(get_settings)):
    client, cache, store = _deps(request)
    try:
        report = await analyze_value(body.value, settings, client, cache)
    except InvalidInput as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.save(report)
    return report


@router.post("/analyze/eml", response_model=Report)
async def analyze_email_file(request: Request, file: UploadFile = File(...), settings: Settings = Depends(get_settings)):
    client, cache, store = _deps(request)
    limit = settings.max_upload_mb * 1024 * 1024
    raw = await file.read(limit + 1)
    if len(raw) > limit:
        raise HTTPException(status_code=413, detail=f"File larger than {settings.max_upload_mb} MB")
    name = (file.filename or "message.eml")[:200]
    if name.lower().endswith(".msg"):
        raise HTTPException(status_code=415, detail="Outlook .msg is not supported yet. Save the message as .eml (File > Save As) and upload that.")
    try:
        report = await analyze_eml(raw, name, settings, client, cache)
    except InvalidInput as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.save(report)
    return report


@router.get("/reports", response_model=list[ReportSummary])
async def list_reports(request: Request, limit: int = 20):
    return request.app.state.store.recent(min(max(limit, 1), 100))


@router.get("/reports/{report_id}", response_model=Report)
async def get_report(report_id: str, request: Request):
    report = request.app.state.store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found (it may have passed the retention period)")
    return report


@router.delete("/reports/{report_id}", status_code=204)
async def delete_report(report_id: str, request: Request):
    if not request.app.state.store.delete(report_id):
        raise HTTPException(status_code=404, detail="Report not found")


@router.get("/reports/{report_id}/case-note.md", response_class=PlainTextResponse)
async def export_case_note(report_id: str, request: Request):
    report = await get_report(report_id, request)
    return PlainTextResponse(case_note(report), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="case-{report_id[:8]}.md"'})


@router.get("/reports/{report_id}/iocs.csv", response_class=PlainTextResponse)
async def export_iocs(report_id: str, request: Request):
    report = await get_report(report_id, request)
    return PlainTextResponse(iocs_csv(report), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="iocs-{report_id[:8]}.csv"'})


@router.get("/settings/sources", response_model=list[SourceInfo])
async def sources(settings: Settings = Depends(get_settings)):
    info = [
        SourceInfo(name="dns", title="DNS (MX, SPF, DMARC)", configured=settings.dns_enabled, needs_key=False,
                   indicator_types=["domain"], rate_limit="Unlimited", licence_note="Uses your system resolver."),
        SourceInfo(name="rdap", title="RDAP domain age", configured=settings.rdap_enabled, needs_key=False,
                   indicator_types=["domain"], rate_limit="Fair use", licence_note="Public registry data via rdap.org."),
        SourceInfo(name="lookalike", title="Lookalike detection", configured=True, needs_key=False,
                   indicator_types=["domain"], rate_limit="Local",
                   licence_note=f"{len(settings.protected_domain_list)} protected domain(s) + built-in brand list."),
    ]
    for e in build_enrichers(settings):
        info.append(SourceInfo(
            name=e.name, title=e.title, configured=e.configured(), needs_key=e.needs_key,
            indicator_types=sorted(t.value for t in e.indicator_types), rate_limit=e.rate_limit,
            licence_note=e.licence_note, signup_url=e.signup_url,
        ))
    return info


@router.get("/settings")
async def public_settings(settings: Settings = Depends(get_settings)) -> dict:
    """Non-secret settings for the UI. API keys are never returned."""
    return {
        "privacy_mode": settings.privacy_mode,
        "unshorten_enabled": settings.unshorten_enabled,
        "retention_days": settings.retention_days,
        "vt_max_lookups": settings.vt_max_lookups,
        "max_upload_mb": settings.max_upload_mb,
        "protected_domains": settings.protected_domain_list,
    }
