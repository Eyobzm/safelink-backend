from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..services.reports_service import list_reports, triage_report
from .deps import require_admin

router = APIRouter()


class TriageBody(BaseModel):
    status: Literal["new", "reviewing", "archived"]


@router.get("/v1/admin/reports")
async def reports(status: str | None = None, _: str = Depends(require_admin)):
    return await list_reports(status)


@router.patch("/v1/admin/reports/{report_id}")
async def triage(report_id: str, body: TriageBody, _: str = Depends(require_admin)):
    row = await triage_report(report_id, body.status)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return row


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_page():
    return _PAGE


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SafeLink reports</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { margin: 0; background: #f4f7f6; color: #14201f; }
  header { background: #0e6b63; color: white; padding: 20px 24px; }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  label { display: block; font-size: 14px; margin-bottom: 6px; }
  input, select, button { font: inherit; }
  input[type=password] { padding: 8px 10px; width: min(360px, 100%); }
  .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 12px 0 20px; }
  button { background: #0e6b63; color: white; border: 0; border-radius: 8px; padding: 8px 14px; cursor: pointer; }
  button.ghost { background: transparent; color: #0e6b63; border: 1px solid #0e6b63; }
  article { background: white; border-radius: 12px; padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  .meta { color: #52615f; font-size: 13px; margin-bottom: 8px; }
  .url { font-weight: 650; word-break: break-all; }
  .err { color: #9b1028; }
  @media (prefers-color-scheme: dark) {
    body { background: #101817; color: #e7f2f0; }
    article { background: #1b2726; }
    .meta { color: #b7c7c4; }
    button.ghost { color: #9ad4cd; border-color: #9ad4cd; }
  }
</style>
</head>
<body>
<header><h1>SafeLink report review</h1><p>False positives and missed threats. URLs are stored without query strings.</p></header>
<main>
  <label for="token">Admin token</label>
  <input id="token" type="password" autocomplete="current-password"/>
  <div class="row">
    <button id="load" type="button">Load reports</button>
    <label>Status <select id="filter"><option value="">All</option><option>new</option><option>reviewing</option><option>archived</option></select></label>
  </div>
  <p id="msg"></p>
  <div id="list"></div>
</main>
<script>
const tokenEl = document.getElementById('token');
tokenEl.value = sessionStorage.getItem('safelinkAdmin') || '';
document.getElementById('load').onclick = load;
async function load() {
  const token = tokenEl.value.trim();
  sessionStorage.setItem('safelinkAdmin', token);
  const status = document.getElementById('filter').value;
  const msg = document.getElementById('msg');
  const list = document.getElementById('list');
  msg.textContent = 'Loading…';
  msg.className = '';
  list.innerHTML = '';
  const q = status ? '?status=' + encodeURIComponent(status) : '';
  const res = await fetch('/v1/admin/reports' + q, { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) {
    msg.textContent = res.status === 401 ? 'Token was rejected.' : 'Could not load reports (' + res.status + ').';
    msg.className = 'err';
    return;
  }
  const rows = await res.json();
  msg.textContent = rows.length + ' report' + (rows.length === 1 ? '' : 's') + '.';
  for (const r of rows) {
    const el = document.createElement('article');
    el.innerHTML = '<div class="meta"></div><div class="url"></div><p class="note"></p><div class="row"></div>';
    el.querySelector('.meta').textContent = r.created_at + ' · ' + r.report_type + ' · ' + r.status;
    el.querySelector('.url').textContent = r.url_redacted;
    el.querySelector('.note').textContent = r.note || '';
    const actions = el.querySelector('.row');
    for (const statusName of ['reviewing', 'archived', 'new']) {
      if (statusName === r.status) continue;
      const b = document.createElement('button');
      b.className = 'ghost';
      b.type = 'button';
      b.textContent = 'Mark ' + statusName;
      b.onclick = () => triage(r.id, statusName);
      actions.appendChild(b);
    }
    list.appendChild(el);
  }
}
async function triage(id, status) {
  const token = tokenEl.value.trim();
  const res = await fetch('/v1/admin/reports/' + id, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  });
  if (!res.ok) { document.getElementById('msg').textContent = 'Update failed.'; return; }
  load();
}
</script>
</body>
</html>
"""
