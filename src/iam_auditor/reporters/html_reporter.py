"""
reporters/html_reporter.py
--------------------------
Writes a self-contained HTML audit report.
Output path: <output_dir>/<account_id>/iam_audit_<timestamp>.html
"""

from __future__ import annotations

import os
from datetime import datetime

from iam_auditor.models import AuditResult, Severity

SEVERITY_COLORS = {
    "CRITICAL": "#c42b2b",
    "HIGH":     "#c17b00",
    "MEDIUM":   "#1a56db",
    "LOW":      "#0f9960",
}


def _badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#888")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:10px;font-size:11px;font-weight:600">{sev}</span>'
    )


def _severity_bar(result: AuditResult) -> str:
    total   = max(len(result.findings), 1)
    summary = result.summary()
    bars    = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary.get(sev, 0)
        if count == 0:
            continue
        pct   = round(count / total * 100)
        color = SEVERITY_COLORS[sev]
        bars += (
            f'<div style="display:flex;align-items:center;gap:10px;margin:6px 0">'
            f'<span style="width:70px;font-size:12px;color:#555">{sev}</span>'
            f'<div style="flex:1;background:#f0f0f0;border-radius:4px;height:18px">'
            f'<div style="width:{pct}%;background:{color};height:18px;border-radius:4px"></div></div>'
            f'<span style="width:30px;text-align:right;font-size:12px;font-weight:600">{count}</span>'
            f'</div>'
        )
    return bars


def _findings_rows(result: AuditResult) -> str:
    rows = ""
    for i, f in enumerate(result.sorted_findings()):
        did      = f"detail-{i}"
        controls = ", ".join(f.compliance_controls) if f.compliance_controls else "—"
        rows += f"""
        <tr onclick="toggle('{did}')" style="cursor:pointer;border-bottom:1px solid #eee">
          <td style="padding:10px 12px">{_badge(f.severity.value)}</td>
          <td style="padding:10px 12px;font-family:monospace;font-size:12px">{f.check_id}</td>
          <td style="padding:10px 12px;font-size:13px">{f.check_name}</td>
          <td style="padding:10px 12px;font-size:11px;color:#555;max-width:280px;
                     overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{f.resource}</td>
          <td style="padding:10px 12px;font-size:11px;color:#777">{f.region}</td>
        </tr>
        <tr id="{did}" style="display:none;background:#f9f9fb">
          <td colspan="5" style="padding:12px 24px">
            <div style="margin-bottom:8px">
              <strong>Resource:</strong>
              <code style="font-size:12px">{f.resource}</code>
            </div>
            <div style="margin-bottom:8px"><strong>Detail:</strong> {f.detail}</div>
            <div style="margin-bottom:8px">
              <strong>Remediation:</strong>
              <span style="color:#185fa5">{f.remediation}</span>
            </div>
            <div><strong>Controls:</strong>
              <span style="font-size:12px;color:#555">{controls}</span>
            </div>
          </td>
        </tr>"""
    return rows


def write(result: AuditResult, output_dir: str = ".") -> str:
    # Create account-specific subdirectory
    account_dir = os.path.join(output_dir, result.account_id)
    os.makedirs(account_dir, exist_ok=True)

    ts_label = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ts_file  = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"iam_audit_{ts_file}.html"
    path     = os.path.join(account_dir, filename)
    summary  = result.summary()
    total    = len(result.findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Security Audit — {result.account_id}</title>
<style>
  body {{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         margin:0;padding:0;background:#f5f5f5;color:#222}}
  .header {{background:#0f1f3d;color:#fff;padding:24px 40px}}
  .header h1 {{margin:0 0 4px;font-size:22px;font-weight:500}}
  .header p  {{margin:0;font-size:13px;opacity:.7}}
  .body {{max-width:1100px;margin:0 auto;padding:24px 40px}}
  .card {{background:#fff;border:1px solid #e8e8e8;border-radius:8px;
          padding:20px 24px;margin-bottom:20px}}
  .stat-grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));
               gap:12px;margin-bottom:20px}}
  .stat {{background:#f7f7f7;border-radius:6px;padding:14px;text-align:center}}
  .stat-num {{font-size:28px;font-weight:600}}
  .stat-lbl {{font-size:11px;color:#777;margin-top:2px}}
  table {{width:100%;border-collapse:collapse}}
  th {{text-align:left;padding:8px 12px;border-bottom:2px solid #eee;
       font-size:12px;color:#777;font-weight:600;text-transform:uppercase}}
  tr:hover td {{background:#f0f4ff}}
  h2 {{font-size:15px;font-weight:600;margin:0 0 14px}}
</style>
</head>
<body>
<div class="header">
  <h1>AWS Security Audit Report</h1>
  <p>Account: {result.account_id} &nbsp;|&nbsp; {ts_label}</p>
</div>
<div class="body">
  <div class="stat-grid">
    <div class="stat"><div class="stat-num" style="color:#c42b2b">{summary.get("CRITICAL",0)}</div>
      <div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:#c17b00">{summary.get("HIGH",0)}</div>
      <div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-num" style="color:#1a56db">{summary.get("MEDIUM",0)}</div>
      <div class="stat-lbl">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:#0f9960">{summary.get("LOW",0)}</div>
      <div class="stat-lbl">Low</div></div>
    <div class="stat"><div class="stat-num">{total}</div><div class="stat-lbl">Total</div></div>
    <div class="stat"><div class="stat-num">{round(result.total_duration_ms()/1000,1)}s</div>
      <div class="stat-lbl">Scan time</div></div>
  </div>
  <div class="card">
    <h2>Severity distribution</h2>
    {_severity_bar(result)}
  </div>
  <div class="card">
    <h2>Findings ({total}) &nbsp;
      <span style="font-size:12px;font-weight:400;color:#888">click any row to expand</span>
    </h2>
    <table>
      <thead>
        <tr>
          <th style="width:90px">Severity</th>
          <th style="width:90px">Check ID</th>
          <th>Finding</th>
          <th>Resource</th>
          <th style="width:100px">Region</th>
        </tr>
      </thead>
      <tbody>{_findings_rows(result)}</tbody>
    </table>
    {"<p style='color:#888;text-align:center;padding:20px'>No findings.</p>" if not result.findings else ""}
  </div>
</div>
<script>
function toggle(id) {{
  var el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return path
