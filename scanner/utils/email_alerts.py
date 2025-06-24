from django.core.mail import send_mail
from django.conf import settings

def send_critical_cve_alert(
    title, source, link, score, summary, vulnerable_products,
    vt_score=None, exploits=None
):
    lines = [
        f"🚨 CRITICAL Vulnerability Detected: {title}",
        f"Source: {source} | CVSS: {score}",
        f"Link: {link}",
        "",
        f"Summary: {summary}",
        "",
        f"Affected Products: {vulnerable_products}",
    ]
    if vt_score is not None:
        lines.append(f"VirusTotal Risk Score: {vt_score}")
    if exploits:
        lines.append(f"Known Exploits: {len(exploits)} — see VT dashboard")

    message = "\n".join(lines)
    send_mail(
        subject=f"[CRITICAL] {title}",
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=settings.ALERT_RECIPIENTS,
        fail_silently=False
    )
