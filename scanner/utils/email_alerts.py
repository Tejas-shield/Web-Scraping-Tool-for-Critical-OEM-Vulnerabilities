from django.core.mail import send_mail
from django.conf import settings

def send_critical_cve_alert(title, source, link, score):
    subject = f"[CRITICAL ALERT] New Vulnerability Found: {title}"
    message = f"""
A critical vulnerability has been identified.

Title: {title}
Source: {source}
CVSS Score: {score}
Link: {link}

Please assess and mitigate as needed.
"""
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        settings.ALERT_RECIPIENTS,
        fail_silently=False,
    )
