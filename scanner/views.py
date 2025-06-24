from django.shortcuts import render
from .models import Vulnerability
from django.db.models import Q
from django.db.models import Count
import json
from collections import Counter
def home(request):
    query = request.GET.get('q', '')
    source_filter = request.GET.get('source', '')

    vulnerabilities = Vulnerability.objects.all()

    if query:
        vulnerabilities = vulnerabilities.filter(
            Q(title__icontains=query) | Q(link__icontains=query)
        )

    if source_filter and source_filter.lower() != "all":
        vulnerabilities = vulnerabilities.filter(source__icontains=source_filter)

    available_sources = Vulnerability.objects.values_list('source', flat=True).distinct()

    # Count each severity level
    severity_counts = Counter(v.severity or "Unknown" for v in vulnerabilities)
    # Sort for consistent x-axis
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Unknown"]
    chart_data = {
        "labels": json.dumps(severity_order),
        "data": json.dumps([severity_counts.get(sev, 0) for sev in severity_order])
    }


    
    return render(request, 'scanner/home.html', {
        'vulnerabilities': vulnerabilities,
        'available_sources': available_sources,
        'query': query,
        'selected_source': source_filter,
        'chart_data': chart_data
    })
