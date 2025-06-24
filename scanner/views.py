from django.shortcuts import render
from .models import Vulnerability
from django.db.models import Q

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

    sources = Vulnerability.objects.values_list('source', flat=True).distinct()

    return render(request, 'scanner/home.html', {
        'vulnerabilities': vulnerabilities,
        'available_sources': sources,
        'query': query,
        'selected_source': source_filter,
    })
