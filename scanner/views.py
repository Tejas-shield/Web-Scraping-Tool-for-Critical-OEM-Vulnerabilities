from django.shortcuts import render
from .models import Vulnerability
from django.db.models import Q

def home(request):
    query = request.GET.get('q')
    source_filter = request.GET.get('source')

    vulns = Vulnerability.objects.all()

    if query:
        vulns = vulns.filter(Q(title__icontains=query) | Q(link__icontains=query))

    if source_filter and source_filter != 'all':
        vulns = vulns.filter(source__iexact=source_filter)

    context = {
        'vulns': vulns.order_by('-date_scraped'),
        'query': query or '',
        'selected_source': source_filter or 'all',
        'available_sources': Vulnerability.objects.values_list('source', flat=True).distinct()
    }
    return render(request, 'scanner/home.html', context)
