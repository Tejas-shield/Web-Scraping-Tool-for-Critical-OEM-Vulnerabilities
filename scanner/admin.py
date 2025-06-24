from django.contrib import admin
from .models import Vulnerability

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'source', 'link', 'date_scraped')
    search_fields = ('title', 'source')
    list_filter = ('source',)
