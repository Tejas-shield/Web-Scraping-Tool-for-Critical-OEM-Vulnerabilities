from django.core.management.base import BaseCommand
from scanner.scraper import scrape_nvd_vulnerabilities

class Command(BaseCommand):
    help = 'Scrapes NVD for critical OEM vulnerabilities and sends email alerts'

    def handle(self, *args, **kwargs):
        scrape_nvd_vulnerabilities()
        self.stdout.write(self.style.SUCCESS('✅ Scraping and alerting completed.'))
