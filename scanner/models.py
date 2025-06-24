from django.db import models

class Vulnerability(models.Model):
    title = models.CharField(max_length=300)
    source = models.CharField(max_length=100)
    link = models.URLField()
    severity = models.CharField(max_length=20, blank=True, null=True)  # NEW FIELD
    score = models.FloatField(blank=True, null=True)  # NEW FIELD
    date_scraped = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
