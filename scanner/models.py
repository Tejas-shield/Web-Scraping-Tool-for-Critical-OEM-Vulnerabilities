from django.db import models

class Vulnerability(models.Model):
    title = models.CharField(max_length=255)
    source = models.CharField(max_length=100)
    link = models.URLField()
    date_scraped = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
