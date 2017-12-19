from django.contrib import admin
from .models import Domain, SSLResult, PSHTTResult

# Register your models here.

admin.site.register(Domain)
admin.site.register(SSLResult)
admin.site.register(PSHTTResult)
