from django.shortcuts import render, redirect
from django.core.management import call_command
from .models import Domain 


def index(request):
    domains = Domain.objects.all()
    return render(request, 'scans/index.html', {'domains':domains})

def scan_now(request):
	call_command('runscan')
	return redirect('index')
