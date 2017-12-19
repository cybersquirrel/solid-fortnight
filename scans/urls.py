from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan', views.scan_now, name='scan_now'),
]
