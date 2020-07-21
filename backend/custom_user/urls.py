from django.urls import path
from . import views

urlpatterns = [
    path('login_user/', views.login_user,name='login_user'),
    path('refresh_token/', views.refresh_token,name='refresh_token'),
    path('simple_user/', views.simple_user,name='simple_user'),
]
