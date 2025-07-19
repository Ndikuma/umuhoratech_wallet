from django.contrib import admin
from django.urls import path, include
from wallet import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('send/', views.send_transaction, name='send'),
    path('history/', views.transaction_history, name='history'),
]