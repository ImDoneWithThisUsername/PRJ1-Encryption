from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
   path('login/', views.loginPage,name='login'),
   path('register/', views.register,name='register'),
   path('logout/', views.logoutUser, name='logout'),
   path('dashboard/', views.dashboard, name='dashboard'),
   path('send_file/', views.send_file, name='send_file'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)