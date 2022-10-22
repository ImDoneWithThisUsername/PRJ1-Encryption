from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
   path('login/', views.loginPage,name='login'),
   path('register/', views.register,name='register'),
   path('logout/', views.logoutUser, name='logout'),
   path('dashboard/', views.dashboard, name='dashboard'),
   path('send_file/', views.sendFile, name='send_file'),
   path('change_info/', views.changeInfo, name='change_info'),
   path('input_password/<int:id>', views.input_password, name='input_password'),
   path('upload_signature/', views.upload_signature, name='upload_signature'),
   path('validate_signature/', views.validate_signature, name='validate_signature'),
   path('signature_list/', views.signature_list, name='signature_list'),
   
   

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)