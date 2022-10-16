from django.urls import path

from . import views

urlpatterns = [
   path('login/', views.loginPage,name='login'),
   path('register/', views.register,name='register'),
   path('logout/', views.logoutUser, name='logout'),
   path('dashboard/', views.dashboard, name='dashboard'),
   path('upload/', views.upload_file, name='upload'),

]