from django.urls import path

from . import views

urlpatterns = [
   path('login/', views.loginPage,name='login'),
   path('register/', views.register,name='register'),
   path('logout/', views.logoutUser, name='logout'),
   path('dashboard/', views.dashboard, name='dashboard'),
   path('send_file/', views.send_file, name='send_file'),

]