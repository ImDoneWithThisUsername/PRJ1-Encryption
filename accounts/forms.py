from django.contrib.auth.forms import UserCreationForm
from .models import *

class CreateCustomUserForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['email', 'password1', 'password2']