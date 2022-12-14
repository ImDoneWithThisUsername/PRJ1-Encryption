from django.contrib.auth.forms import UserCreationForm
from django import forms
from .models import *

class CreateCustomUserForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['email', 'password1', 'password2']

class UploadFileForm(forms.ModelForm):
    # temp_document = forms.FileField(widget=forms.FileInput())
    class Meta:
        model = Document
        fields = ['document']

class ChangeCustomUserForm(forms.ModelForm):
    old_password = forms.CharField(widget=forms.PasswordInput(),required=False)
    password1 = forms.CharField(widget=forms.PasswordInput(), required=False)
    password2 = forms.CharField(widget=forms.PasswordInput(), required=False)
    
    class Meta:
        model = CustomUser
        fields = ['name', 'birth', 'phone', 'address','old_password', 'password1', 'password2']


class UploadSignatureDocumentForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        model = SignatureDocument
        fields = ['document','password']


        
class UploadValidateDocumentForm(forms.ModelForm):
    class Meta:
        model = ValidateDocument
        fields = ['document']