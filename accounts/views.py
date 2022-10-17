from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import *
from .forms import *
from .encryption import *

def register(request):
    form = CreateCustomUserForm()

    if request.method == 'POST':
        form = CreateCustomUserForm(request.POST)

        if form.is_valid():
            user = form.save()

            key = generate_rsa_key()
            cipherkey, tag, nonce = encrypt_rsa_private_key(user.passphrase,key.export_key())
            
            user.private_key = concanate_nonce_tag_cipherkey(cipherkey, tag, nonce)
            user.public_key = key.public_key().export_key()

            user.save()
            #group = Group.objects.get(name='custom_user')

            #if group == None:
            #    raise ValueError('Chưa có group custom_user')

            #user.groups.add(group)

            messages.success(request, 'Tạo tài khoản thành công.')
            return redirect('login')

    context = {'form':form}
    return render(request, 'pages/register.html', context)

def loginPage(request):

    if request.method == 'POST':

        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)

        if email == '':
            messages.error(request, 'Email không được để trống')

        elif password == '' : 
            messages.error(request, 'Mật khẩu không được bỏ trống')

        elif user is not None:
            login(request, user)
            return redirect('dashboard')

        else: 
            messages.error(request, 'Email hoặc mật khẩu chưa đúng.')
            
    context = {}
    return render(request, 'pages/login.html', context)

def logoutUser(request):
    logout(request)
    return redirect('login')

def dashboard(request):
    email = request.user
    user = CustomUser.objects.get(email=email)
    files = Document.objects.filter(receiver=user)
    context = {

        'files':files
    }

    return render(request, 'pages/dashboard.html', context)

def send_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)

        if form.is_valid():
            rec_email = request.POST['receiver']
            rec = CustomUser.objects.filter(email=rec_email).exists()

            if rec is True:
                rec = CustomUser.objects.get(email=rec_email)
            else:
                messages.error(request, 'Không có người nhận với email này.')
                return redirect('send_file')

            file = form.save(commit=False)
            file.receiver = rec
            file.sender = request.user

            file.save()
            messages.success(request, 'Gửi file thành công.')
            return redirect('send_file')
    else:
        form = UploadFileForm()
    return render(request, 'pages/send_file.html', {'form': form})