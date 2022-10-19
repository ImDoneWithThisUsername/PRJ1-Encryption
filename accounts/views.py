from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
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
            passphrase = form.clean_password2()
            cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase,key.export_key())
            user.private_key = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)
            user.public_key = key.public_key().export_key()

            user.save()
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

def sendFile(request):
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

def changeInfo(request):
    #autofill
    user = request.user
    form = ChangeCustomUserForm(instance=user)
    #submit
    if request.method == 'POST':
        form = ChangeCustomUserForm(request.POST, instance=user)
        if form.is_valid():
            #get old passphrase
            old_password = form.cleaned_data['old_password']
            verify_user = authenticate(request, email=user.email, password=old_password)
            if verify_user == None:
                messages.error(request,'Password cũ không đúng')
                return redirect('change_info')

            #verify new password
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']
            if password1 != password2:
                messages.error(request,'Mật khẩu và xác nhận mật khẩu không giống nhau')
                return redirect('change_info')

            
            #get private key
            cipherkey, tag, nonce = slide_cipherkey_tag_nonce(user.private_key)
            key_decrypt = decrypt_rsa_private_key(old_password, cipherkey, tag, nonce)
            
            user = form.save()
            #encrypt private key with new passphrase
            cipherkey, tag, nonce = encrypt_rsa_private_key(password2, key_decrypt)
            user.private_key = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)
            user.set_password(password2)
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request,'Thay đổi thông tin thành công')
            return redirect('change_info')

    context = {'form':form}
    return render(request, 'pages/change_info.html', context)