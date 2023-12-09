# views.py
from pyexpat.errors import messages
from django.shortcuts import render, redirect
from .models import UserProfile
from DocOrgnizerMaria.settings import EMAIL_HOST_USER
from .forms import SignUpForm 
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage
from django.contrib import messages
from .tokens import account_activation_token,reset_password_token
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import PasswordResetView
from .forms import ForgotPasswordForm, PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.http import HttpResponseRedirect


def sign_up(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.is_active = False
            user.save()
            activateEmail(request, user, form.cleaned_data.get('email'))
            return redirect(reverse('login')) # Redirect to a success page or login page
    else:
        form = SignUpForm()


    return render(request, 'registreation/signup.html', {'form': form})

def activateEmail(request, user, to_email):
    mail_subject = 'Activate your user account.'
    message = render_to_string('activate_account.html', {
        'user': user.full_name,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
            received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else:
        messages.error(request, f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        if user.is_active:
            # User is already active, display an error message
            messages.error(request, 'Account is already activated. Please try logging in.')
        else:
            # Activate the user account
            user.is_active = True
            user.save()
            messages.success(request, f'Dear <b>{user}</b>, Thank you for your email confirmation. Now you can log in to your account.')
    else:
        # Invalid activation link, display an error message
        messages.error(request, 'Activation link is invalid, it can only be used once. Please check your email or contact support.')

    return redirect('login')

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            User = get_user_model()

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "This email address is not associated with any account.")
                return render(request, 'registreation/forgoturpassword.html', {'form': form})

            if not user.is_active:
                messages.error(request, "This account is not active.")
                return render(request, 'registreation/forgoturpassword.html', {'form': form})

            send_reset_email(request, user, email)
            #return redirect(reverse('login'))  # Redirect to login page after sending reset email
    else:
        form = ForgotPasswordForm()

    return render(request, 'registreation/forgoturpassword.html', {'form': form})

from .tokens import PasswordResetTokenGenerator    
reset_password_token = PasswordResetTokenGenerator()

def send_reset_email(request, user, to_email):
    if user.is_active:
        mail_subject = 'Reset Your Password.'
        message = render_to_string('reset_password.html', {
            'user': user.full_name,
            'domain': get_current_site(request).domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': reset_password_token.make_token(user),
            'protocol': 'https' if request.is_secure() else 'http'
        })

        email = EmailMessage(mail_subject, message, to=[to_email])
        if email.send():
            messages.success(request,f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
            the received Password Reset link to reset your password. <b>Note:</b> Check your spam folder.')
        else:
            messages.error(request, f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')
            
            
reset_password_token = PasswordResetTokenGenerator()
def reset_password(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and reset_password_token.check_token(user, token):
        if request.method == 'POST':
            form = PasswordResetForm(request.POST)
            if form.is_valid():
                # Set the password using set_password to ensure it's properly hashed
                user.set_password(form.cleaned_data['password'])
                user.save()

                messages.success(request, "Password reset successfully. You can now log in with your new password.")
                return redirect(reverse('login'))  # Redirect to a success page or login page
            else:
                for error in form.non_field_errors():
                    messages.error(request, error)
        else:
            form = PasswordResetForm()

        return render(request, 'registreation/reseturpassword.html', {'form': form, 'reset_error': None})
    else:

        messages.error(request, 'Invalid password reset link. Please request a new one.')

    # Display the error message on the same password reset page
    form = PasswordResetForm()  # Ensure form is initialized for rendering
    return render(request, 'registreation/login.html', {'form': form, 'reset_error': 'Invalid password reset link. Please request a new one.'})
    

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .forms import SignInViaEmailOrUsernameForm
from django.utils.translation import gettext as _
import logging

def login_view(request):
    if request.method == 'POST':
        form = SignInViaEmailOrUsernameForm(request.POST)

        if form.is_valid():
            # Authentication
            username_or_email = form.cleaned_data['email_or_username']
            password = form.cleaned_data['password']
            # Use the correct field for authentication (email in this case)
            user = authenticate(request, username=username_or_email, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  # Redirect to the desired URL after successful login
            else:
                # Authentication failed
                form.add_error(None, _('Invalid login credentials'))
    
    else:
        form = SignInViaEmailOrUsernameForm()

    return render(request, 'registreation/login.html', {'form': form})
   

def home_view(request):
    return render(request, 'home.html')

def about_us(request):
    return render(request, 'registreation/about.html')




