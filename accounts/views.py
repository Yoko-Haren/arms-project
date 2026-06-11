from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm
from .models import get_secret_pepper
import json
import re
import secrets

User = get_user_model()

@require_http_methods(["GET", "POST"])
def signin_view(request):
    """Login view for ARMS"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    form = LoginForm()
    error = None
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            remember = form.cleaned_data.get('remember', False)
            
            # Try to authenticate with email or username
            user = None
            
            # Check if input is email
            if '@' in username:
                try:
                    user_obj = User.objects.get(email=username)
                    user = authenticate(request, username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            else:
                user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    
                    # Set session expiry based on remember me
                    if not remember:
                        request.session.set_expiry(0)  # Browser close
                    
                    messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
                    
                    # Redirect to next or dashboard
                    next_url = request.GET.get('next', 'dashboard')
                    return redirect(next_url)
                else:
                    error = 'Your account has been disabled. Contact support.'
            else:
                error = 'Invalid email/username or password. Please try again.'
        else:
            error = 'Please correct the errors below.'
    
    context = {
        'form': form,
        'error': error,
    }
    return render(request, 'accounts/login.html', context)

@require_http_methods(["GET", "POST"])
def register_view(request):
    """Registration view for new users"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    error = None
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        
        # Validation
        errors_list = []
        
        if not email:
            errors_list.append('Email is required.')
        elif not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            errors_list.append('Please enter a valid email address.')
        elif User.objects.filter(email=email).exists():
            errors_list.append('This email is already registered.')
        
        if not username:
            errors_list.append('Username is required.')
        elif len(username) < 3:
            errors_list.append('Username must be at least 3 characters.')
        elif User.objects.filter(username=username).exists():
            errors_list.append('This username is already taken.')
        
        if not first_name:
            errors_list.append('First name is required.')
        
        if not last_name:
            errors_list.append('Last name is required.')
        
        if not password:
            errors_list.append('Password is required.')
        else:
            if len(password) < 12:
                errors_list.append('Password must be at least 12 characters.')
            if not re.search(r'[A-Z]', password):
                errors_list.append('Password must contain at least one uppercase letter.')
            if not re.search(r'[a-z]', password):
                errors_list.append('Password must contain at least one lowercase letter.')
            if not re.search(r'[0-9]', password):
                errors_list.append('Password must contain at least one number.')
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors_list.append('Password must contain at least one special character.')
        
        if password != confirm_password:
            errors_list.append('Passwords do not match.')
        
        if errors_list:
            error = errors_list[0]
        else:
            # Create user
            try:
                user = User.objects.create_user(
                    email=email,
                    username=username,
                    password=password,  # Django handles the hashing
                    first_name=first_name,
                    last_name=last_name,
                )
                
                # Set salt for record keeping (but use Django's default hashing)
                user.salt = secrets.token_hex(32)
                user.save()
                
                messages.success(request, 'Registration successful! Please sign in with your credentials.')
                return redirect('signin')
                
            except Exception as e:
                error = f'An error occurred during registration. Please try again.'
                print(f"Registration error: {e}")
    
    context = {
        'error': error,
    }
    return render(request, 'accounts/register.html', context)

def signout_view(request):
    """Logout view"""
    logout(request)
    messages.info(request, 'You have been successfully logged out.')
    return redirect('signin')

@require_http_methods(["POST"])
def password_reset_request_view(request):
    """Handle password reset request via AJAX"""
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        
        # Basic email validation (no domain restriction)
        if not email or not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return JsonResponse({
                'success': False,
                'error': 'Please enter a valid email address.'
            })
        
        try:
            user = User.objects.get(email=email)
            
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Build reset URL
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            
            # Send email
            subject = 'Password Reset Request - ARMS'
            message = f'''
Hello,

You have requested to reset your password for your ARMS account.

Please click the link below to reset your password:
{reset_url}

If you did not request this, please ignore this email and your password will remain unchanged.

Thank you,
ARMS Team
            '''
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset link sent! Check your inbox.'
            })
            
        except User.DoesNotExist:
            # Don't reveal if user exists for security
            return JsonResponse({
                'success': True,
                'message': 'If this email is registered, a reset link has been sent.'
            })
            
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request data.'})

@login_required
def dashboard_view(request):
    """Main dashboard after login"""
    context = {
        'user': request.user,
        'page_title': 'Dashboard',
    }
    return render(request, 'accounts/dashboard.html', context)