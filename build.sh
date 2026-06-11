#!/usr/bin/env bash
pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate

# Create superuser automatically
python manage.py shell -c "
from accounts.models import CustomUser
if not CustomUser.objects.filter(email='admin@arms.edu.ph').exists():
    user = CustomUser.objects.create_superuser(
        email='admin@arms.edu.ph',
        username='admin',
        password='Admin123!@#',
        first_name='Admin',
        last_name='User'
    )
    # Set salt and pepper for the admin
    import secrets, os
    user.salt = secrets.token_hex(32)
    pepper = os.environ.get('PASSWORD_PEPPER', 'default-pepper')
    peppered_password = f'Admin123!@#{user.salt}{pepper}'
    from django.contrib.auth.hashers import make_password
    user.password = make_password(peppered_password)
    user.is_staff = True
    user.is_superuser = True
    user.save()
    print('Superuser created successfully!')
else:
    print('Superuser already exists.')
"