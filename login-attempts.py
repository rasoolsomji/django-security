# models.py
class FailedLoginAttempt(models.Model):	
	# Note that you do not want to ForeignKey into the User model
	# You want to log all attempts, whether the username exists or not
	username = models.CharField(max_length=100)
	date = models.DateTimeField(auto_now_add=True)


# views.py
def login(request):
    ALLOWED_LOGIN_ATTEMPTS = 4

    if request.method == 'POST':
        username = request.POST['username']
        stripped_username = username.strip().lower()
        if FailedLoginAttempt.objects.filter(
            username=stripped_username
    	).count() > ALLOWED_LOGIN_ATTEMPTS:
            # Send a message, redirect, add a delay
        else:
            password = request.POST['password']
            user = authenticate(request, username=stripped_username, password=password)
            if user is not None:
                auth_login(request, user)
                FailedLoginAttempt.objects.filter(username=user.email).delete()
                # Redirect
            else:
                if request.POST.get('username'):
                    FailedLoginAttempt.objects.create(username=stripped_username)
                # Send a message, add a delay
