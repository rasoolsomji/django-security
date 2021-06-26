# models.py
class PasswordResetRequest(models.Model):
	# Note that you do not want to ForeignKey into the User model
	# You want to log all attempts, whether the username exists or not
	username = models.CharField(max_length=100)
	date = models.DateTimeField(auto_now_add=True)


# views.py
import random
import sleep
from django.contrib.auth import views as auth_views
from django.utils import timezone
from .models import PasswordResetRequest

class PasswordResetViewOverride(auth_views.PasswordResetView):

   def post(self, request, *args, **kwargs):
    	if request.POST.get('username'):
    		# You can choose to add an increasing delay for each repeated request
    		time.sleep(random.random())
    		# Choose a suitable window for valid re-requests
    		five_minutes_ago = timezone.now() - timezone.timedelta(minutes=5)
    		if PasswordResetRequest.objects.filter(
    			username=request.POST['username'],
    			date__gte=five_minutes_ago
    		).exists():
    			# Send a message to the front-end
    			# messages.info(
    				# self.request,
    				# "You have recently requested a password reset, please check your emails"
				# )
				# Log a duplicate request
				# logger.warn()
				return self.form_invalid(self.get_form())
			PasswordResetRequest.objects.create(username=request.POST['username'])
		return super().post(self, request, *args, **kwargs)


 class PasswordResetConfirmOverride(auth_views.PasswordResetConfirmView):

    def get(self, request, *args, **kwargs):
    	if self.user:
    		FailedLoginAttempt.objects.filter(username=self.user.username).delete()
		return super().get(self, request, *args, **kwargs)
