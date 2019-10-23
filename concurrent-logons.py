# models.py
class UserSession(models.Model):
    user_id = models.PositiveIntegerField()
    session_key = models.CharField(max_length=40)


# views.py
# ...
# To be inserted after a successful login
user_sessions = UserSession.objects.filter(user_id=user.id)
session_keys = user_sessions.values_list('session_key', flat=True)
Session.objects.filter(session_key__in=session_keys).delete()
user_sessions.delete()
UserSession.objects.create(user_id=user.id, session_key=request.session.session_key)
# ...