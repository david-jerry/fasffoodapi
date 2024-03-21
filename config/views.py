from django.shortcuts import redirect
from django.contrib.auth.views import LoginView

from chowapi.users.forms import PhonePinAdminAuthenticationForm

def redirect_home_view(request):
    if request.user.is_authenticated:
        return redirect("/api/v1/docs/")
    return redirect("admin:index")

class CustomAdminLoginView(LoginView):
    authentication_form = PhonePinAdminAuthenticationForm
