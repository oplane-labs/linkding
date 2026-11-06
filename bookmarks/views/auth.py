import time

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth import views as auth_views
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from bookmarks.services import mfa
from bookmarks.widgets import FormErrorList

MFA_PENDING_USER_ID = "mfa_pending_user_id"
MFA_PENDING_AT = "mfa_pending_at"
MFA_PENDING_BACKEND = "mfa_pending_backend"
MFA_PENDING_NEXT = "mfa_pending_next"
MFA_PENDING_MAX_AGE = 5 * 60


class LinkdingLoginView(auth_views.LoginView):
    """
    Custom login view to lazily add additional context data
    Allows to override settings in tests
    """

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.error_class = FormErrorList
        return form

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["enable_oidc"] = settings.LD_ENABLE_OIDC
        context["disable_login"] = settings.LD_DISABLE_LOGIN_FORM
        return context

    def post(self, request, *args, **kwargs):
        # Disabling the login form must also disable password login, not only
        # hide the form
        if settings.LD_DISABLE_LOGIN_FORM:
            raise PermissionDenied()
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.get_user()
        if not mfa.is_enabled(user):
            return super().form_valid(form)

        # Password is correct, but no session is created until the second step
        session = self.request.session
        session.cycle_key()
        session[MFA_PENDING_USER_ID] = user.pk
        session[MFA_PENDING_AT] = int(time.time())
        session[MFA_PENDING_BACKEND] = user.backend
        # get_redirect_url validates the URL with url_has_allowed_host_and_scheme
        session[MFA_PENDING_NEXT] = self.get_redirect_url()
        return HttpResponseRedirect(reverse("login_mfa"))

    def form_invalid(self, form):
        """
        Return 401 status code on failed login. Should allow integrating with
        tools like Fail2Ban. Also, Hotwired Turbo requires a non 2xx status
        code to handle failed form submissions.
        """
        response = super().form_invalid(form)
        response.status_code = 401
        return response


def login_mfa(request):
    if settings.LD_DISABLE_LOGIN_FORM:
        raise PermissionDenied()

    user = _get_pending_user(request)
    if user is None:
        _clear_pending(request)
        return HttpResponseRedirect(settings.LOGIN_URL)

    if request.method != "POST":
        return render(request, "registration/login_mfa.html")

    result = mfa.verify(user, request.POST.get("code", ""))
    if result == mfa.VerifyResult.OK:
        backend = request.session[MFA_PENDING_BACKEND]
        next_url = request.session.get(MFA_PENDING_NEXT)
        # login() rotates the session key
        login(request, user, backend=backend)
        _clear_pending(request)
        return HttpResponseRedirect(next_url or settings.LOGIN_REDIRECT_URL)

    # Return 401 status code for Fail2Ban, same as the password step
    if result == mfa.VerifyResult.LOCKED:
        _clear_pending(request)
        context = {"locked": True}
    else:
        context = {"invalid": True}
    return render(request, "registration/login_mfa.html", context, status=401)


def _get_pending_user(request):
    session = request.session
    user_id = session.get(MFA_PENDING_USER_ID)
    pending_at = session.get(MFA_PENDING_AT)
    if user_id is None or pending_at is None:
        return None
    if time.time() - pending_at > MFA_PENDING_MAX_AGE:
        return None
    # MFA can be removed while the login is pending, for example by reset_mfa
    return User.objects.filter(pk=user_id, is_active=True, mfa__enabled=True).first()


def _clear_pending(request):
    for key in (
        MFA_PENDING_USER_ID,
        MFA_PENDING_AT,
        MFA_PENDING_BACKEND,
        MFA_PENDING_NEXT,
    ):
        request.session.pop(key, None)


class LinkdingPasswordChangeView(auth_views.PasswordChangeView):
    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.error_class = FormErrorList
        return form

    def form_invalid(self, form):
        """
        Hotwired Turbo requires a non 2xx status code to handle failed form
        submissions.
        """
        response = super().form_invalid(form)
        response.status_code = 422
        return response
