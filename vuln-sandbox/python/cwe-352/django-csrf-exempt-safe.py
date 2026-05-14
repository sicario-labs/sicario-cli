# SAFE: django-csrf-exempt — CSRF protection enabled (no @csrf_exempt decorator)
# Rule: DjangoCsrfExempt | CWE-352 | Expected: TrueNegative

from django.views import View
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator


@method_decorator(login_required, name='dispatch')
class UpdateProfileView(View):
    """Profile update view with CSRF protection enabled (default Django behavior)."""

    # SAFE: no @csrf_exempt decorator; Django's CsrfViewMiddleware validates the token
    def post(self, request):
        data = request.POST
        username = data.get('username', '').strip()
        if not username:
            return JsonResponse({'error': 'Username required'}, status=400)
        request.user.username = username
        request.user.save()
        return JsonResponse({'status': 'updated'})
