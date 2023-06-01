from .settings import PASS_REQ

def isauth_context_processor(request):
    return {
        'isAuthenticated': request.COOKIES.get('isAuthenticated'),
        'pass_policy': PASS_REQ,
        'userName': request.COOKIES.get('userName'),
    }
