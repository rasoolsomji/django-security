import http.cookies as Cookie
from django.conf import settings


Cookie.Morsel._reserved['samesite'] = 'SameSite'


def cookies_samesite(get_response):

    def middleware(request):

        response = get_response(request)
        for cookie in [settings.CSRF_COOKIE_NAME, settings.SESSION_COOKIE_NAME]:
            if cookie in response.cookies:
                response.cookies[cookie]['samesite'] = 'lax'

        return response

    return middleware
