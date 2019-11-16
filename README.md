# Security tips for your Django project

1. [HTTP Headers](#http-headers)
    1. [HTTP Strict Transport Security (HSTS)](#hsts)
    2. [Content Security Policy (CSP)](#csp)
    3. [X-Content-Type-Options](#x-content-type-options)
2. [Cookies](#cookies)
    1. [Rename Django defaults](#rename-cookies)
    2. [CSRF Settings](#csrf-settings)
    3. [Disuse 'expires' attribute](#cookie-expires)
    4. [Add SameSite attribute](#samesite)
    5. [Add Secure attribute](#cookies-secure)
3. [User Management](#user-management)
    1. [Username enumeration](#username-enumeration)
    1. [Forgot password limit](#forgot-password-limit)
    2. [Incorrect password limit](#incorrect-password-limit)
    3. [Require strong passwords](#strong-passwords)
    4. [Transferable sessions](#transferable-sessions)
    5. [Concurrent logons](#concurrent-logons)
    6. [Require password change](#require-password-change)
4. [Webserver Settings](#webserver-settings)
    1. [Disable support for old TLS versions](#tls-versions)
    2. [Disable support for old TLS ciphers](#tls-ciphers)
    3. [Rate limit](#rate-limit)
5. [Admin](#admin)
    1. [Don't use /admin/](#change-admin-url)
    2. [Updating insecure version of jQuery](#insecure-jquery)
    

## HTTP Headers <a name="http-headers"></a>
### HTTP Strict Transport Security (HSTS) <a name="hsts"></a>

#### Vulnerabilities: 
_SSL-stripping, man-in-the-middle_
#### One-liner:
Forces browsers to redirect non-HTTP traffic to HTTPS
#### Further detail:
[OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
#### Implementation:
Django >= 1.8 allows you set the setting ```SECURE_HSTS_SECONDS``` (and ```SECURE_HSTS_INCLUDE_SUBDOMAINS``` etc)

Alternatively you can add the following line to your server block in your nginx configuration:

```
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

#### Things to note
- If you `includeSubDomains` / [`SECURE_HSTS_INCLUDE_SUBDOMAINS`](https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-SECURE_HSTS_INCLUDE_SUBDOMAINS), it may break other site functionality.  For example, if you use SendGrid for sending emails with click tracking links, it does not work with HTTPs without [further configuration](https://sendgrid.com/docs/ui/analytics-and-reporting/click-tracking-ssl/)
- If you use the nginx `add_header` method, make sure it covers all relevant location blocks, such as your static files or user-uploaded files. You may need to add that add_header directive within your `location /static/` or `location /uploads/` blocks

### Content Security Policy (CSP) <a name="csp"></a>
#### Vulnerabilities:
_XSS_
#### One-liner:
You whitelist valid sources of executable scripts.
#### Further-detail:
[Mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
#### Implementation:
Django does not support this out of the box, so you need to either use a 3rd-party library, or you can use a `<meta http-equiv="Content-Security-Policy">` tag within your HTML.

#### Things to note
- A (good) CSP-policy will break all inline scripts and styles!  So make sure you are only using external stylesheets and javascript files.
- You need to include external sources (such as script files from CDNs)
- You have the ability to [test your policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#Testing_your_policy) before it takes effect

### X-Content-Type-Options <a name="x-content-type-options"></a>
#### Vulnerabilities:
_XSS_
#### One-liner:
Preventing the execution of malicious files.
#### Further detail:
[Mozilla documentation](https://infosec.mozilla.org/guidelines/web_security#x-content-type-options)
#### Implementation:
Django >= 1.8 allows you set the setting `SECURE_CONTENT_TYPE_NOSNIFF` which you ought to set to `True`

Alternatively you can add the following line to your server block in your nginx configuration:

```
add_header X-Content-Type-Options "nosniff";
```


## Cookies <a name="cookies"></a>
### Rename Django defaults <a name="rename-cookies">
#### Vulnabilities:
_Information exposure_
#### One liner:
The Django default names for cookies mean than an attacker knows to probe Django-specific weaknesses
#### Further Detail:
[CWE](https://cwe.mitre.org/data/definitions/200.html)
#### Implementation:
Since at least Django 1.4, you can edit the setting `SESSION_COOKIE_NAME` from it's default of `'sessionid'`. 

Since Django 1.2, you can edit the setting `CSRF_COOKIE_NAME` from it's default of `'csrftoken'`

#### Things to note:
- Renaming the CSRF cookie is redundant if you [put the CSRF cookie in the session cookie](#csrf-use-sessions)

### CSRF Settings <a name="csrf-settings"></a>
#### Vulnabilities:
_CSRF attack, Information exposure_
#### One liner:
If an attacker could acquire the CSRF cookie value, due to their long expiry (1 year by default), they could use it to submit a form as a user.
#### Further detail:
[OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
#### Implementation:
Since Django 1.11, you can change the setting `CSRF_USE_SESSIONS` to `True`.

Alternatively or for older versions, you can shorten the expiry of the cookie, as of Django 1.7 this is done with the setting `CSRF_COOKIE_AGE`.  You can also try writing custom middleware which regenerates the CSRF-token on a per-request basis.

#### Things to note:
- As Django's own documentation states:
>Storing the CSRF token in a cookie (Django’s default) is safe, but storing it in the session is common practice in other web frameworks and therefore sometimes demanded by security auditors.
- Setting the CSRF token to a shorter expiry may annoy users, as any form they leave in the background for a while or load from a bookmark will fail.

### Disuse 'expires' attribute <a name="cookie-expires"></a>
#### Vulnerabilities:
_Account/session takeover_
#### One-liner:
The expires attribute writes the session cookie to the browser persistently, this can then be used by an attacker or someone sharing the same device.
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/Testing_for_cookies_attributes_%28OTG-SESS-002%29)
#### Implementation:
Change the setting `SESSION_EXPIRE_AT_BROWSER_CLOSE` to `True`.  This setting has existed since Django 1.4

### Add SameSite attribute <a name="samesite"></a>
#### Vulnerabilities:
_CSRF attack, information exposure_
#### One-liner:
Adding this attribute prevents sending cookies (like Django's session id) when requesting resources (eg. images, fonts, scripts) hosted elsewhere.
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/SameSite)
#### Implementation:
Django 2.1 introduced `CSRF_COOKIE_SAMESITE` and `SESSION_COOKIE_SAMESITE`.  Previous versions may make use of custom middleware - an example, tested in v2.0 can be found [here](samesite-middleware.py) - or by intervening at the webserver level.  An albeit crude addition to an Apache config may look like:
``` 
Header edit Set-Cookie ^(.*)$ $1;Samesite=Lax
```
#### Things to note:
- Django 2.1 sets the default SameSite value to 'lax' which is a sensible default, consider before changing it's value to 'strict'

### Add Secure attribute <a name="cookies-secure"></a>
#### Vulnerabilities:
_Session hijacking, man-in-the-middle_
#### One-liner:
Adding this attribute only allows the transmission of cookies over https, if an attacker manages to get a user to use http, they will not be able to read the cookies.
#### Further Detail:
[Pivotpoint blog](https://www.pivotpointsecurity.com/blog/securing-web-cookies-secure-flag/)
#### Implementation:
Django 2.1 introduced `CSRF_COOKIE_SAMESITE` and `SESSION_COOKIE_SAMESITE`.  Previous versions may make use of custom middleware - an example, tested in v2.0 can be found [here](samesite-middleware.py) - or by intervening at the webserver level.  An albeit crude addition to an Apache config may look like:
``` 
Header edit Set-Cookie ^(.*)$ $1;Samesite=Lax
```
#### Things to note:
- Django 2.1 sets the default SameSite value to 'lax' which is a sensible default, consider before changing it's value to 'strict'

## User Management <a name="user-management"></a>
### Username enumeration <a name="username-enumeration"></a>
#### Vulnerabilities:
_phishing, brute force_
#### One-liner:
You ought to treat non-existent usernames/email addresses the same as existing ones, so as not to reveal this information to an attacker who can for example, look up where else this username is used, if it exists in any data breaches, and can target that user directly. 
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002))
#### Implementation:
This vulnerability can occur in several places, including:
- **Registration**. You ought not to state that a username/email address already exists as an error message to the user.
- **Forgotten password**. You ought not to treat existing usernames/email addresses any differently to non-existing ones.
- **Login**. You should not display a specific error message if the username does not exist, but rather a generic message like: "Incorrect username or password"
- **URL Parameter**. Applications sometimes have /<username>/ as part of the URL structure, and if you return a 404 error if the username does not exist but a 403 error if the username does exist but you are not allowed to see it, that can be used to enumerate usernames.
#### Things to note:
- By default Django already prevents this on the provided forgotten password view, by displaying a success message whether or not the user account exists.

### Forgot password limit <a name="forgot-password-limit"></a>
#### Vulnerabilities:
_DoS, money waste_
#### One-liner:
An attacker can repeatedly hit your 'Forgot password' endpoint, prompting the sending of many emails which could cost you money or lead to a denial-of-service.
#### Further Detail:
[Cloudflare on Denial-of-Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/)
#### Implementation:
There are several non-mutually-exclusive methods you can employ:
- Log each forgotten password request, and only further process the request (and send emails) if there hasn't been a request for that particular username  and/or IP address recently
- Add an (increasing) delay in responding to repeated forgotten password requests
- Add a CAPTCHA or some other dynamic field that is required before processing the request.

You can see an example implementation [here](forgotten-password.py) using the PasswordResetView class-based view, introduced in Django 1.11

#### Things to note:
- You don't want to leak information about valid and invalid usernames (see [username enumeration](#username-enumeration)) so make sure you treat requests for valid and invalid usernames the same.

### Incorrect password limit <a name="incorrect-password-limit"></a>
#### Vulnerabilities:
_Brute force_
#### One-liner:
Without a limit, an attacker can repeatedly try different passwords to gain access to a user's account.
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks)
#### Implementation:
There are several non-mutually-exclusive methods you can employ:
- 'Lock' accounts with too many failed attempts
- Add an (increasing) delay in responding to repeated login attempts
- Add a CAPTCHA or some other dynamic field that is required before processing the request
- Monitor IP address / user agent to detect patterns anomalous to the user's usual usage

You can see an example implementation [here](login-attempts.py)

#### Things to note:
- You don't want to leak information about valid and invalid usernames (see [username enumeration](#username-enumeration)) so make sure you treat requests for valid and invalid usernames the same.

### Require strong passwords <a name="strong-passwords"></a>
#### Vulnerabilities:
_Brute force, credential stuffing_
#### One-liner:
Some security auditors require stronger password validation than Django's default.  It can also ensure they are less easily guessed by an attacker.
#### Further Detail:
[Wikipedia](https://en.wikipedia.org/wiki/Password_strength)
#### Implementation:
Depending on your version of Django, it usually comes with a few useful validators, such as minimum length, and similarity to other user attributes.  These can be modified (for example increasing the minimum length):

```
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    # ...
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 10,
        }
    },
    # ...
]
```

Or you can write your own.  Example validators (tested with v2.0) for requiring special characters and a combination of numbers, uppercase, and lowercase letters can be found [here](password-validators.py).  These can then be added to the `AUTH_PASSWORD_VALIDATORS` setting.

#### Things to note:
- Requiring special characters or other demanding rules in itself can be a vulnerability, as users may write down their password, or re-use a stock 'strong' password across several sites.

### Transferable Sessions <a name="transferable-sessions"></a>
#### Vulnerabilities:
_XSS, session highjacking_
#### One-liner:
If an attacker acquires the value of the session cookie, they are able to use it to authenticate requests from their own device.
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/Session_hijacking_attack)
#### Implementation:
One needs to ensure that each user session is linked to a particular device, so something like a middleware which stores the user agent / IP address of a user at the start of a session, and invalidates the session if it detects a different user agent / IP address on any subsequent request.
#### See also:
[Concurrent Logons](#concurrent-logons)

### Concurrent Logons <a name="concurrent-logons"></a>
#### Vulnerabilities:
_XSS, session highjacking_
#### One-liner:
If an attacker acquires the value of the session cookie, they are able to use it to authenticate requests from their own device at the same time as the original user.
#### Further Detail:
[OWASP](https://www.owasp.org/index.php/Session_hijacking_attack)
#### Implementation:
One needs to ensure that when logging in, all existing sessions associated with that user account are deleted.  An example implementation can be found [here](concurrent-logons.py).
#### Things to note:
- You may want to implement something like this for reasons other than security - for example to prevent data from being changed simultaneously from two locations, or to prevent the sharing of login credentials.

#### See also:
[Transferable Sessions](#transferable-sessions)

### Require Password Change <a name="require-password-change"></a>
#### Vulnerabilities:
_auditability, non-repudiation_
#### One-liner:
When you create an account for a user and provide them with the credentials, the user should be required to change their password when they first login, so that their password is known only to them.
#### Further Detail:
[Techopedia](https://www.techopedia.com/definition/4031/nonrepudiation)
#### Implementation:
Add a boolean field to your user model that is set to `True` when you have manually created their account.  When this user logs in, redirect them to the change password form, optionally with a message explaining why.  On a successful completion of the change password form, this field can be set to `False`.

## Webserver Settings <a name="webserver-settings"></a>
### Disable support for old TLS versions <a name="tls-versions"></a>
#### Vulnerabilities:
_Padding oracle attack, BEAST, POODLE_
#### One-liner:
Your webserver might by-default support TLS v1.0 and v1.1, and though almost every modern browser will use v1.2, a security auditor might moan about supporting these older protocols.
#### Further Detail:
[Payment
Card Industry Data Security Standard 3.2](https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls)
#### Implementation:
Somewhere on your nginx server will be the line:
```
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
```
And you need to remove the `TLSv1` and `TLSv1.1` statements.
If you used Let's Encrypt for your SSL certificate, you may find this configuration in `/etc/letsencrypt/options-ssl-nginx.conf`

#### Things to note: <a name="certbot-things-to-note">
- If you do use Let's Encrypt and Certbot, the file `options-ssl-nginx.conf`, won't update as you update the certbot package.  The update will instead print out what changes were meant to be made, which you can copy over. [Source](https://community.letsencrypt.org/t/remove-support-for-tls-1-0-1-1-in-nginx/88924/11)

### Disable support for old TLS ciphers <a name="tls-ciphers"></a>
#### Vulnerabilities:
_meet in the middle, downgrade attack_
#### One-liner:
Your TLS setup might by-default support some insecure ciphers which may be allow an attacker to decrypt traffic.
#### Further Detail:
[SSL Labs](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
#### Implementation:
Somewhere on your nginx server will be the line:
```
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...
```
And you need to remove all insecure ciphers. SSL Labs provide a [free analysis](https://www.ssllabs.com/ssltest/index.html) of your site to show which ciphers you currently support and how secure they are.  If you used Let's Encrypt for your SSL certificate, you may find this configuration in `/etc/letsencrypt/options-ssl-nginx.conf`

#### Things to note:
- If you do use Let's Encrypt and Certbot, same as [above](#certbot-things-to-note)

### Rate limit <a name="rate-limit"></a>
#### Vulnerabilities:
_ddos, brute force_
#### One-liner:
Too many HTTP requests from a single source is almost certainly not a legitimate human user and can cause your webserver to fail as it tries to process them.
#### Further Detail:
[Wikipedia](https://en.wikipedia.org/wiki/Rate_limiting)
#### Implementation:
You can either apply a policy globally, or at particularly vulnerable endpoints, which include API endpoints, login pages, or other pages requiring user input.
This [Nginx blog post](https://www.nginx.com/blog/rate-limiting-nginx/) and the [official Apache docs](https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html) explain how to set it up.
#### Things to note:
- Both the Nginx and Apache setups allow for 'bursts' which is a useful feature.  Sometimes HTTP requests will bunch up and be received in a short burst, and this allows to handle these gracefully without returning an error.

## Admin <a name="admin"></a>
### Don't use /admin/ <a name="change-admin-url"></a>
#### Vulnerabilities:
_Information exposure_
#### One-liner:
Because it is conventional to use /admin/ as the url for Django's admin site, it's presense can alert an attacker to the fact that a site is running Django, allowing them to customise their attack methods.
#### Further detail:
[CWE](https://cwe.mitre.org/data/definitions/200.html)
#### Implementation:

In your main `urls.py`, change the URL at which you include `admin.site.urls`:
```
urlpatterns += [
    url(r'^new-secret-location/', admin.site.urls, name='admin')
]
```

### Insecure version of jQuery <a name="insecure-jquery"></a>
#### Vulnerabilities:
_XSS_
#### One-liner:
Django admin ships with jQuery version v2.2.3 (/your/static/url/admin/js/vendor/jquery/jquery.min.js) which has known security issues.
#### Further detail:
[CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9251)
#### Implementation:

1. You can update the jQuery file within your `STATICFILES` folder but this needs to be done every time you update your static files with `collectstatic`
2. You can rewrite requests to the insecure version towards an up-to-date version within your webserver configuration, ie `mod_rewrite` (Apache) / `ngx_http_rewrite_module` (nginx)
For nginx it might look like this:
```
location /your/static/url/admin/js/vendor/jquery/jquery.min.js {
        return 301 /your/static/url/js/patched-jquery.min.js;
    }
```

# Contributing
I am keen to hear suggestions and improvements, please open an issue to discuss!

I am particularly keen on hearing about new vulnerabilities and original ways of mitigating them.
