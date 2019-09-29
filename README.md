# Security tips for your Django project

1. [HTTP Headers](#http-headers)
    1. [HTTP Strict Transport Security (HSTS)](#hsts)
    2. [Content Security Policy (CSP)](#csp)
    3. [X-Content-Type-Options](#x-content-type-options)
2. [Cookies](#cookies)
    1. [Rename Django defaults](#rename-cookies)
    2. [CSRF Settings](#csrf-settings)
    3. [Disuse 'expires' attribute](#cookie-expires)
3. [User Management](#user-management)
    1. [Forgot password limit](#forgot-password-limit)
4. [TLS Settings](#tls-settings)
    1. [Disable support for old TLS versions](#tls-versions)
    2. [Disable support for old TLS ciphers](#tls-ciphers)
5. [Admin](#admin)
    1. [Updating insecure version of jQuery](#insecure-jquery)

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

## User Management <a name="user-management"></a>
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

## TLS Settings <a name="tls-settings"></a>
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

## Admin <a name="admin"></a>
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

I am particularly keen on contributions for Apache or older versions of Django.
