# Security tips for your Django project

1. [HTTP Headers](#http-headers)
    1. [HTTP Strict Transport Security (HSTS)](#hsts)
    2. [Content Security Policy (CSP)](#csp)
    3. [X-Content-Type-Options](#x-content-type-options)
2. [Cookies](#cookies)
    1. [Renaming Django defaults](#rename-cookies)
    2. [Store CSRF cookie within the session cookie](#csrf-use-sessions)
3. [User Management](#user-management)
4. [TLS Settings](#tls-settings)
    1. [Disable support for old TLS versions](#tls-versions)
    2. [Disable support for old TLS ciphers](#tls-ciphers)
5. [Admin](#admin)

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
- If you ```includeSubDomains``` / [```SECURE_HSTS_INCLUDE_SUBDOMAINS```](https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-SECURE_HSTS_INCLUDE_SUBDOMAINS), it may break other site functionality.  For example, if you use SendGrid for sending emails with click tracking links, it does not work with HTTPs without [further configuration](https://sendgrid.com/docs/ui/analytics-and-reporting/click-tracking-ssl/)
- If you use the nginx ```add_header``` method, make sure it covers all relevant location blocks, such as your static files or user-uploaded files. You may need to add that add_header directive within your ```location /static/``` or ```location /uploads/``` blocks

### Content Security Policy (CSP) <a name="csp"></a>
#### Vulnerabilities:
_XSS_
#### One-liner:
You whitelist valid sources of executable scripts.
#### Further-detail:
[Mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
#### Implementation:
Django does not support this out of the box, so you need to either use a 3rd-party library, or you can use a ```<meta http-equiv="Content-Security-Policy">``` tag within your HTML.

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
Django >= 1.8 allows you set the setting ```SECURE_CONTENT_TYPE_NOSNIFF``` which you ought to set to ```True```

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
Since at least Django 1.4, you can edit the setting ```SESSION_COOKIE_NAME``` from it's default of ```'sessionid'```. 

Since Django 1.2, you can edit the setting ```CSRF_COOKIE_NAME``` from it's default of ```'csrftoken'```

#### Things to note:
- Renaming the CSRF cookie is redundant if you [put the CSRF cookie in the session cookie](#csrf-use-sessions)

### Store CSRF cookie within the session cookie <a name="csrf-use-sessions"></a>
#### Vulnabilities:
_CSRF attack, Information exposure_
#### One liner:
If an attacker could acquire the CSRF cookie value, due to their long expiry (1 year by default), they could use it to submit a form as a user.
#### Further detail:
[OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
#### Implementation:
Since Django 1.11, you can change the setting ```CSRF_USE_SESSIONS``` to ```True```


## User Management <a name="user-management"></a>

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
And you need to remove the ```TLSv1``` and ```TLSv1.1``` statements.
If you used Let's Encrypt for your SSL certificate, you may find this configuration in ```/etc/letsencrypt/options-ssl-nginx.conf```

#### Things to note: <a name="certbot-things-to-note">
- If you do use Let's Encrypt and Certbot, the file ```options-ssl-nginx.conf```, won't update as you update the certbot package.  The update will instead print out what changes were meant to be made, which you can copy over. [Source](https://community.letsencrypt.org/t/remove-support-for-tls-1-0-1-1-in-nginx/88924/11)

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
And you need to remove all insecure ciphers. SSL Labs provide a [free analysis](https://www.ssllabs.com/ssltest/index.html) of your site to show which ciphers you currently support and how secure they are.  If you used Let's Encrypt for your SSL certificate, you may find this configuration in ```/etc/letsencrypt/options-ssl-nginx.conf```

#### Things to note:
- If you do use Let's Encrypt and Certbot, same as [above](#certbot-things-to-note)

## Admin <a name="admin"></a>

# Contributing
I am keen to hear suggestions and improvements, please open an issue to discuss!

I am particularly keen on contributions for Apache or older versions of Django.
