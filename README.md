# Security tips for your Django project

1. [HTTP Headers](#http-headers)
    1. [HTTP Strict Transport Security (HSTS)](#hsts)
    2. [Content Security Policy (CSP)](#csp)
    3. [X-Content-Type-Options](#x-content-type-options)
2. [Cookies](#cookies)
3. [User Management](#user-management)
4. [TLS Settings](#tls-settings)
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

```add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
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

```add_header X-Content-Type-Options "nosniff";
```


## Cookies <a name="cookies"></a>


## User Management <a name="user-management"></a>

## TLS Settings <a name="tls-settings"></a>

## Admin <a name="admin"></a>

# Contributing
I am keen to hear suggestions and improvements, please open an issue to discuss!
