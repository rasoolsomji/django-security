# Security tips for your Django project

1. [HTTP Headers](#http-headers)
    1. [HSTS](#hsts)
2. [Cookies](#cookies)
3. [User Management](#user-management)
4. [TLS Settings](#tls-settings)
5. [Admin](#admin)

## HTTP Headers <a name="http-headers"></a>
  
## Cookies <a name="cookies"></a>
### HSTS <a name="hsts"></a>
Even if you are redirecting all non-HTTPS traffic to HTTPs in your web server configuration you are still vulnerable to an SSL-stripping attack.

Django >= 1.8 allows you set the setting ```SECURE_HSTS_SECONDS``` and recommended values can be found on the [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html).

Alternatively you can add the following line to your server block in your nginx configuration:

```add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;```

#### Things to note
- If you ```includeSubDomains```, it may break other site functionality.  For example, if you use SendGrid for sending emails with click tracking links, it does not work with HTTPs without [further configuration](https://sendgrid.com/docs/ui/analytics-and-reporting/click-tracking-ssl/)
- If you use the nginx ```add_header``` method, make sure it covers all relevant location blocks, such as your static files or user-uploaded files. You may need to add that add_header directive within your ```location /static/``` or ```location /uploads/``` blocks


## User Management <a name="user-management"></a>

## TLS Settings <a name="tls-settings"></a>

## Admin <a name="admin"></a>

# Contributing
I am keen to hear suggestions and improvements, please open an issue to discuss!
