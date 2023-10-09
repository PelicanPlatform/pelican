A short README explaining our authorization permissions, specifically regarding tokens recieved from the URL or Header vs the login cookie.


Tokens that are part of the HTTP Request Header e.g. `{"Authorization": "Bearer +"<token>}` and that are set in the URL Query via `Authz` are considered valid if they are signed by either the Federation jwk or the Origin jwk.

However, tokens that are retrieved from the login cookie `ctx.Cookie("login")` are ONLY valid if the are signed by the Origin jwk. This can be seen in the prometheus code and how it accesses the functions in `Authorization.go`
