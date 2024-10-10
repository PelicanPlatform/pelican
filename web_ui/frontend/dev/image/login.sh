#!/bin/bash

# Check if API_PASSWORD and API_URL are set in env
if [ -z "$API_PASSWORD" ] || [ -z "$API_URL" ]; then
  echo "API_PASSWORD or API_URL not set. Skipping login."
  exit 0
fi

# Prepend /api/v1.0/auth/login to the API_URL
LOGIN_URL="${API_URL%/}/api/v1.0/auth/login"

# Login and store the cookie
curl -s -c /etc/nginx/conf.d/login_cookie.txt -X POST -H "Content-Type: application/json" -d "{\"user\": \"admin\", \"password\": \"$API_PASSWORD\"}" "$LOGIN_URL"

# Extract the JWT from the cookie file
jwt=$(grep 'login' /etc/nginx/conf.d/login_cookie.txt | awk '{print $7}')

# Create a file with the Authorization header
echo "proxy_set_header Authorization \"Bearer $jwt\";" > /etc/nginx/conf.d/login_header.txt

# Reload Nginx to apply the new configuration if process exists
if [ -e /var/run/nginx.pid ]; then
  /usr/sbin/nginx -s reload
fi

echo "\n Successfully Updated the Authorization Header"
