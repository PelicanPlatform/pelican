docker restart pelican-dev-proxy
docker run --name pelican-dev-proxy -it -p 8443:8443 -v /Users/clock/GolandProjects/pelican/origin_ui/src/dev/nginx.conf:/etc/nginx/nginx.conf:ro -d nginx
