docker restart pelican-dev-proxy
docker run --name pelican-dev-proxy -it -p 8443:8443 -v $0/../nginx.conf:/etc/nginx/nginx.conf:ro -d nginx
