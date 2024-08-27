FROM nginx:1.27

ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx

# Set some default environment variables so we can check them later
ENV API_URL=https://host.docker.internal:8444

# Install cron
RUN apt-get update && apt-get install -y cron

# Update the entrypoint
COPY ./entrypoint.sh /opt/bin/entrypoint.sh
RUN chmod +x /opt/bin/entrypoint.sh
ENTRYPOINT ["/opt/bin/entrypoint.sh"]

# Copy the NGINX configuration file
COPY ./nginx.conf /etc/nginx/templates/nginx.conf.template

# Copy the login script
COPY ./login.sh /opt/bin/login.sh
RUN chmod +x /opt/bin/login.sh

# Copy the crontab file and set up cron job
COPY ./crontab /etc/cron.d/login_cron
RUN chmod 0644 /etc/cron.d/login_cron
RUN crontab /etc/cron.d/login_cron

CMD ["nginx", "-g", "daemon off;"]
