FROM nginx:latest

ARG MLF_USERNAME
ARG MLF_PASSWORD

# Install apache2-utils to get htpasswd command to setup a login password
RUN apt-get update -y && apt-get install -y apache2-utils && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf

RUN htpasswd -c -b /etc/nginx/.htpasswd $MLF_USERNAME $MLF_PASSWORD

