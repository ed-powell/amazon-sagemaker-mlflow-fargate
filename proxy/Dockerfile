FROM nginx:latest

# Install apache2-utils and gawk to get htpasswd command to work in start_nginx.sh
RUN apt-get update -y && apt-get install -y apache2-utils && apt-get install gawk && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf

# Startup with script that retrieves MLflow_Login password from secrets manager
COPY -chmod=u+x start_nginx.sh ./
CMD [ "./start_nginx.sh" ]