FROM codeberg.org/eoelab/cenv:debian

COPY start.sh /usr/local/bin/

RUN apt-get update && apt-get install -y openssl nginx python3-flask python3-requests python3-markdown python3-gunicorn && apt-get clean && rm -rf /var/lib/apt/lists/* && \
    chmod +x /usr/local/bin/start.sh

COPY nginx.conf /etc/nginx/sites-enabled/default
COPY ./ /workspace

# Set up workspace
WORKDIR /workspace

CMD ["start.sh"]