FROM crpi-0fzeutaz68uv7lwt.cn-hangzhou.personal.cr.aliyuncs.com/eoelab/cenv:debian

RUN apt-get update && apt-get install -y git python3-flask python3-flask-babel python3-polib python3-requests python3-markdown python3-gunicorn && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./ /workspace

# Set up workspace
WORKDIR /workspace