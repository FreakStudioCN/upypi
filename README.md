# Upypi

## 项目概述

## 运行项目
1. 安装依赖：apt install nginx python3-flask python3-requests python3-markdown python3-gunicorn
2. python3 -m gunicorn -w 2 -k gthread --threads 4 -b 127.0.0.1:5000 app:app

## 注意
1. 生产力环境要提前准备证书并准备好nginx服务器，样例配置参考nginx-sample.conf

## 项目演示

https://upypi.net