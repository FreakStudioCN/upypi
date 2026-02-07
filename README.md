# Upypi

## 项目概述

## 运行项目

1. 本地运行：
    1. 安装依赖：pip install Flask requests markdown
    2. python app.py
2. 容器运行（推荐）： 
    1. 自行准备tls证书（或者手动修改app.py）
    2. docker run -p 8080:443 -v tls:/tls -v pkgs:/upypi/pkgs -v db:/upypi/db codeberg.org/eoelab/cenv:upypi
    3. 注意持久化目录为`/upypi/db`，`/upypi/pkgs`


## 项目演示

https://upypi.net