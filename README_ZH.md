[English Version](./README.md)
# uPyPi：类 PyPI 的 MicroPython 软件包仓库
`uPyPi` 是面向 `MicroPython` 生态的专属包管理中心，旨在简化 `MicroPython` 库和驱动的发现、共享与部署流程。

## 核心功能
* 包管理功能：类 `PyPI` 设计的仓库系统，支持上传、浏览、下载和管理你的 `MicroPython` 软件包。
* `JSON` 元数据解析：所有软件包均需通过 `package.json` 文件定义核心元数据（如名称、版本），确保一致性与兼容性。
* 双语支持：界面支持中英文一键切换，适配全球用户使用。
* 芯片与固件筛选：可筛选适配特定硬件（如 `RP2040`）和固件环境的软件包。
* 个人控制台：在统一界面追踪并管理所有已上传的软件包，清晰查看个人贡献记录。

## 相关说明
* 平台地址：https://upypi.net/
* 用户指南：https://f1829ryac0m.feishu.cn/wiki/L9AlwY1MEiVHQMk19Q7cYb3Hnwh

# 部署相关
## 翻译功能
### 初始化
    * pybabel extract -F babel.cfg -o messages.pot .
    * pybabel init -i messages.pot -d translations -l zh
    * pybabel init -i messages.pot -d translations -l en

### 更新
    * pybabel extract -F babel.cfg -o messages.pot .
    * pybabel update -i messages.pot -d translations
    * pybabel compile -d translations

## 运行项目
1. 构建容器：podman build -t upypi .
2. 运行容器：podman run -d -p 8080:443 upypi 自行准备证书文件与持久化目录

# 关于我们
![freakstudio](docs/freakstudio.jpg)