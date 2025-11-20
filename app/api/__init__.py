from app.api.controller.demoController import app
from app.config import url_path_prefix

DEFAULT_BLUEPRINT = [
    (app, '/app'),  # 应用管理
]

def config_blueprint(app):
    for blueprint, url_prefix in DEFAULT_BLUEPRINT:
        url_prefix = url_path_prefix + url_prefix  # 添加 /api 前缀
        app.register_blueprint(blueprint, url_prefix=url_prefix)