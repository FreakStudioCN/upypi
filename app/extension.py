from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# 初始化拓展
def config_extensions(app):
    db.init_app(app)



