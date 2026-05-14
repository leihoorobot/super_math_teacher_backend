# Super Math Teacher Backend

教师管理系统后端 API。当前使用 Python 标准库 HTTP 服务和 SQLite，提供登录注册、角色鉴权、教师、班级、课程、小节和通知接口。

## 启动

```bash
python3 app.py --host 127.0.0.1 --port 8000
```

初始化数据库：

```bash
python3 app.py --init-db
```

默认管理员：

```text
admin
Admin123456
```

默认教师：

```text
teacher
Teacher123456
```

数据库文件运行后生成在 `data/super_math_teacher.db`，不会提交到仓库。
