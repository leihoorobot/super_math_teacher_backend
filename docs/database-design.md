# 数据库粗略设计

当前项目使用 SQLite 作为开发期数据库，后续可以迁移到 MySQL 或 PostgreSQL。核心角色暂定为 `ADMIN` 和 `TEACHER`。

| 表名 | 用途 |
| --- | --- |
| `users` | 登录账号、基础资料、角色和账号状态 |
| `teacher_profiles` | 教师扩展档案，如工号、科目、职称、部门、入职日期 |
| `classes` | 班级信息、年级、班主任和人数 |
| `courses` | 课程、任课教师、班级、星期、节次和教室 |
| `course_sections` | 课程小节，保存老师导出的 HTML 课件内容 |
| `notices` | 系统公告或校园通知 |
| `auth_tokens` | 登录令牌，用于简单会话管理 |
