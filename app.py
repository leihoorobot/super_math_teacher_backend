#!/usr/bin/env python3
"""Teacher management API built with the Python standard library."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "super_math_teacher.db"
SECRET = os.environ.get("SMT_SECRET", "dev-secret-change-me")
TOKEN_TTL = 60 * 60 * 24 * 7
PBKDF2_ROUNDS = 180_000


def now_ts() -> int:
    return int(time.time())


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    return int(value)


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt, digest = stored.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(rounds)
    ).hex()
    return hmac.compare_digest(candidate, digest)


def sign_token(raw: str) -> str:
    return hmac.new(SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def create_token(user_id: int) -> str:
    raw = f"{user_id}.{now_ts()}.{secrets.token_urlsafe(24)}"
    payload = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{payload}.{sign_token(payload)}"


def token_user_id(token: str) -> Optional[int]:
    try:
        payload, signature = token.rsplit(".", 1)
        if not hmac.compare_digest(sign_token(payload), signature):
            return None
        padded = payload + "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        return int(raw.split(".", 1)[0])
    except Exception:
        return None


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                role TEXT NOT NULL CHECK(role IN ('ADMIN','TEACHER')),
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','DISABLED')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS teacher_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                employee_no TEXT UNIQUE,
                subject TEXT,
                title TEXT,
                department TEXT,
                hire_date TEXT,
                bio TEXT
            );

            CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                grade TEXT NOT NULL,
                head_teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                student_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                subject TEXT NOT NULL,
                teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
                weekday INTEGER NOT NULL CHECK(weekday BETWEEN 1 AND 7),
                lesson_time TEXT NOT NULL,
                room TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS course_sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                summary TEXT,
                html_content TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 1,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

        exists = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not exists:
            ts = now_ts()
            conn.execute(
                """
                INSERT INTO users(username, password_hash, name, email, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'ADMIN', ?, ?)
                """,
                ("admin", hash_password("Admin123456"), "系统管理员", "admin@example.com", ts, ts),
            )
        teacher_exists = conn.execute("SELECT id FROM users WHERE username = ?", ("teacher",)).fetchone()
        if not teacher_exists:
            ts = now_ts()
            cur = conn.execute(
                """
                INSERT INTO users(username, password_hash, name, email, phone, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'TEACHER', ?, ?)
                """,
                ("teacher", hash_password("Teacher123456"), "示范教师", "teacher@example.com", "13800000000", ts, ts),
            )
            conn.execute(
                """
                INSERT INTO teacher_profiles(user_id, employee_no, subject, title, department, hire_date, bio)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (cur.lastrowid, "T0001", "数学", "教师", "数学教研组", "2026-05-14", "教师角色演示账号"),
            )
        if conn.execute("SELECT COUNT(*) AS c FROM classes").fetchone()["c"] == 0:
            ts = now_ts()
            conn.executemany(
                """
                INSERT INTO classes(name, grade, student_count, status, created_at)
                VALUES (?, ?, ?, 'ACTIVE', ?)
                """,
                [
                    ("初一 1 班", "初一", 42, ts),
                    ("初二 2 班", "初二", 39, ts),
                    ("初三冲刺班", "初三", 28, ts),
                ],
            )
        if conn.execute("SELECT COUNT(*) AS c FROM notices").fetchone()["c"] == 0:
            admin_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
            conn.execute(
                """
                INSERT INTO notices(title, content, author_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                ("系统初始化完成", "教师管理系统基础模块已就绪，可继续扩展排课、考勤、成绩等功能。", admin_id, now_ts()),
            )
        if conn.execute("SELECT COUNT(*) AS c FROM courses").fetchone()["c"] == 0:
            teacher = conn.execute("SELECT id FROM users WHERE username = 'teacher'").fetchone()
            klass = conn.execute("SELECT id FROM classes ORDER BY id LIMIT 1").fetchone()
            if teacher and klass:
                conn.execute(
                    """
                    INSERT INTO courses(name, subject, teacher_id, class_id, weekday, lesson_time, room, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("七年级数学互动课", "数学", teacher["id"], klass["id"], 1, "09:00-09:45", "A101", now_ts()),
                )


def public_user(user: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "role": user["role"],
        "status": user["status"],
        "createdAt": user["created_at"],
    }


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "SuperMathTeacherAPI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def do_PUT(self) -> None:
        self.dispatch("PUT")

    def do_DELETE(self) -> None:
        self.dispatch("DELETE")

    def dispatch(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
            body = self.read_json() if method in {"POST", "PUT"} else {}
            status, payload = self.route(method, path, query, body)
            self.write_json(status, payload)
        except ApiError as exc:
            self.write_json(exc.status, {"error": exc.message})
        except Exception as exc:
            self.write_json(500, {"error": f"服务器错误: {exc}"})

    def read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(400, "请求体必须是 JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "请求体必须是 JSON 对象")
        return data

    def write_json(self, status: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def current_user(self) -> sqlite3.Row:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise ApiError(401, "请先登录")
        token = header.replace("Bearer ", "", 1).strip()
        user_id = token_user_id(token)
        if not user_id:
            raise ApiError(401, "登录已失效")
        with connect() as conn:
            token_row = conn.execute(
                "SELECT * FROM auth_tokens WHERE token = ? AND expires_at > ?",
                (token, now_ts()),
            ).fetchone()
            if not token_row:
                raise ApiError(401, "登录已失效")
            user = conn.execute("SELECT * FROM users WHERE id = ? AND status = 'ACTIVE'", (user_id,)).fetchone()
            if not user:
                raise ApiError(401, "账号不可用")
            return user

    def require_admin(self) -> sqlite3.Row:
        user = self.current_user()
        if user["role"] != "ADMIN":
            raise ApiError(403, "需要管理员权限")
        return user

    def route(
        self, method: str, path: str, query: Dict[str, str], body: Dict[str, Any]
    ) -> Tuple[int, Dict[str, Any]]:
        if method == "GET" and path == "/api/health":
            return 200, {"status": "ok", "time": now_ts()}
        if method == "POST" and path == "/api/auth/register":
            return self.register(body)
        if method == "POST" and path == "/api/auth/login":
            return self.login(body)
        if method == "GET" and path == "/api/auth/me":
            return 200, {"user": public_user(self.current_user())}
        if method == "POST" and path == "/api/auth/logout":
            return self.logout()
        if method == "GET" and path == "/api/dashboard":
            return self.dashboard()
        if path == "/api/teachers" and method == "GET":
            return self.list_teachers(query)
        if path == "/api/teachers" and method == "POST":
            return self.create_teacher(body)
        if path.startswith("/api/teachers/") and method == "PUT":
            return self.update_teacher(int(path.rsplit("/", 1)[1]), body)
        if path == "/api/classes" and method == "GET":
            return self.list_classes()
        if path == "/api/classes" and method == "POST":
            return self.create_class(body)
        if path == "/api/courses" and method == "GET":
            return self.list_courses()
        if path == "/api/courses" and method == "POST":
            return self.create_course(body)
        if path == "/api/course-sections" and method == "GET":
            return self.list_course_sections(query)
        if path == "/api/course-sections" and method == "POST":
            return self.create_course_section(body)
        if path.startswith("/api/course-sections/") and method == "GET":
            return self.get_course_section(int(path.rsplit("/", 1)[1]))
        if path == "/api/notices" and method == "GET":
            return self.list_notices()
        raise ApiError(404, "接口不存在")

    def register(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        name = str(body.get("name", "")).strip()
        email = str(body.get("email", "")).strip() or None
        phone = str(body.get("phone", "")).strip() or None
        if len(username) < 3 or len(password) < 8 or not name:
            raise ApiError(400, "用户名至少 3 位，密码至少 8 位，姓名必填")
        ts = now_ts()
        try:
            with connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO users(username, password_hash, name, email, phone, role, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'TEACHER', ?, ?)
                    """,
                    (username, hash_password(password), name, email, phone, ts, ts),
                )
                conn.execute(
                    "INSERT INTO teacher_profiles(user_id, subject, title, department) VALUES (?, ?, ?, ?)",
                    (cur.lastrowid, body.get("subject", "数学"), "教师", "数学教研组"),
                )
                user = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            raise ApiError(409, "用户名已存在")
        return 201, {"user": public_user(user)}

    def login(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        with connect() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                raise ApiError(401, "用户名或密码错误")
            if user["status"] != "ACTIVE":
                raise ApiError(403, "账号已停用")
            token = create_token(user["id"])
            conn.execute(
                "INSERT INTO auth_tokens(token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token, user["id"], now_ts() + TOKEN_TTL, now_ts()),
            )
        return 200, {"token": token, "user": public_user(user)}

    def logout(self) -> Tuple[int, Dict[str, Any]]:
        header = self.headers.get("Authorization", "")
        token = header.replace("Bearer ", "", 1).strip() if header.startswith("Bearer ") else ""
        if token:
            with connect() as conn:
                conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
        return 200, {"ok": True}

    def dashboard(self) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        with connect() as conn:
            stats = {
                "teachers": conn.execute("SELECT COUNT(*) c FROM users WHERE role = 'TEACHER'").fetchone()["c"],
                "classes": conn.execute("SELECT COUNT(*) c FROM classes").fetchone()["c"],
                "courses": conn.execute("SELECT COUNT(*) c FROM courses").fetchone()["c"],
                "students": conn.execute("SELECT COALESCE(SUM(student_count), 0) c FROM classes").fetchone()["c"],
            }
            notices = [row_to_dict(r) for r in conn.execute("SELECT * FROM notices ORDER BY created_at DESC LIMIT 5")]
        return 200, {"stats": stats, "notices": notices}

    def list_teachers(self, query: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        keyword = f"%{query.get('keyword', '').strip()}%"
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT u.id, u.username, u.name, u.email, u.phone, u.role, u.status, u.created_at,
                       p.employee_no, p.subject, p.title, p.department, p.hire_date, p.bio
                FROM users u
                LEFT JOIN teacher_profiles p ON p.user_id = u.id
                WHERE u.role = 'TEACHER' AND (? = '%%' OR u.name LIKE ? OR u.username LIKE ?)
                ORDER BY u.created_at DESC
                """,
                (keyword, keyword, keyword),
            ).fetchall()
        return 200, {"items": [row_to_dict(r) for r in rows]}

    def create_teacher(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self.require_admin()
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "Teacher123456"))
        name = str(body.get("name", "")).strip()
        if len(username) < 3 or len(password) < 8 or not name:
            raise ApiError(400, "用户名至少 3 位，密码至少 8 位，姓名必填")
        ts = now_ts()
        try:
            with connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO users(username, password_hash, name, email, phone, role, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'TEACHER', ?, ?, ?)
                    """,
                    (
                        username,
                        hash_password(password),
                        name,
                        body.get("email"),
                        body.get("phone"),
                        body.get("status", "ACTIVE"),
                        ts,
                        ts,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO teacher_profiles(user_id, employee_no, subject, title, department, hire_date, bio)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cur.lastrowid,
                        body.get("employeeNo"),
                        body.get("subject"),
                        body.get("title"),
                        body.get("department"),
                        body.get("hireDate"),
                        body.get("bio"),
                    ),
                )
        except sqlite3.IntegrityError:
            raise ApiError(409, "用户名或工号已存在")
        return 201, {"ok": True}

    def update_teacher(self, teacher_id: int, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self.require_admin()
        with connect() as conn:
            if not conn.execute("SELECT id FROM users WHERE id = ? AND role = 'TEACHER'", (teacher_id,)).fetchone():
                raise ApiError(404, "教师不存在")
            conn.execute(
                """
                UPDATE users SET name = ?, email = ?, phone = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    body.get("name"),
                    body.get("email"),
                    body.get("phone"),
                    body.get("status", "ACTIVE"),
                    now_ts(),
                    teacher_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO teacher_profiles(user_id, employee_no, subject, title, department, hire_date, bio)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    employee_no = excluded.employee_no,
                    subject = excluded.subject,
                    title = excluded.title,
                    department = excluded.department,
                    hire_date = excluded.hire_date,
                    bio = excluded.bio
                """,
                (
                    teacher_id,
                    body.get("employeeNo"),
                    body.get("subject"),
                    body.get("title"),
                    body.get("department"),
                    body.get("hireDate"),
                    body.get("bio"),
                ),
            )
        return 200, {"ok": True}

    def list_classes(self) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*, u.name AS head_teacher_name
                FROM classes c
                LEFT JOIN users u ON u.id = c.head_teacher_id
                ORDER BY c.created_at DESC
                """
            ).fetchall()
        return 200, {"items": [row_to_dict(r) for r in rows]}

    def create_class(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self.require_admin()
        name = str(body.get("name", "")).strip()
        grade = str(body.get("grade", "")).strip()
        if not name or not grade:
            raise ApiError(400, "班级名称和年级必填")
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO classes(name, grade, head_teacher_id, student_count, status, created_at)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?)
                """,
                (name, grade, optional_int(body.get("headTeacherId")), int(body.get("studentCount", 0)), now_ts()),
            )
        return 201, {"ok": True}

    def list_courses(self) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        with connect() as conn:
            rows = conn.execute(
                """
                SELECT co.*, u.name AS teacher_name, c.name AS class_name
                     , (SELECT COUNT(*) FROM course_sections cs WHERE cs.course_id = co.id) AS section_count
                FROM courses co
                LEFT JOIN users u ON u.id = co.teacher_id
                LEFT JOIN classes c ON c.id = co.class_id
                ORDER BY co.weekday, co.lesson_time
                """
            ).fetchall()
        return 200, {"items": [row_to_dict(r) for r in rows]}

    def create_course(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        self.require_admin()
        if not body.get("name") or not body.get("subject"):
            raise ApiError(400, "课程名称和科目必填")
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO courses(name, subject, teacher_id, class_id, weekday, lesson_time, room, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    body.get("name"),
                    body.get("subject"),
                    optional_int(body.get("teacherId")),
                    optional_int(body.get("classId")),
                    int(body.get("weekday", 1)),
                    body.get("lessonTime", "08:00-08:45"),
                    body.get("room"),
                    now_ts(),
                ),
            )
        return 201, {"ok": True}

    def list_course_sections(self, query: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        course_id = query.get("courseId")
        params = []
        where = ""
        if course_id:
            where = "WHERE cs.course_id = ?"
            params.append(int(course_id))
        with connect() as conn:
            rows = conn.execute(
                f"""
                SELECT cs.id, cs.course_id, cs.title, cs.summary, cs.sort_order, cs.created_by,
                       cs.created_at, cs.updated_at, co.name AS course_name, u.name AS creator_name
                FROM course_sections cs
                LEFT JOIN courses co ON co.id = cs.course_id
                LEFT JOIN users u ON u.id = cs.created_by
                {where}
                ORDER BY cs.course_id, cs.sort_order, cs.created_at
                """,
                params,
            ).fetchall()
        return 200, {"items": [row_to_dict(r) for r in rows]}

    def get_course_section(self, section_id: int) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        with connect() as conn:
            row = conn.execute(
                """
                SELECT cs.*, co.name AS course_name, u.name AS creator_name
                FROM course_sections cs
                LEFT JOIN courses co ON co.id = cs.course_id
                LEFT JOIN users u ON u.id = cs.created_by
                WHERE cs.id = ?
                """,
                (section_id,),
            ).fetchone()
        if not row:
            raise ApiError(404, "小节不存在")
        return 200, {"item": row_to_dict(row)}

    def create_course_section(self, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        user = self.current_user()
        course_id = optional_int(body.get("courseId"))
        title = str(body.get("title", "")).strip()
        html = str(body.get("htmlContent", "")).strip()
        if not course_id or not title or not html:
            raise ApiError(400, "课程、小节名称和 HTML 内容必填")
        if len(html.encode("utf-8")) > 5 * 1024 * 1024:
            raise ApiError(400, "HTML 内容不能超过 5MB")
        with connect() as conn:
            course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
            if not course:
                raise ApiError(404, "课程不存在")
            if user["role"] == "TEACHER" and course["teacher_id"] not in (None, user["id"]):
                raise ApiError(403, "只能维护自己任教课程的小节")
            ts = now_ts()
            cur = conn.execute(
                """
                INSERT INTO course_sections(course_id, title, summary, html_content, sort_order, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    course_id,
                    title,
                    body.get("summary"),
                    html,
                    int(body.get("sortOrder", 1)),
                    user["id"],
                    ts,
                    ts,
                ),
            )
        return 201, {"ok": True, "id": cur.lastrowid}

    def list_notices(self) -> Tuple[int, Dict[str, Any]]:
        self.current_user()
        with connect() as conn:
            rows = conn.execute("SELECT * FROM notices ORDER BY created_at DESC").fetchall()
        return 200, {"items": [row_to_dict(r) for r in rows]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Super Math Teacher backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--init-db", action="store_true")
    args = parser.parse_args()

    init_db()
    if args.init_db:
        print(f"Database initialized at {DB_PATH}")
        return

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"API server running at http://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
