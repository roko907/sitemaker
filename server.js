const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

/* =====================
   기본 설정
===================== */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    session({
        secret: "secret-key",
        resave: false,
        saveUninitialized: false
    })
);

app.use(express.static(path.join(__dirname, "public")));

/* =====================
   DB 설정
===================== */
const db = new sqlite3.Database("./users.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            birthdate TEXT,
            role TEXT DEFAULT 'user'
        )
    `);
});

/* =====================
   유틸 함수
===================== */
function getAge(birthdate) {
    const today = new Date();
    const birth = new Date(birthdate);

    let age = today.getFullYear() - birth.getFullYear();
    const m = today.getMonth() - birth.getMonth();

    if (m < 0 || (m === 0 && today.getDate() < birth.getDate())) {
        age--;
    }
    return age;
}

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).send("로그인이 필요합니다");
    }
    next();
}

function requireAdmin(req, res, next) {
    console.log("ADMIN CHECK:", req.session.user);

    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).send("관리자 권한이 필요합니다");
    }
    next();
}


/* =====================
   회원가입
===================== */
app.post("/register", async (req, res) => {
    const { username, password, birthdate } = req.body;

    if (!username || !password || !birthdate) {
        return res.send("모든 항목을 입력하세요");
    }

    if (getAge(birthdate) < 14) {
        return res.send("14세 이상만 가입 가능합니다");
    }

    const hashed = await bcrypt.hash(password, 10);

    // ⭐ admin 자동 처리
    const role = username === "admin" ? "admin" : "user";

    db.run(
        `INSERT INTO users (username, password, birthdate, role)
         VALUES (?, ?, ?, ?)`,
        [username, hashed, birthdate, role],
        err => {
            if (err) {
                return res.send("이미 존재하는 아이디입니다");
            }
            res.send("회원가입 성공");
        }
    );
});

/* =====================
   로그인
===================== */
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err || !user) {
                return res.send("아이디 또는 비밀번호 오류");
            }

            const ok = await bcrypt.compare(password, user.password);
            if (!ok) {
                return res.send("아이디 또는 비밀번호 오류");
            }

            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };
            console.log("LOGIN USER:", req.session.user);

            res.send("로그인 성공");
        }
    );
});

/* =====================
   로그아웃
===================== */
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.send("로그아웃 완료");
    });
});

/* =====================
   오늘 생일인 유저
===================== */
app.get("/birthdays/today", requireLogin, (req, res) => {
    const today = new Date();
    const mmdd = String(today.getMonth() + 1).padStart(2, "0") +
                 "-" +
                 String(today.getDate()).padStart(2, "0");

    db.all(
        `
        SELECT username, birthdate
        FROM users
        WHERE substr(birthdate, 6, 5) = ?
        `,
        [mmdd],
        (err, rows) => {
            if (err) return res.send("에러 발생");
            res.json(rows);
        }
    );
});

/* =====================
   🔐 관리자: 전체 생일 조회
===================== */
app.get("/admin/birthdays/all", requireAdmin, (req, res) => {
    db.all(
        `
        SELECT username, birthdate, role
        FROM users
        ORDER BY birthdate
        `,
        (err, rows) => {
            if (err) return res.send("에러 발생");
            res.json(rows);
        }
    );
});

/* =====================
   서버 시작
===================== */
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
