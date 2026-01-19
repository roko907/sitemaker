const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();

/* =====================
   기본 설정
===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, "public")));

/* =====================
   DB 설정
===================== */
const db = new sqlite3.Database("./users.db");

/* 테이블 생성 */
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    birthdate TEXT,
    role TEXT DEFAULT 'user'
)
`);

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

function isBirthdayToday(birthdate) {
    const today = new Date();
    const birth = new Date(birthdate);

    return (
        today.getMonth() === birth.getMonth() &&
        today.getDate() === birth.getDate()
    );
}

/* 관리자 권한 체크 */
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ message: "관리자 권한 필요" });
    }
    next();
}

/* =====================
   회원가입
===================== */
app.post("/signup", async (req, res) => {
    const { username, password, birthdate } = req.body;
    const MIN_AGE = 14;

    if (!username || !password || !birthdate) {
        return res.json({ message: "모든 항목을 입력하세요" });
    }

    if (getAge(birthdate) < MIN_AGE) {
        return res.json({ message: `${MIN_AGE}세 이상만 가입 가능` });
    }

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password, birthdate) VALUES (?, ?, ?)",
        [username, hash, birthdate],
        err => {
            if (err) {
                if (err.message.includes("UNIQUE")) {
                    return res.json({ message: "이미 존재하는 아이디" });
                }
                console.error("signup error:", err);
                return res.json({ message: "서버 오류" });
            }
            res.json({ message: "회원가입 성공" });
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
            if (!user) {
                return res.json({ message: "로그인 실패" });
            }

            const ok = await bcrypt.compare(password, user.password);
            if (!ok) {
                return res.json({ message: "로그인 실패" });
            }

            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };

            res.json({ message: "로그인 성공" });
        }
    );
});

/* =====================
   로그인 상태 확인
===================== */
app.get("/me", (req, res) => {
    if (!req.session.user) {
        return res.json({ loggedIn: false });
    }

    db.get(
        "SELECT birthdate FROM users WHERE id = ?",
        [req.session.user.id],
        (err, row) => {
            res.json({
                loggedIn: true,
                user: req.session.user,
                birthdayToday: row ? isBirthdayToday(row.birthdate) : false
            });
        }
    );
});

/* =====================
   로그아웃
===================== */
app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "로그아웃 완료" });
    });
});

/* =====================
   관리자 API
===================== */

/* 전체 사용자 생일 조회 */
app.get("/admin/birthdays/all", requireAdmin, (req, res) => {
    db.all(
        "SELECT username, birthdate FROM users ORDER BY birthdate",
        (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: "DB 오류" });
            }
            res.json(rows);
        }
    );
});

/* 오늘 생일인 사용자 */
app.get("/admin/birthdays/today", requireAdmin, (req, res) => {
    db.all("SELECT username, birthdate FROM users", (err, rows) => {
        if (err) return res.status(500).json({ message: "DB 오류" });

        const today = rows.filter(u => isBirthdayToday(u.birthdate));
        res.json(today);
    });
});

/* =====================
   서버 실행
===================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port", PORT);
});
