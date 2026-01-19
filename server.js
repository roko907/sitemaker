const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();

/* =========================
   기본 미들웨어
========================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: "my-secret-key",
    resave: false,
    saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DB 연결
========================= */
const db = new sqlite3.Database("./users.db", (err) => {
    if (err) {
        console.error("DB 연결 실패", err);
    } else {
        console.log("DB 연결 성공");
    }
});

/* 테이블 생성 */
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
`);

/* =========================
   회원가입
========================= */
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ message: "아이디와 비밀번호를 입력하세요" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        (err) => {
            if (err) {
                return res.json({ message: "이미 존재하는 아이디입니다" });
            }
            res.json({ message: "회원가입 성공" });
        }
    );
});

/* =========================
   로그인
========================= */
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (!user) {
                return res.json({ message: "아이디 또는 비밀번호 오류" });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.json({ message: "아이디 또는 비밀번호 오류" });
            }

            /* 세션 저장 */
            req.session.user = {
                id: user.id,
                username: user.username
            };

            res.json({ message: "로그인 성공" });
        }
    );
});

/* =========================
   로그인 상태 확인
========================= */
app.get("/me", (req, res) => {
    if (!req.session.user) {
        return res.json({ loggedIn: false });
    }

    res.json({
        loggedIn: true,
        user: req.session.user
    });
});

/* =========================
   로그아웃
========================= */
app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "로그아웃 완료" });
    });
});

/* =========================
   서버 실행 (배포 필수 형태)
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("server running on", PORT);
});
