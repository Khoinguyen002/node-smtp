// server.js
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const ipaddr = require("ipaddr.js");
const { Redis } = require("@upstash/redis");

const app = express();
const redis = Redis.fromEnv();
app.use(express.json());

// If your app is behind a proxy (Cloudflare, nginx, load balancer), enable this:
if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", true);
}

// returns true if clientIp is allowed by any entry in whitelist
function ipAllowed(clientIp, whitelist) {
  if (!whitelist || whitelist.length === 0) return true; // no whitelist configured -> allow

  // Normalize IPv4-mapped IPv6 addresses if present
  let addr;
  try {
    addr = ipaddr.parse(clientIp);
  } catch (err) {
    return false; // invalid IP
  }

  for (const entry of whitelist) {
    if (entry.includes("/")) {
      try {
        const [range, prefixLengthStr] = entry.split("/");
        const prefixLength = parseInt(prefixLengthStr, 10);
        const rangeAddr = ipaddr.parse(range);
        
        if (addr.kind() !== rangeAddr.kind()) {
          if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress && rangeAddr.kind() === "ipv4") {
            addr = addr.toIPv4Address();
          } else {
            continue;
          }
        }
        if (addr.match(rangeAddr, prefixLength)) return true;
      } catch (err) {
        continue;
      }
    } else {
      try {
        const allowed = ipaddr.parse(entry);
        let a = addr;
        if (a.kind() === "ipv6" && a.isIPv4MappedAddress && allowed.kind() === "ipv4") {
          a = a.toIPv4Address();
        }
        if (a.toNormalizedString() === allowed.toNormalizedString()) return true;
      } catch (err) {
        continue;
      }
    }
  }
  return false;
}

// -----------------------------
// Middleware: IP whitelist
// -----------------------------
async function ipWhitelistMiddleware(req, res, next) {
  const clientIp = req.ip || req.connection.remoteAddress;

  const cfIpWhitelist = (
    await Promise.all([
      await (await fetch("https://www.cloudflare.com/ips-v6")).text(),
      await (await fetch("https://www.cloudflare.com/ips-v4")).text(),
    ])
  )
    .join("\n") // ✅ ĐÃ FIX LỖI JOIN NỐI CHUỖI
    .trim()
    .split("\n")
    .map((line) => line.trim());

  const redisWhitelist = await redis.smembers(process.env.UPSTASH_REDIS_IP_WHITELIST_KEY);
  const whitelist = [...cfIpWhitelist, ...redisWhitelist];

  if (!whitelist || whitelist.length === 0) {
    return next(); // no whitelist configured
  }

  if (!ipAllowed(clientIp, whitelist)) {
    const msg = "Forbidden: IP not allowed";
    console.log(msg);
    return res.status(403).json({ error: msg });
  }

  next();
}

// -----------------------------
// Middleware: Email whitelist
// -----------------------------
async function emailWhitelistMiddleware(req, res, next) {
  const { to } = req.body;
  const allowedEmailList = await redis.smembers(process.env.UPSTASH_REDIS_EMAIL_WHITELIST_KEY);

  const isAllowed = (() => {
    if (Array.isArray(to)) {
      const allowedMails = to.filter((email) => allowedEmailList.includes(email));
      if (allowedMails.length > 0) {
        req.body.to = allowedMails;
        return true;
      }
      return false;
    }
    return allowedEmailList.includes(to);
  })();

  if (!isAllowed) return res.status(403).json({ error: "Email(s) are not allowed" });
  next();
}

// -----------------------------
// Middleware: API token auth
// -----------------------------
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing Authorization header" });

  const [type, token] = authHeader.split(" ");
  if (type !== "Bearer" || token !== process.env.API_TOKEN) {
    return res.status(403).json({ error: "Invalid API token" });
  }
  next();
}

// -----------------------------
// Configure SMTP transporter
// -----------------------------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USERNAME,
    pass: process.env.SMTP_PASSWORD,
  },
});

app.get("/", (req, res) => {
  res.json({ status: "SMTP API server running" });
});

app.post("/send", /* ipWhitelistMiddleware, emailWhitelistMiddleware, */ authMiddleware, async (req, res) => {
  try {
    const { to, subject, text, html } = req.body;
    if (!to || !subject) return res.status(400).json({ error: "Missing 'to' or 'subject'" });

    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      text,
      html,
    });

    return res.json({ messageId: info.messageId });
  } catch (err) {
    console.error("send error", err);
    return res.status(500).json({ error: err.message });
  }
});

// -----------------------------
// Khởi tạo Redis Keys
// -----------------------------
async function initRedisKeys() {
  const ipKey = process.env.UPSTASH_REDIS_IP_WHITELIST_KEY;
  const emailKey = process.env.UPSTASH_REDIS_EMAIL_WHITELIST_KEY;

  try {
    const ipExists = await redis.exists(ipKey);
    if (!ipExists) {
      console.log(`[Init] Key IP '${ipKey}' chưa có. Tạo mới với IP mồi (127.0.0.1)...`);
      await redis.sadd(ipKey, "127.0.0.1"); // Mồi IP ảo để tạo Set
    }

    const emailExists = await redis.exists(emailKey);
    if (!emailExists) {
      console.log(`[Init] Key Email '${emailKey}' chưa có. Tạo mới với Email mồi...`);
      await redis.sadd(emailKey, "test@example.com"); // Mồi Email ảo để tạo Set
    }
  } catch (err) {
    console.error("[Init] Lỗi kết nối Redis lúc khởi tạo:", err);
  }
}

// -----------------------------
// Chạy Server
// -----------------------------
const PORT = Number(process.env.PORT || 3000);

// Phải đợi hàm init chạy xong rồi mới mở Port
initRedisKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`SMTP middleware API running on port ${PORT}`);
  });
});
