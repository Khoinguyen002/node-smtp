// server.js
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const ipaddr = require("ipaddr.js");

const app = express();
app.use(express.json());

// If your app is behind a proxy (Cloudflare, nginx, load balancer), enable this:
if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", true);
}

// --- Helper: parse IP whitelist from env ---
function parseWhitelist(envValue) {
  if (!envValue || !envValue.trim()) return null;
  return envValue
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
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
    // If entry is CIDR
    if (entry.includes("/")) {
      try {
        const [range, prefixLengthStr] = entry.split("/");
        const prefixLength = parseInt(prefixLengthStr, 10);

        const rangeAddr = ipaddr.parse(range);
        if (addr.kind() !== rangeAddr.kind()) {
          // try convert IPv4-mapped IPv6 to IPv4
          if (
            addr.kind() === "ipv6" &&
            addr.isIPv4MappedAddress &&
            rangeAddr.kind() === "ipv4"
          ) {
            addr = addr.toIPv4Address();
          } else {
            continue;
          }
        }

        if (addr.match(rangeAddr, prefixLength)) return true;
      } catch (err) {
        // skip invalid entry
        continue;
      }
    } else {
      // single IP
      try {
        const allowed = ipaddr.parse(entry);
        let a = addr;
        // handle IPv4-mapped IPv6 addresses
        if (
          a.kind() === "ipv6" &&
          a.isIPv4MappedAddress &&
          allowed.kind() === "ipv4"
        ) {
          a = a.toIPv4Address();
        }
        if (a.toNormalizedString() === allowed.toNormalizedString())
          return true;
      } catch (err) {
        continue;
      }
    }
  }

  return false;
}

// load whitelist
const WHITELIST = parseWhitelist(process.env.IP_WHITELIST);

// -----------------------------
// Middleware: IP whitelist
// -----------------------------
function ipWhitelistMiddleware(req, res, next) {
  // Get client IP. express's req.ip respects trust proxy if set.
  const clientIp = req.ip || req.connection.remoteAddress;

  if (!WHITELIST) {
    return next(); // no whitelist configured
  }

  if (!ipAllowed(clientIp, WHITELIST)) {
    return res.status(403).json({ error: "Forbidden: IP not allowed" });
  }

  next();
}

// -----------------------------
// Middleware: API token auth
// -----------------------------
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

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

// -----------------------------
// Public route (no authentication / whitelist bypass allowed if you want)
// -----------------------------
app.get("/", (req, res) => {
  res.json({ status: "SMTP API server running" });
});

// -----------------------------
// Protected route — applies whitelist first, then token auth
// -----------------------------
app.post("/send", ipWhitelistMiddleware, authMiddleware, async (req, res) => {
  try {
    const { to, subject, text, html } = req.body;

    if (!to || !subject) {
      return res.status(400).json({ error: "Missing 'to' or 'subject'" });
    }

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
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`SMTP middleware API running on port ${PORT}`);
});
