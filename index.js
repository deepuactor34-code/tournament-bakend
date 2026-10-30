/**
 * Esports Tournament Backend — Single File
 * Node.js + Express + Firebase Admin SDK + Cashfree
 * Deployable on Vercel / Render / Node
 *
 * ENV VARS REQUIRED:
 *  FIREBASE_PROJECT_ID
 *  FIREBASE_CLIENT_EMAIL
 *  FIREBASE_PRIVATE_KEY
 *  CASHFREE_APP_ID
 *  CASHFREE_SECRET_KEY
 *  CASHFREE_ENV                (SANDBOX | PRODUCTION)
 *  CASHFREE_WEBHOOK_SECRET     (used for signature verification)
 *  BACKEND_BASE_URL            (e.g. https://api.yourdomain.com)
 *  PORT                        (optional, default 3000)
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const axios = require("axios");

/* =========================================================
   FIREBASE ADMIN INIT
========================================================= */
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
  });
}

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/* =========================================================
   EXPRESS APP
========================================================= */
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

/* =========================================================
   CONSTANTS
========================================================= */
const CASHFREE_BASE =
  process.env.CASHFREE_ENV === "PRODUCTION"
    ? "https://api.cashfree.com/pg"
    : "https://sandbox.cashfree.com/pg";

const CASHFREE_API_VERSION = "2023-08-01";

const DAILY_REWARD_AMOUNT = Number(process.env.DAILY_REWARD_AMOUNT || 2);
const DAILY_REWARD_COOLDOWN_MS = 24 * 60 * 60 * 1000;

// XP formula: constant
const XP_PER_KILL = 10;
const XP_PER_RANK_BASE = 50;

/* =========================================================
   HELPERS
========================================================= */
const now = () => new Date();

function safeStr(v, max = 500) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max);
}
function isPosNumber(v) {
  return typeof v === "number" && isFinite(v) && v > 0;
}
function round2(n) {
  return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}
function generateReferralCode(prefix = "APP") {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 6; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return `${prefix}${out}`;
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ message: "Missing auth token" });

    const decoded = await admin.auth().verifyIdToken(match[1]);
    req.uid = decoded.uid;
    req.tokenEmail = decoded.email || "";
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

/* =========================================================
   CASHFREE HELPERS
========================================================= */
function cashfreeHeaders() {
  return {
    "Content-Type": "application/json",
    "x-api-version": CASHFREE_API_VERSION,
    "x-client-id": process.env.CASHFREE_APP_ID,
    "x-client-secret": process.env.CASHFREE_SECRET_KEY,
  };
}

async function cashfreeCreateOrder({ orderId, amount, customerId, customerEmail, customerPhone, returnUrl }) {
  const payload = {
    order_id: orderId,
    order_amount: amount,
    order_currency: "INR",
    customer_details: {
      customer_id: customerId,
      customer_email: customerEmail || "player@example.com",
      customer_phone: customerPhone || "9999999999",
    },
    order_meta: {
      return_url: returnUrl,
    },
  };
  const resp = await axios.post(`${CASHFREE_BASE}/orders`, payload, {
    headers: cashfreeHeaders(),
    timeout: 15000,
  });
  return resp.data;
}

async function cashfreeGetOrder(orderId) {
  const resp = await axios.get(`${CASHFREE_BASE}/orders/${encodeURIComponent(orderId)}`, {
    headers: cashfreeHeaders(),
    timeout: 15000,
  });
  return resp.data;
}

/**
 * Cashfree webhook signature verification.
 * Cashfree sends header `x-webhook-signature` = base64( HMAC_SHA256( timestamp + rawBody, secret ) )
 * Also `x-webhook-timestamp`.
 * We must verify against the RAW body — hence express.raw for the webhook route.
 */
function verifyCashfreeWebhook(rawBody, timestamp, signature) {
  if (!timestamp || !signature) return false;
  const secret = process.env.CASHFREE_WEBHOOK_SECRET || "";
  if (!secret) return false;
  const signedPayload = `${timestamp}${rawBody}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("base64");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

/* =========================================================
   UTIL: ensure user doc exists (used by signup & fallback)
========================================================= */
async function ensureUserDoc(uid, username, email, referralCode) {
  const ref = db.collection("users").doc(uid);
  const snap = await ref.get();
  if (snap.exists) return { exists: true, data: snap.data(), ref };

  let finalRefCode = referralCode;
  if (!finalRefCode) {
    // ensure uniqueness (best-effort)
    for (let i = 0; i < 5; i++) {
      const candidate = generateReferralCode();
      const q = await db.collection("users").where("referralCode", "==", candidate).limit(1).get();
      if (q.empty) { finalRefCode = candidate; break; }
    }
    if (!finalRefCode) finalRefCode = generateReferralCode("X");
  }

  const data = {
    uid,
    username: username || "Player",
    email: email || "",
    wallet: 0,
    totalXP: 0,
    joinedMatches: [],
    referralCode: finalRefCode,
    referredBy: null,
    matchesPlayed: 0,
    totalKills: 0,
    dailyStreak: 0,
    lastDailyRewardAt: null,
    isVIP: false,
    createdAt: now(),
  };
  await ref.set(data);
  return { exists: false, data, ref };
}

/* =========================================================
   ROUTES
========================================================= */

/* ---------- HEALTH ---------- */
app.get("/", (_req, res) => res.json({ ok: true, service: "esports-backend" }));
app.get("/healthz", (_req, res) => res.json({ ok: true }));

/* =========================================================
   AUTH: SIGNUP
========================================================= */
app.post("/auth/signup", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const username = safeStr(req.body.username, 60);
    const email = safeStr(req.body.email || req.tokenEmail, 120);
    const referralCode = safeStr(req.body.referralCode, 20);

    if (!username) return res.status(400).json({ message: "username required" });

    const ref = db.collection("users").doc(uid);
    const snap = await ref.get();
    if (snap.exists) {
      return res.json({ ok: true, alreadyExists: true, user: snap.data() });
    }

    // generate unique referral code
    let finalRefCode = null;
    for (let i = 0; i < 5; i++) {
      const candidate = generateReferralCode();
      const q = await db.collection("users").where("referralCode", "==", candidate).limit(1).get();
      if (q.empty) { finalRefCode = candidate; break; }
    }
    if (!finalRefCode) finalRefCode = generateReferralCode("X");

    let referredBy = null;
    if (referralCode) {
      const q = await db.collection("users").where("referralCode", "==", referralCode).limit(1).get();
      if (!q.empty) referredBy = q.docs[0].id;
    }

    const data = {
      uid,
      username,
      email,
      wallet: 0,
      totalXP: 0,
      joinedMatches: [],
      referralCode: finalRefCode,
      referredBy,
      matchesPlayed: 0,
      totalKills: 0,
      dailyStreak: 0,
      lastDailyRewardAt: null,
      isVIP: false,
      createdAt: now(),
    };
    await ref.set(data);

    return res.json({ ok: true, user: data });
  } catch (e) {
    console.error("signup error", e);
    return res.status(500).json({ message: "signup failed" });
  }
});

/* =========================================================
   WALLET: CREATE ORDER (Cashfree)
========================================================= */
app.post("/wallet/createOrder", requireAuth, async (req, res) => {
  try {
    const amount = round2(Number(req.body.amount));
    if (!isPosNumber(amount) || amount < 1 || amount > 100000) {
      return res.status(400).json({ message: "Invalid amount" });
    }

    const userRef = db.collection("users").doc(req.uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) return res.status(404).json({ message: "User not found" });

    const user = userSnap.data();

    // unique order id
    const orderId = `ORD_${req.uid.slice(0, 8)}_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`;

    const returnUrl = `${process.env.BACKEND_BASE_URL || ""}/wallet/paymentReturn?orderId=${orderId}`;

    const cfOrder = await cashfreeCreateOrder({
      orderId,
      amount,
      customerId: req.uid,
      customerEmail: user.email,
      customerPhone: "9999999999",
      returnUrl,
    });

    // persist pending transaction — wallet NOT touched
    await db.collection("transactions").doc(orderId).set({
      transactionId: orderId,
      orderId,
      userId: req.uid,
      type: "DEPOSIT",
      amount,
      status: "PENDING",
      provider: "CASHFREE",
      cashfreeOrderId: cfOrder.order_id,
      paymentSessionId: cfOrder.payment_session_id,
      createdAt: now(),
      updatedAt: now(),
    });

    return res.json({
      ok: true,
      orderId,
      amount,
      paymentSessionId: cfOrder.payment_session_id,
      cashfreeOrderId: cfOrder.order_id,
      environment: process.env.CASHFREE_ENV || "SANDBOX",
    });
  } catch (e) {
    console.error("createOrder error", e?.response?.data || e.message);
    return res.status(500).json({ message: "Failed to create order" });
  }
});

/* =========================================================
   WALLET: PAYMENT RETURN (redirect from Cashfree — informational only)
========================================================= */
app.get("/wallet/paymentReturn", async (req, res) => {
  // DO NOT CREDIT HERE. Webhook is source of truth.
  // Just redirect to a friendly page or app.
  const orderId = safeStr(req.query.orderId, 120);
  return res.redirect(
    `${process.env.BACKEND_BASE_URL || ""}/?payu_status=success&orderId=${encodeURIComponent(orderId)}`
  );
});

/* =========================================================
   CASHFREE WEBHOOK — ONLY PLACE WALLET IS CREDITED
   Raw body required for signature verification.
========================================================= */
app.post(
  "/webhook/cashfree",
  express.raw({ type: "*/*" }),
  async (req, res) => {
    try {
      const rawBody = req.body instanceof Buffer ? req.body.toString("utf8") : "";
      const signature = req.headers["x-webhook-signature"];
      const timestamp = req.headers["x-webhook-timestamp"];

      if (!verifyCashfreeWebhook(rawBody, timestamp, signature)) {
        console.warn("webhook signature failed");
        return res.status(401).json({ message: "Invalid signature" });
      }

      let payload;
      try { payload = JSON.parse(rawBody); } catch { return res.status(400).json({ message: "Bad JSON" }); }

      // Cashfree webhook shape:
      // { type: "PAYMENT_SUCCESS_WEBHOOK", data: { order: {...}, payment: {...}, customer_details: {...} } }
      const type = payload?.type || "";
      const data = payload?.data || {};
      const order = data.order || {};
      const payment = data.payment || {};

      const orderId = order.order_id;
      const orderAmount = Number(order.order_amount);
      const paymentStatus = payment.payment_status || "";
      const cfPaymentId = payment.cf_payment_id;

      if (!orderId) return res.status(400).json({ message: "Missing orderId" });

      const txnRef = db.collection("transactions").doc(orderId);

      await db.runTransaction(async (tx) => {
        const txnSnap = await tx.get(txnRef);
        if (!txnSnap.exists) {
          // Unknown order — ignore to stay idempotent
          return;
        }
        const txn = txnSnap.data();

        // Idempotency: if already final, do nothing
        if (txn.status === "SUCCESS" || txn.status === "FAILED") return;

        // Verify amount matches
        if (Math.abs(Number(txn.amount) - orderAmount) > 0.01) {
          tx.update(txnRef, {
            status: "FAILED",
            reason: "AMOUNT_MISMATCH",
            updatedAt: now(),
          });
          return;
        }

        if (type === "PAYMENT_SUCCESS_WEBHOOK" || paymentStatus === "SUCCESS") {
          const userRef = db.collection("users").doc(txn.userId);
          const userSnap = await tx.get(userRef);
          if (!userSnap.exists) {
            tx.update(txnRef, { status: "FAILED", reason: "USER_NOT_FOUND", updatedAt: now() });
            return;
          }

          const currentWallet = Number(userSnap.data().wallet || 0);
          const newWallet = round2(currentWallet + Number(txn.amount));

          tx.update(userRef, { wallet: newWallet });
          tx.update(txnRef, {
            status: "SUCCESS",
            cfPaymentId: cfPaymentId || null,
            updatedAt: now(),
          });
        } else {
          tx.update(txnRef, {
            status: "FAILED",
            reason: paymentStatus || "UNKNOWN",
            updatedAt: now(),
          });
        }
      });

      return res.json({ ok: true });
    } catch (e) {
      console.error("webhook error", e);
      return res.status(500).json({ message: "webhook failed" });
    }
  }
);

/* =========================================================
   MATCH: JOIN
========================================================= */
app.post("/match/join", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const matchId = safeStr(req.body.matchId, 120);
    const gameUids = Array.isArray(req.body.gameUids) ? req.body.gameUids : [];

    if (!matchId) return res.status(400).json({ message: "matchId required" });
    if (![1, 2, 4].includes(gameUids.length)) {
      return res.status(400).json({ message: "gameUids must contain 1, 2, or 4 entries" });
    }

    const cleanedGameUids = [];
    for (const g of gameUids) {
      const s = safeStr(String(g), 40);
      if (!s) return res.status(400).json({ message: "Invalid gameUid" });
      if (cleanedGameUids.includes(s)) {
        return res.status(400).json({ message: "Duplicate gameUid in request" });
      }
      cleanedGameUids.push(s);
    }

    // detect duplicate gameUids across ALL teams (global pre-check, also enforced in txn)
    const teamsRef = db.collection("matches").doc(matchId).collection("teams");
    const allTeamsSnap = await teamsRef.get();
    for (const tDoc of allTeamsSnap.docs) {
      const tData = tDoc.data();
      const existing = Array.isArray(tData.gameUids) ? tData.gameUids : [];
      for (const g of cleanedGameUids) {
        if (existing.includes(g)) {
          return res.status(409).json({ message: `gameUid ${g} already registered in this match` });
        }
      }
    }

    const result = await db.runTransaction(async (tx) => {
      const matchRef = db.collection("matches").doc(matchId);
      const userRef = db.collection("users").doc(uid);

      const [matchSnap, userSnap] = await Promise.all([
        tx.get(matchRef),
        tx.get(userRef),
      ]);

      if (!matchSnap.exists) throw { code: 404, message: "Match not found" };
      if (!userSnap.exists) throw { code: 404, message: "User not found" };

      const match = matchSnap.data();
      const user = userSnap.data();

      if (match.status !== "upcoming") throw { code: 409, message: "Match is not open for joining" };

      const mode = match.mode;
      const expectedPlayers = mode === "SOLO" ? 1 : mode === "DUO" ? 2 : mode === "SQUAD" ? 4 : null;
      if (!expectedPlayers) throw { code: 400, message: "Invalid match mode" };
      if (cleanedGameUids.length !== expectedPlayers) {
        throw { code: 400, message: `Mode ${mode} requires exactly ${expectedPlayers} gameUid(s)` };
      }

      const maxPlayers = Number(match.maxPlayers || 0);
      const joinedCount = Number(match.joinedCount || 0);
      if (maxPlayers > 0 && joinedCount + expectedPlayers > maxPlayers) {
        throw { code: 409, message: "Not enough slots" };
      }

      const entryFee = Number(match.entryFee || 0);

      // wallet check
      const wallet = Number(user.wallet || 0);
      if (wallet < entryFee) throw { code: 402, message: "Insufficient wallet balance" };

      // team doc
      const teamRef = matchRef.collection("teams").doc(uid);
      const teamSnap = await tx.get(teamRef);
      if (teamSnap.exists) throw { code: 409, message: "You have already joined this match" };

      // cross-check duplicates inside transaction against any team docs
      const teamsSnapTx = await tx.get(matchRef.collection("teams"));
      for (const d of teamsSnapTx.docs) {
        const data = d.data();
        const existing = Array.isArray(data.gameUids) ? data.gameUids : [];
        for (const g of cleanedGameUids) {
          if (existing.includes(g)) throw { code: 409, message: `gameUid ${g} already registered` };
        }
      }

      // deduct wallet
      const newWallet = round2(wallet - entryFee);
      tx.update(userRef, {
        wallet: newWallet,
        joinedMatches: FieldValue.arrayUnion(matchId),
      });

      // team group
      tx.set(teamRef, {
        ownerUid: uid,
        ownerUsername: user.username || "Player",
        gameUids: cleanedGameUids,
        mode,
        matchId,
        createdAt: now(),
      });

      // update match counter
      tx.update(matchRef, { joinedCount: joinedCount + expectedPlayers });

      // log transaction
      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "MATCH_JOIN",
        matchId,
        amount: entryFee,
        status: "SUCCESS",
        timestamp: now(),
      });

      return { entryFee, newWallet, matchId };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message) return res.status(e.code).json({ message: e.message });
    console.error("match join error", e);
    return res.status(500).json({ message: "Failed to join match" });
  }
});

/* =========================================================
   REWARDS: DAILY
========================================================= */
app.post("/rewards/daily", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(userRef);
      if (!snap.exists) throw { code: 404, message: "User not found" };
      const user = snap.data();

      const last = user.lastDailyRewardAt ? new Date(user.lastDailyRewardAt).getTime() : 0;
      const current = Date.now();
      if (last && current - last < DAILY_REWARD_COOLDOWN_MS) {
        const remaining = DAILY_REWARD_COOLDOWN_MS - (current - last);
        throw { code: 429, message: `Daily reward not ready. Try again in ${Math.ceil(remaining / 60000)} min` };
      }

      const newWallet = round2(Number(user.wallet || 0) + DAILY_REWARD_AMOUNT);
      const newStreak = Number(user.dailyStreak || 0) + 1;

      tx.update(userRef, {
        wallet: newWallet,
        dailyStreak: newStreak,
        lastDailyRewardAt: now(),
      });

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "DAILY_REWARD",
        amount: DAILY_REWARD_AMOUNT,
        status: "SUCCESS",
        timestamp: now(),
      });

      return { wallet: newWallet, dailyStreak: newStreak, amount: DAILY_REWARD_AMOUNT };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message) return res.status(e.code).json({ message: e.message });
    console.error("daily reward error", e);
    return res.status(500).json({ message: "Failed to claim daily reward" });
  }
});

/* =========================================================
   WALLET: WITHDRAW
========================================================= */
app.post("/wallet/withdraw", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const amount = round2(Number(req.body.amount));
    const upiId = safeStr(req.body.upiId, 80);

    if (!isPosNumber(amount) || amount < 10) {
      return res.status(400).json({ message: "Minimum withdrawal is ₹10" });
    }
    if (!upiId || !/^[\w.\-]+@[\w.\-]+$/.test(upiId)) {
      return res.status(400).json({ message: "Invalid UPI ID" });
    }

    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(userRef);
      if (!snap.exists) throw { code: 404, message: "User not found" };
      const user = snap.data();

      const wallet = Number(user.wallet || 0);
      if (wallet < amount) throw { code: 402, message: "Insufficient wallet balance" };

      const newWallet = round2(wallet - amount);
      tx.update(userRef, { wallet: newWallet });

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "WITHDRAW",
        amount,
        upiId,
        status: "PENDING",
        timestamp: now(),
      });

      return { newWallet, txnId: txnRef.id, amount };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message) return res.status(e.code).json({ message: e.message });
    console.error("withdraw error", e);
    return res.status(500).json({ message: "Failed to request withdrawal" });
  }
});

/* =========================================================
   ADMIN: DISTRIBUTE PRIZE
========================================================= */
function calcRankPrize(rankPrizes, rank) {
  if (!rankPrizes || typeof rankPrizes !== "object") return 0;
  const v = rankPrizes[String(rank)];
  return Number(v || 0);
}

app.post("/admin/match/distribute", requireAuth, async (req, res) => {
  try {
    const matchId = safeStr(req.body.matchId, 120);
    const gameUid = safeStr(String(req.body.gameUid || ""), 40);
    const rank = Number(req.body.rank);
    const kills = Number(req.body.kills || 0);

    if (!matchId) return res.status(400).json({ message: "matchId required" });
    if (!gameUid) return res.status(400).json({ message: "gameUid required" });
    if (!Number.isFinite(rank) || rank < 1) return res.status(400).json({ message: "rank must be >= 1" });
    if (!Number.isFinite(kills) || kills < 0) return res.status(400).json({ message: "kills must be >= 0" });

    const matchRef = db.collection("matches").doc(matchId);

    const result = await db.runTransaction(async (tx) => {
      const matchSnap = await tx.get(matchRef);
      if (!matchSnap.exists) throw { code: 404, message: "Match not found" };
      const match = matchSnap.data();

      // resolve team
      const teamsSnap = await tx.get(matchRef.collection("teams"));
      let teamDoc = null;
      for (const d of teamsSnap.docs) {
        const data = d.data();
        if (Array.isArray(data.gameUids) && data.gameUids.includes(gameUid)) {
          teamDoc = { id: d.id, data };
          break;
        }
      }
      if (!teamDoc) throw { code: 404, message: "No team owns this gameUid" };

      const ownerUid = teamDoc.data.ownerUid;
      if (!ownerUid) throw { code: 500, message: "Team missing ownerUid" };

      // dedupe using per-team distribution flag keyed by gameUid
      const distributedMap = match.prizeDistributed || {};
      const teamKey = teamDoc.id;
      const key = `${teamKey}:${gameUid}`;
      if (distributedMap[key]) {
        throw { code: 409, message: "Prize already distributed for this gameUid" };
      }

      // compute rewards
      const perKillRate = Number(match.perKillRate || 0);
      const rankPrize = calcRankPrize(match.rankPrizes, rank);
      const killPrize = perKillRate * kills;
      const totalPrize = round2(killPrize + rankPrize);

      // XP formula (constant)
      const xp = kills * XP_PER_KILL + Math.max(0, (10 - rank)) * XP_PER_RANK_BASE;

      const ownerRef = db.collection("users").doc(ownerUid);
      const ownerSnap = await tx.get(ownerRef);
      if (!ownerSnap.exists) throw { code: 404, message: "Team owner not found" };
      const owner = ownerSnap.data();

      const newWallet = round2(Number(owner.wallet || 0) + totalPrize);
      const newXP = Number(owner.totalXP || 0) + xp;
      const newKills = Number(owner.totalKills || 0) + kills;
      const newMatchesPlayed = Number(owner.matchesPlayed || 0) + 1;

      tx.update(ownerRef, {
        wallet: newWallet,
        totalXP: newXP,
        totalKills: newKills,
        matchesPlayed: newMatchesPlayed,
      });

      // mark distributed (atomic on match doc)
      const update = {};
      update[`prizeDistributed.${key}`] = true;
      tx.update(matchRef, update);

      // log prize txn
      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: ownerUid,
        type: "PRIZE",
        matchId,
        gameUid,
        rank,
        kills,
        amount: totalPrize,
        xpAwarded: xp,
        status: "SUCCESS",
        timestamp: now(),
      });

      return {
        ownerUid,
        totalPrize,
        xpAwarded: xp,
        newWallet,
        newXP,
      };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message) return res.status(e.code).json({ message: e.message });
    console.error("distribute error", e);
    return res.status(500).json({ message: "Failed to distribute prize" });
  }
});

/* =========================================================
   ORDER STATUS (for polling after webhook)
========================================================= */
app.get("/wallet/orderStatus", requireAuth, async (req, res) => {
  try {
    const orderId = safeStr(req.query.orderId, 120);
    if (!orderId) return res.status(400).json({ message: "orderId required" });

    const snap = await db.collection("transactions").doc(orderId).get();
    if (!snap.exists) return res.status(404).json({ message: "Order not found" });

    const txn = snap.data();
    if (txn.userId !== req.uid) return res.status(403).json({ message: "Forbidden" });

    let status = "pending";
    if (txn.status === "SUCCESS") status = "credited";
    else if (txn.status === "FAILED") status = "failed";

    return res.json({ ok: true, status, amount: txn.amount });
  } catch (e) {
    console.error("orderStatus error", e);
    return res.status(500).json({ message: "Failed to fetch status" });
  }
});

/* =========================================================
   FALLBACK
========================================================= */
app.use((req, res) => res.status(404).json({ message: "Not found" }));

/* =========================================================
   START
========================================================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Esports backend running on port ${PORT}`);
});

module.exports = app;
