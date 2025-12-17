const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());

// ✅ CORS
const allowedOrigins = ["http://localhost:5173", process.env.CLIENT_URL].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS: " + origin));
    },
    credentials: true,
  })
);

const serviceAccount = require("./firebase-admin-key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

if (!process.env.DB_URI) {
  console.error("❌ DB_URI missing in .env");
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET missing in .env");
  process.exit(1);
}

const normalizeEmail = (email) =>
  typeof email === "string" ? email.trim().toLowerCase() : "";

const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized (no token)" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized (invalid token)" });
    req.decoded = decoded;
    next();
  });
};

app.get("/", (req, res) => {
  res.send("✅ Server running");
});

app.post("/jwt", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).send({ message: "Token missing" });

    const decoded = await admin.auth().verifyIdToken(token);
    const email = normalizeEmail(decoded.email);

    if (!email) {
      return res.status(401).send({ message: "Unauthorized (no email in Firebase token)" });
    }

    const serverToken = jwt.sign({ email, uid: decoded.uid }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.send({ token: serverToken });
  } catch (err) {
    console.log("JWT error:", err.message);
    res.status(401).send({ message: "Unauthorized" });
  }
});

async function run() {
  try {
    await client.connect();
    console.log("✅ MongoDB connected");

    const db = client.db("bloodDB");
    console.log("✅ Using DB:", db.databaseName);

    const usersCollection = db.collection("users");
    const donationRequestsCollection = db.collection("donation_requests");
    const fundingCollection = db.collection("fundings");

    const getDBUser = async (email) => {
      const e = normalizeEmail(email);
      if (!e) return null;
      return usersCollection.findOne({ email: e });
    };

    const verifyAdmin = async (req, res, next) => {
      try {
        const user = await getDBUser(req.decoded?.email);
        if (!user || user.role !== "admin") {
          return res.status(403).send({ message: "Forbidden: Admin only" });
        }
        next();
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    };

    const verifyVolunteerOrAdmin = async (req, res, next) => {
      try {
        const user = await getDBUser(req.decoded?.email);
        if (!user || !["admin", "volunteer"].includes(user.role)) {
          return res.status(403).send({ message: "Forbidden: Admin/Volunteer only" });
        }
        next();
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    };

    const verifyNotBlocked = async (req, res, next) => {
      try {
        const user = await getDBUser(req.decoded?.email);
        if (user?.status === "blocked") {
          return res.status(403).send({ message: "Blocked users cannot perform this action" });
        }
        next();
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    };

    // ---------------- USERS ----------------
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        const email = normalizeEmail(user?.email);
        if (!email) return res.status(400).send({ message: "Email is required" });

        const existing = await usersCollection.findOne({ email });

        const safeUser = {
          name: user?.name || existing?.name || "",
          email,
          avatar: user?.avatar || existing?.avatar || "",
          bloodGroup: user?.bloodGroup || existing?.bloodGroup || "",
          district: user?.district || existing?.district || "",
          upazila: user?.upazila || existing?.upazila || "",
          role: existing?.role || "donor",
          status: existing?.status || "active",
        };

        const result = await usersCollection.updateOne(
          { email },
          {
            $set: { ...safeUser, updatedAt: new Date() },
            $setOnInsert: { createdAt: new Date() },
          },
          { upsert: true }
        );

        res.send(result);
      } catch (err) {
        console.log("POST /users error:", err.message);
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    app.get("/users/me", verifyJWT, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({
            message: "User not found in database. Please register/complete profile.",
            email,
          });
        }

        res.send(user);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/users/me", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const { name, avatar, district, upazila, bloodGroup } = req.body;

        const updateDoc = {
          ...(name !== undefined ? { name } : {}),
          ...(avatar !== undefined ? { avatar } : {}),
          ...(district !== undefined ? { district } : {}),
          ...(upazila !== undefined ? { upazila } : {}),
          ...(bloodGroup !== undefined ? { bloodGroup } : {}),
          updatedAt: new Date(),
        };

        const result = await usersCollection.updateOne({ email }, { $set: updateDoc });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ---------------- FUNDINGS ----------------
    app.post("/fundings", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const { amount, trxId, note } = req.body;

        const numericAmount = Number(amount);
        if (!numericAmount || numericAmount < 10) {
          return res.status(400).send({ message: "Amount must be at least 10" });
        }

        const dbUser = await getDBUser(email);

        const doc = {
          amount: numericAmount,
          name: dbUser?.name || "User",
          email,
          trxId: trxId ? String(trxId).trim() : null,
          note: note ? String(note).trim() : null,
          status: "paid",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await fundingCollection.insertOne(doc);
        res.status(201).send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    app.get("/fundings", verifyJWT, async (req, res) => {
      try {
        const items = await fundingCollection
          .find({ createdAt: { $exists: true } })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(items);
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ---------------- DONATION REQUESTS ----------------

    // ✅ PUBLIC list
    app.get("/donation-requests", async (req, res) => {
      try {
        const { status, page = 1, limit = 12 } = req.query;

        const query = {};
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(Number(limit))
            .toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ ✅ IMPORTANT: put /my and /my-recent BEFORE /:id
    app.get("/donation-requests/my-recent", verifyJWT, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const result = await donationRequestsCollection
          .find({ requesterEmail: email })
          .sort({ createdAt: -1 })
          .limit(3)
          .toArray();

        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/donation-requests/my", verifyJWT, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const { status, page = 1, limit = 10 } = req.query;

        const query = { requesterEmail: email };
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(Number(limit))
            .toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ PRIVATE get one (after my routes)
    app.get("/donation-requests/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid request id" });
        }

        const data = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!data) return res.status(404).send({ message: "Request not found" });
        res.send(data);
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ CREATE REQUEST
    app.post("/donation-requests", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const tokenEmail = normalizeEmail(req.decoded?.email);
        if (!tokenEmail) return res.status(401).send({ message: "Unauthorized" });

        const payload = req.body || {};
        delete payload.requesterEmail;
        delete payload.status;

        const dbUser = await getDBUser(tokenEmail);

        const doc = {
          ...payload,
          requesterName: payload.requesterName || dbUser?.name || "User",
          requesterEmail: tokenEmail,
          status: "pending",
          donorName: null,
          donorEmail: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await donationRequestsCollection.insertOne(doc);
        res.status(201).send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ DONOR delete own request
    app.delete("/donation-requests/:id", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });

        const email = normalizeEmail(req.decoded?.email);

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Not found" });

        if (normalizeEmail(existing.requesterEmail) !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const result = await donationRequestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ DONOR set done/canceled
    app.patch("/donation-requests/:id/status", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });

        const email = normalizeEmail(req.decoded?.email);
        const { status } = req.body;

        if (!["done", "canceled"].includes(status)) {
          return res.status(400).send({ message: "Donor can only set done or canceled" });
        }

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Not found" });

        if (normalizeEmail(existing.requesterEmail) !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        if (existing.status !== "inprogress") {
          return res.status(400).send({ message: "Only inprogress can be done/canceled" });
        }

        const result = await donationRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );

        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ---------------- ADMIN/VOLUNTEER: DONATION REQUESTS ----------------
    app.get("/admin/donation-requests", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
      try {
        const { status, page = 1, limit = 10 } = req.query;

        const query = {};
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(Number(limit))
            .toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/admin/donation-requests/:id/status", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });

        const { status } = req.body;
        if (!["pending", "inprogress", "done", "canceled"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const result = await donationRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );

        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.delete("/admin/donation-requests/:id", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });

        const result = await donationRequestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ---------------- START SERVER ----------------
    app.listen(port, () => {
      console.log(`✅ Server listening on http://localhost:${port}`);
    });
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
}

run();

app.use((err, req, res, next) => {
  console.error("❌ Server error:", err.message);
  res.status(500).send({ message: err.message || "Server error" });
});
