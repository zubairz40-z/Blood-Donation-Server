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


// ---------------- CORS (FINAL FIX) ----------------
const allowedOrigins = ["http://localhost:5173", process.env.CLIENT_URL].filter(Boolean);


app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: true,
  })
);


// ✅ Express 5 compatible preflight
app.options(/.*/, cors());


// ---------------- Firebase Admin ----------------
const serviceAccount = require("./firebase-admin-key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});


// ---------------- Env checks ----------------
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


// ---------------- MongoDB ----------------
const client = new MongoClient(process.env.DB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});


// ---------------- JWT middleware ----------------
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized (no token)" });
  }


  const token = authHeader.split(" ")[1];


  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized (invalid token)" });
    req.decoded = decoded;
    next();
  });
};


// ---------------- Base route ----------------
app.get("/", (req, res) => res.send("✅ Server running"));


// ---------------- JWT exchange ----------------
app.post("/jwt", async (req, res) => {
  try {
    const { token } = req.body || {};
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
    const usersCollection = db.collection("users");
    const donationRequestsCollection = db.collection("donation_requests");
    const fundingCollection = db.collection("fundings");


    const safeUserProjection = {
      _id: 1,
      name: 1,
      email: 1,
      avatar: 1,
      bloodGroup: 1,
      district: 1,
      upazila: 1,
      role: 1,
      status: 1,
      createdAt: 1,
      updatedAt: 1,
    };


    const getDBUser = async (email) => {
      const e = normalizeEmail(email);
      if (!e) return null;
      return usersCollection.findOne({ email: e });
    };


    // ---------------- Role middlewares ----------------
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
        const u = req.body || {};
        const email = normalizeEmail(u?.email);
        if (!email) return res.status(400).send({ message: "Email is required" });


        const existing = await usersCollection.findOne({ email });


        const safeUser = {
          name: u?.name || existing?.name || "",
          email,
          avatar: u?.avatar || existing?.avatar || "",
          bloodGroup: u?.bloodGroup || existing?.bloodGroup || "",
          district: u?.district || existing?.district || "",
          upazila: u?.upazila || existing?.upazila || "",
          role: existing?.role || "donor",
          status: existing?.status || "active",
        };


        const result = await usersCollection.updateOne(
          { email },
          { $set: { ...safeUser, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
          { upsert: true }
        );


        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Failed to save user", error: err.message });
      }
    });


    app.get("/users/me", verifyJWT, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const user = await usersCollection.findOne({ email }, { projection: safeUserProjection });
        if (!user) return res.status(404).send({ message: "User not found in database.", email });
        res.send(user);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    app.patch("/users/me", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const { name, avatar, district, upazila, bloodGroup } = req.body || {};


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


    app.get("/users", async (req, res) => {
      try {
        const users = await usersCollection
          .find({}, { projection: safeUserProjection })
          .sort({ createdAt: -1 })
          .limit(500)
          .toArray();
        res.send(users);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    app.get("/donors", async (req, res) => {
      try {
        const { bloodGroup, district, upazila } = req.query;
        const query = { role: "donor", status: "active" };
        if (bloodGroup) query.bloodGroup = bloodGroup;
        if (district) query.district = district;
        if (upazila) query.upazila = upazila;


        const donors = await usersCollection
          .find(query, { projection: safeUserProjection })
          .sort({ createdAt: -1 })
          .toArray();


        res.send(donors);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    // ---------------- ADMIN: USER MANAGEMENT (✅ FIXED PLACE) ----------------


    // ✅ Admin get users
    app.get("/admin/users", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection
          .find({}, { projection: safeUserProjection })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(users);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    // ✅ Update user role
    app.patch("/admin/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { role } = req.body || {};


        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid user id" });
        if (!["donor", "volunteer", "admin"].includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }


        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role, updatedAt: new Date() } }
        );


        if (result.matchedCount === 0) return res.status(404).send({ message: "User not found" });


        res.send({ success: true });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });


    // ✅ Block / Unblock user
    app.patch("/admin/users/:id/status", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body || {};


        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid user id" });
        if (!["active", "blocked"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }


        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );


        if (result.matchedCount === 0) return res.status(404).send({ message: "User not found" });


        res.send({ success: true });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });


    // ---------------- ADMIN STATS ----------------
    app.get("/admin/stats", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
      try {
        const [totalAllUsers, totalDonors, totalRequests] = await Promise.all([
          usersCollection.countDocuments({}),
          usersCollection.countDocuments({ role: "donor" }),
          donationRequestsCollection.countDocuments({}),
        ]);


        const byStatusAgg = await donationRequestsCollection
          .aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }])
          .toArray();


        const requestByStatus = byStatusAgg.reduce((acc, cur) => {
          acc[cur._id || "unknown"] = cur.count;
          return acc;
        }, {});


        const fundAgg = await fundingCollection
          .aggregate([
            {
              $group: {
                _id: null,
                totalFunding: { $sum: "$amount" },
                totalFundingCount: { $sum: 1 },
              },
            },
          ])
          .toArray();


        res.send({
          totalAllUsers,
          totalUsers: totalDonors,
          totalRequests,
          totalFunding: fundAgg[0]?.totalFunding || 0,
          totalFundingCount: fundAgg[0]?.totalFundingCount || 0,
          requestByStatus,
        });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    // ---------------- FUNDINGS ----------------
    app.post("/fundings", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const { amount, trxId, note } = req.body || {};


        const numericAmount = Number(amount);
        if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
          return res.status(400).send({ message: "Valid amount required" });
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
        const email = normalizeEmail(req.decoded?.email);
        const dbUser = await getDBUser(email);


        const query = dbUser?.role === "admin" ? {} : { email };
        const items = await fundingCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.send(items);
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });


    // ---------------- DONATION REQUESTS ----------------
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


    app.get("/donation-requests/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });


        const data = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!data) return res.status(404).send({ message: "Request not found" });


        res.send(data);
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });


    app.post("/donation-requests", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = normalizeEmail(req.decoded?.email);
        const payload = req.body || {};


        delete payload.requesterEmail;
        delete payload.status;


        const dbUser = await getDBUser(email);


        const doc = {
          ...payload,
          requesterName: payload.requesterName || dbUser?.name || "User",
          requesterEmail: email,
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


    app.patch("/donation-requests/:id/donate", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });


        const { donorName, donorEmail } = req.body || {};
        if (!donorEmail) return res.status(400).send({ message: "donorEmail required" });


        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Request not found" });


        if (existing.status !== "pending") {
          return res.status(400).send({ message: "Only pending requests can be donated" });
        }


        await donationRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: "inprogress",
              donorName: donorName || "Donor",
              donorEmail,
              updatedAt: new Date(),
            },
          }
        );


        res.send({ success: true });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });


    app.delete("/donation-requests/:id", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const { id } = req.params;
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


    app.patch("/donation-requests/:id/status", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });


        const email = normalizeEmail(req.decoded?.email);
        const { status } = req.body || {};


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
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid request id" });


        const { status } = req.body || {};
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
        const { id } = req.params;
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
      console.log("✅ Allowed origins:", allowedOrigins);
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


