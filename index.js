// index.js (FULL - Perfect)

const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// -------------------- Middlewares --------------------
app.use(express.json());

// ✅ CORS
const allowedOrigins = [
  "http://localhost:5173",
  process.env.CLIENT_URL, // e.g. https://your-site.netlify.app
].filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

// -------------------- Firebase Admin --------------------
const serviceAccount = require("./firebase-admin-key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// -------------------- Env checks --------------------
if (!process.env.DB_URI) {
  console.error("❌ DB_URI missing in .env");
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error("❌ JWT_SECRET missing in .env");
  process.exit(1);
}

// -------------------- MongoDB --------------------
const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// -------------------- JWT Middleware --------------------
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized (no token)" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized (invalid token)" });
    req.decoded = decoded; // { email, uid }
    next();
  });
};

// -------------------- Basic Route --------------------
app.get("/", (req, res) => {
  res.send("✅ Server running");
});

// -------------------- JWT Route --------------------
// Client sends Firebase ID Token => server verifies => server returns JWT
app.post("/jwt", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).send({ message: "Token missing" });

    const decoded = await admin.auth().verifyIdToken(token);

    const serverToken = jwt.sign(
      { email: decoded.email, uid: decoded.uid },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

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

    // -------------------- Helpers --------------------
    const getDBUser = async (email) => {
      if (!email) return null;
      return usersCollection.findOne({ email });
    };

    // -------------------- Role Middlewares --------------------
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.decoded?.email;
        const user = await getDBUser(email);
        if (!user || user.role !== "admin") {
          return res.status(403).send({ message: "Forbidden: Admin only" });
        }
        next();
      } catch (err) {
        res.status(500).send({ message: "Server error" });
      }
    };

    const verifyVolunteerOrAdmin = async (req, res, next) => {
      try {
        const email = req.decoded?.email;
        const user = await getDBUser(email);
        if (!user || !["admin", "volunteer"].includes(user.role)) {
          return res.status(403).send({ message: "Forbidden: Admin/Volunteer only" });
        }
        next();
      } catch (err) {
        res.status(500).send({ message: "Server error" });
      }
    };

    // ✅ Blocked guard for any donor action
    const verifyNotBlocked = async (req, res, next) => {
      try {
        const email = req.decoded?.email;
        const user = await getDBUser(email);
        if (user?.status === "blocked") {
          return res.status(403).send({ message: "Blocked users cannot perform this action" });
        }
        next();
      } catch (err) {
        res.status(500).send({ message: "Server error" });
      }
    };

    // -------------------- USERS --------------------

    // ✅ Register / Save user (does not overwrite existing role/status)
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email) return res.status(400).send({ message: "Email is required" });

        const existing = await usersCollection.findOne({ email: user.email });

        const safeUser = {
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          bloodGroup: user.bloodGroup,
          district: user.district,
          upazila: user.upazila,
          role: existing?.role || "donor",
          status: existing?.status || "active",
        };

        const result = await usersCollection.updateOne(
          { email: safeUser.email },
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

    // ✅ Logged-in user profile (for dashboard)
    app.get("/users/me", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const user = await usersCollection.findOne(
          { email },
          {
            projection: {
              name: 1,
              email: 1,
              avatar: 1,
              role: 1,
              status: 1,
              district: 1,
              upazila: 1,
              bloodGroup: 1,
              createdAt: 1,
              updatedAt: 1,
            },
          }
        );
        res.send(user);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ Update logged-in user profile (email cannot be changed)
    app.patch("/users/me", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const email = req.decoded.email;
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

    // ✅ PUBLIC: Search donors (active donors only)
    app.get("/donors", async (req, res) => {
      try {
        const { bloodGroup, district, upazila } = req.query;

        const query = { role: "donor", status: "active" };
        if (bloodGroup) query.bloodGroup = bloodGroup;
        if (district) query.district = district;
        if (upazila) query.upazila = upazila;

        const donors = await usersCollection
          .find(query, {
            projection: { name: 1, email: 1, avatar: 1, bloodGroup: 1, district: 1, upazila: 1 },
          })
          .toArray();

        res.send(donors);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // -------------------- ADMIN: USERS --------------------

    app.get("/admin/users", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const { status } = req.query;
        const query = {};
        if (status) query.status = status;

        const users = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.send(users);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/admin/users/:id/block", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "blocked", updatedAt: new Date() } }
        );
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/admin/users/:id/unblock", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "active", updatedAt: new Date() } }
        );
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/admin/users/:id/make-volunteer", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role: "volunteer", updatedAt: new Date() } }
        );
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.patch("/admin/users/:id/make-admin", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role: "admin", updatedAt: new Date() } }
        );
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // -------------------- DONATION REQUESTS --------------------

    // ✅ PUBLIC: list requests by status + pagination
    app.get("/donation-requests", async (req, res) => {
      try {
        const { status, page = 1, limit = 12 } = req.query;

        const query = {};
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ PRIVATE: details
    app.get("/donation-requests/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const data = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!data) return res.status(404).send({ message: "Request not found" });
        res.send(data);
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ PRIVATE: create request (blocked cannot)
    app.post("/donation-requests", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const payload = req.body;

        if (payload?.requesterEmail !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden: requester email mismatch" });
        }

        const doc = {
          ...payload,
          status: "pending",
          donorName: null,
          donorEmail: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await donationRequestsCollection.insertOne(doc);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ PRIVATE: donate (pending -> inprogress)
    app.patch("/donation-requests/:id/donate", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        const { donorName, donorEmail } = req.body;

        if (!donorName || !donorEmail) {
          return res.status(400).send({ message: "donorName and donorEmail are required" });
        }

        if (donorEmail !== req.decoded.email) {
          return res.status(403).send({ message: "Forbidden: donor email mismatch" });
        }

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Request not found" });
        if (existing.status !== "pending") {
          return res.status(400).send({ message: "Only pending requests can be donated" });
        }

        const result = await donationRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "inprogress", donorName, donorEmail, updatedAt: new Date() } }
        );

        res.send({ success: true, modifiedCount: result.modifiedCount });
      } catch (err) {
        res.status(500).send({ message: "Server error", error: err.message });
      }
    });

    // ✅ PRIVATE: donor recent 3
    app.get("/donation-requests/my-recent", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const result = await donationRequestsCollection.find({ requesterEmail: email }).sort({ createdAt: -1 }).limit(3).toArray();
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ PRIVATE: donor all (filter + pagination)
    app.get("/donation-requests/my", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const { status, page = 1, limit = 10 } = req.query;

        const query = { requesterEmail: email };
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ PRIVATE: donor update request (owner only)
    app.patch("/donation-requests/:id", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decoded.email;

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Not found" });

        if (existing.requesterEmail !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const fields = [
          "recipientName",
          "recipientDistrict",
          "recipientUpazila",
          "hospitalName",
          "fullAddress",
          "bloodGroup",
          "donationDate",
          "donationTime",
          "requestMessage",
        ];

        const updateDoc = { updatedAt: new Date() };
        fields.forEach((key) => {
          if (req.body[key] !== undefined) updateDoc[key] = req.body[key];
        });

        const result = await donationRequestsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateDoc });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ PRIVATE: donor delete (owner only)
    app.delete("/donation-requests/:id", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decoded.email;

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Not found" });

        if (existing.requesterEmail !== email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const result = await donationRequestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ PRIVATE: donor status update (ONLY done/canceled, ONLY when inprogress)
    app.patch("/donation-requests/:id/status", verifyJWT, verifyNotBlocked, async (req, res) => {
      try {
        const id = req.params.id;
        const email = req.decoded.email;
        const { status } = req.body;

        if (!["done", "canceled"].includes(status)) {
          return res.status(400).send({ message: "Donor can only set done or canceled" });
        }

        const existing = await donationRequestsCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).send({ message: "Not found" });

        if (existing.requesterEmail !== email) {
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

    // -------------------- ADMIN/VOLUNTEER: ALL DONATION REQUESTS --------------------

    app.get("/admin/donation-requests", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
      try {
        const { status, page = 1, limit = 10 } = req.query;

        const query = {};
        if (status) query.status = status;

        const skip = (Number(page) - 1) * Number(limit);

        const [items, total] = await Promise.all([
          donationRequestsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
          donationRequestsCollection.countDocuments(query),
        ]);

        res.send({ items, total });
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ✅ Admin/Volunteer: status update (any request)
    app.patch("/admin/donation-requests/:id/status", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        const allowed = ["pending", "inprogress", "done", "canceled"];
        if (!allowed.includes(status)) {
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

    // ✅ Admin only: delete any request
    app.delete("/admin/donation-requests/:id", verifyJWT, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await donationRequestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch {
        res.status(500).send({ message: "Server error" });
      }
    });

    // -------------------- Start Server --------------------
    app.listen(port, () => {
      console.log(`✅ Server listening on http://localhost:${port}`);
    });
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
}

run();
