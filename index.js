const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion } = require("mongodb");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// -------------------- Firebase Admin --------------------
const serviceAccount = require("./firebase-admin-key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// -------------------- MongoDB --------------------
if (!process.env.DB_URI) {
  console.error("❌ DB_URI missing in .env");
  process.exit(1);
}

const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// -------------------- Routes --------------------
app.get("/", (req, res) => {
  res.send("✅ Server running");
});

// JWT route (client sends Firebase ID token, server returns server JWT)
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

    // Uses DB name from your URI (lifedropDB)
    const db = client.db();
    const usersCollection = db.collection("users");

    // Create/Update user (Register step)
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;

        if (!user?.email) {
          return res.status(400).send({ message: "Email is required" });
        }

        const filter = { email: user.email };
        const updateDoc = {
          $set: {
            ...user,
            updatedAt: new Date(),
          },
          $setOnInsert: {
            createdAt: new Date(),
          },
        };

        const result = await usersCollection.updateOne(filter, updateDoc, {
          upsert: true,
        });

        // If new insert happens, upsertedId exists; otherwise it's an update
        res.send({
          acknowledged: result.acknowledged,
          upsertedId: result.upsertedId || null,
          matchedCount: result.matchedCount,
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.log("POST /users error:", err.message);
        res.status(500).send({ message: "Failed to save user" });
      }
    });

    app.listen(port, () => {
      console.log(`✅ Server listening on http://localhost:${port}`);
    });
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
}

run();
