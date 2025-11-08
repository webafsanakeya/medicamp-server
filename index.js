require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SK_KEY);

const app = express();
app.use(express.json());

// ===== CORS =====
const allowedOrigins = [
  "http://localhost:5173",
  "https://medical-camp-37f24.web.app"
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("CORS not allowed"));
    },
    credentials: true,
  })
);

// ===== MongoDB =====
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});
const dbName = "campDB";

async function run() {
  try {
    await client.connect();
    console.log("MongoDB connected successfully!");

    const db = client.db(dbName);
    const campsCollection = db.collection("camps");
    const campsJoinCollection = db.collection("campsJoin");
    const usersCollection = db.collection("users");
    const feedbacksCollection = db.collection("feedback");

    const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET;

    // ===== JWT Middleware =====
    const verifyJWT = (req, res, next) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).send({ message: "Unauthorized: No token provided" });

      jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).send({ message: "Forbidden: Invalid token" });
        req.decoded = decoded;
        next();
      });
    };

    // ===== Organizer Middleware =====
    const verifyOrganizer = async (req, res, next) => {
      try {
        const email = req.decoded.email;
        if (!email) return res.status(401).send({ message: "Unauthorized: No email found" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });

        if (user.role !== "organizer")
          return res.status(403).send({ message: "Forbidden: Not an organizer" });

        req.user = user;
        next();
      } catch (err) {
        console.error("verifyOrganizer error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    };

    // ===== JWT Token API =====
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      const token = jwt.sign({ email }, ACCESS_TOKEN_SECRET, { expiresIn: "7d" });
      res.send({ token });
    });

    // ===== Users API =====
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email) return res.status(400).json({ message: "Email is required" });

        const existingUser = await usersCollection.findOne({ email: user.email });
        if (existingUser) return res.status(409).json({ message: "User already exists" });

        const result = await usersCollection.insertOne(user);
        res.status(201).json({ message: "User added successfully", data: result });
      } catch (err) {
        console.error("Add User Error:", err);
        res.status(500).json({ message: "Internal Server Error", error: err.message });
      }
    });

    app.get("/users/role/:email", async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.params.email });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
    });

    // ===== Camps API (Example: get top camps) =====
    app.get("/camps", async (req, res) => {
      try {
        const result = await campsCollection.find().sort({ participants: -1 }).limit(6).toArray();
        res.send(result);
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
    });

    // ===== Health check =====
    app.get("/", (req, res) => res.send("🚑 Medical Camp API is running!"));

  } catch (err) {
    console.error("Server initialization error:", err);
  }
}
run().catch(console.dir);

// ===== Export app for Vercel =====
module.exports = app;
