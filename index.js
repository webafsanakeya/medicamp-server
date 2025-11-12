require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SK_KEY);

const port = process.env.PORT || 3000;
const app = express();

// ======================= Middleware =======================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://medicamp-app.web.app",
  "https://medicamp-app.firebaseapp.com",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// ======================= MongoDB =======================
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1 },
});

async function run() {
  try {
    await client.connect();
    console.log("✅ Connected to MongoDB");

    const db = client.db("campdb");
    const usersCollection = db.collection("users");
    const campsCollection = db.collection("camps");
    const campsJoinCollection = db.collection("campsJoin");
    const feedbacksCollection = db.collection("feedback");

    // ======================= Auth Middleware =======================
    const verifyJWT = (req, res, next) => {
      const token = req.cookies?.token;
      if (!token) return res.status(401).send({ message: "Unauthorized" });
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ message: "Unauthorized" });
        req.user = decoded;
        next();
      });
    };

    const verifyOrganizer = async (req, res, next) => {
      try {
        const email = req.user.email;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });
        if (user.role !== "organizer")
          return res.status(403).send({ message: "Forbidden: Not organizer" });
        req.user = user;
        next();
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Internal server error" });
      }
    };

    // ======================= Routes =======================
    // Root health check
    app.get("/", (req, res) => res.send("🚑 Medical Camp API is running!"));

    // JWT token
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).send({ message: "Email required" });
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });
      const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "7d" }
      );
      res.send({ token, role: user.role });
    });

    // Users API
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email)
          return res.status(400).send({ message: "Email is required" });

        const existingUser = await usersCollection.findOne({ email: user.email });
        if (existingUser)
          return res.status(409).send({ message: "User already exists" });

        const result = await usersCollection.insertOne(user);
        res.status(201).json({ message: "User added", data: result });
      } catch (err) {
        res.status(500).send({ message: err.message });
      }
    });

    app.get("/users/role/:email", async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.params.email });
        if (!user) return res.status(404).send({ message: "User not found" });
        res.send(user);
      } catch (err) {
        res.status(500).send({ message: err.message });
      }
    });

    // Camps API
    app.get("/camps", async (req, res) => {
      const result = await campsCollection.find().sort({ participants: -1 }).limit(6).toArray();
      res.send(result);
    });

    app.get("/available-camps", async (req, res) => {
      const { search, sort } = req.query;
      const query = search
        ? {
            $or: [
              { campName: { $regex: search, $options: "i" } },
              { location: { $regex: search, $options: "i" } },
              { doctorName: { $regex: search, $options: "i" } },
            ],
          }
        : {};
      const sortMap = {
        "most-registered": { participants: -1 },
        "lowest-fee": { fees: 1 },
        "highest-fee": { fees: -1 },
      };
      const result = await campsCollection.find(query).sort(sortMap[sort] || {}).toArray();
      res.send(result);
    });

    // Camp Registration
    app.post("/camps-join", async (req, res) => {
      const { email, campId } = req.body;
      const session = client.startSession();
      try {
        await session.withTransaction(async () => {
          const existing = await campsJoinCollection.findOne({ email, campId }, { session });
          if (existing) throw new Error("Already registered");

          await campsJoinCollection.insertOne(
            { ...req.body, status: "unpaid", confirmationStatus: "Pending", registeredAt: new Date() },
            { session }
          );
          await campsCollection.updateOne(
            { _id: new ObjectId(campId) },
            { $inc: { participants: 1 } },
            { session }
          );
        });
        res.send({ success: true, message: "Registration successful" });
      } catch (error) {
        res.status(400).send({ success: false, message: error.message });
      } finally {
        await session.endSession();
      }
    });

    // Payment intent
    app.post("/create-payment-intent", async (req, res) => {
      const { amount } = req.body;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: "usd",
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    // Feedback
    app.post("/submit-feedback", async (req, res) => {
      const feedback = { ...req.body, submittedAt: new Date() };
      const result = await feedbacksCollection.insertOne(feedback);
      res.send(result);
    });

    app.get("/feedbacks", async (req, res) => {
      const result = await feedbacksCollection.find().toArray();
      res.send(result);
    });

    // Update profile
    app.patch("/update-profile", verifyJWT, async (req, res) => {
      if (req.user.email !== req.body.email)
        return res.status(403).send({ message: "Forbidden" });

      const { email, name, photoURL, contact } = req.body;
      const updateFields = { updatedAt: new Date() };
      if (name) updateFields.name = name;
      if (photoURL) updateFields.photoURL = photoURL;
      if (contact !== undefined) updateFields.contact = contact;

      const result = await usersCollection.updateOne({ email }, { $set: updateFields });
      if (result.matchedCount === 0) return res.status(404).send({ error: "User not found" });

      res.send({ success: true, message: "Profile updated" });
    });

  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
  }
}

run();

// // ======================= Start Server =======================
// app.listen(port, () => console.log(`🚀 Server running on port ${port}`));

module.exports = app;
