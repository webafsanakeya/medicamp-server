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
  "https://medical-camp-37f24.web.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// ======================= MongoDB =======================
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1 }
});

let db;
let usersCollection, campsCollection, campsJoinCollection, feedbacksCollection;

async function run() {
  await client.connect();
  db = client.db("campdb");
  usersCollection = db.collection("users");
  campsCollection = db.collection("camps");
  campsJoinCollection = db.collection("campsJoin");
  feedbacksCollection = db.collection("feedback");
  console.log("Connected to MongoDB");
}

run().catch(console.error);

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

const verifyRole = (role) => async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user || user.role !== role) {
      return res.status(403).send({ message: `${role} only action!` });
    }
    next();
  } catch (err) {
    res.status(500).send({ message: "Role verification failed" });
  }
};

// ======================= JWT Token Generation =======================
app.post("/jwt", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send({ message: "Email required" });

  const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "365d" });
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict"
  }).send({ success: true });
});

// ======================= User APIs =======================
app.post("/users", async (req, res) => {
  const user = req.body;
  if (!user?.email) return res.status(400).json({ message: "Email required" });
  try {
    const existingUser = await usersCollection.findOne({ email: user.email });
    if (existingUser) return res.status(409).json({ message: "User already exists" });
    const result = await usersCollection.insertOne(user);
    res.status(201).json({ message: "User added", data: result });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});

app.get("/users/role/:email", async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.params.email });
    res.send({ role: user?.role || "user" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Demo Login =======================
app.post("/demo-login", async (req, res) => {
  const { role } = req.body;
  const credentials = {
    admin: { email: "demo.admin@medicamp.com", password: "password123" },
    user: { email: "demo.user@medicamp.com", password: "password123" }
  };
  const userCred = role === "admin" ? credentials.admin : credentials.user;

  try {
    const user = await usersCollection.findOne({ email: userCred.email });
    if (!user) return res.status(404).send({ message: "Demo user not found" });

    const token = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1d" });
    res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
    res.send({ success: true, user });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Profile =======================
app.patch("/update-profile", verifyJWT, async (req, res) => {
  const { email, name, photoURL, contact } = req.body;
  if (req.user.email !== email) return res.status(403).send({ message: "Forbidden" });

  const updateFields = { updatedAt: new Date() };
  if (name) updateFields.name = name;
  if (photoURL) updateFields.photoURL = photoURL;
  if (contact !== undefined) updateFields.contact = contact;

  try {
    const result = await usersCollection.updateOne({ email }, { $set: updateFields });
    if (result.matchedCount === 0) return res.status(404).send({ message: "User not found" });
    res.send({ success: true, message: "Profile updated" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Camp APIs =======================
app.get("/camps", async (req, res) => {
  const { search, sort } = req.query;
  const query = search ? {
    $or: [
      { campName: { $regex: search, $options: "i" } },
      { location: { $regex: search, $options: "i" } },
      { doctorName: { $regex: search, $options: "i" } }
    ]
  } : {};
  const sortMap = {
    "most-registered": { participants: -1 },
    "lowest-fee": { fees: 1 },
    "highest-fee": { fees: -1 }
  };
  try {
    const result = await campsCollection.find(query).sort(sortMap[sort] || { campName: 1 }).toArray();
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// Organizer creates camp
app.post("/camps", verifyJWT, verifyRole("organizer"), async (req, res) => {
  const campData = { ...req.body, participants: 0 };
  try {
    const result = await campsCollection.insertOne(campData);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// Participant joins camp
app.post("/camps-join", verifyJWT, async (req, res) => {
  const { email, campId } = req.body;
  const session = client.startSession();
  try {
    await session.withTransaction(async () => {
      const existing = await campsJoinCollection.findOne({ email, campId }, { session });
      if (existing) throw new Error("Already registered");

      await campsJoinCollection.insertOne({
        ...req.body,
        status: "unpaid",
        confirmationStatus: "Pending",
        registeredAt: new Date()
      }, { session });

      await campsCollection.updateOne({ _id: new ObjectId(campId) }, { $inc: { participants: 1 } }, { session });
    });
    res.send({ success: true, message: "Registered successfully" });
  } catch (err) {
    res.status(400).send({ success: false, message: err.message });
  } finally {
    await session.endSession();
  }
});

// ======================= Payments =======================
app.post("/create-payment-intent", async (req, res) => {
  const { amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: "usd",
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

app.patch("/update-payment-status/:id", async (req, res) => {
  const { status, transactionId } = req.body;
  try {
    const result = await campsJoinCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, transactionId } }
    );
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Feedback =======================
app.post("/submit-feedback", async (req, res) => {
  const feedback = { ...req.body, submittedAt: new Date() };
  try {
    const result = await feedbacksCollection.insertOne(feedback);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

app.get("/participant-feedbacks", verifyJWT, async (req, res) => {
  if (req.user.email !== req.query.email) return res.status(403).send({ message: "Forbidden" });
  try {
    const feedbacks = await feedbacksCollection.find({ participantEmail: req.query.email }).sort({ submittedAt: -1 }).toArray();
    res.send(feedbacks);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Organizer Stats =======================
app.get("/organizer-stats", verifyJWT, verifyRole("organizer"), async (req, res) => {
  try {
    const campStats = await campsCollection.aggregate([
      { $group: { _id: null, totalCamps: { $sum: 1 }, totalParticipants: { $sum: "$participants" } } }
    ]).toArray();

    const revenueStats = await campsJoinCollection.aggregate([
      { $match: { status: "paid" } },
      { $lookup: { from: "camps", localField: "campId", foreignField: "_id", as: "campDetails" } },
      { $unwind: "$campDetails" },
      { $group: { _id: null, totalRevenue: { $sum: "$campDetails.fees" } } }
    ]).toArray();

    res.send({
      totalCamps: campStats[0]?.totalCamps || 0,
      totalParticipants: campStats[0]?.totalParticipants || 0,
      totalRevenue: revenueStats[0]?.totalRevenue || 0
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

// ======================= Test =======================
app.get("/", (req, res) => res.send("Hello from MediCamp Server"));

// ======================= Start server =======================
app.listen(port, () => console.log(`Server running on port ${port}`));
