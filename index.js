const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SK_KEY);

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function run() {
  try {
    await client.connect();
    console.log("MongoDB connected successfully");

    const db = client.db("campDB");
    const usersCollection = db.collection("users");
    const campsCollection = db.collection("camps");
    const campsJoinCollection = db.collection("campsJoin");
    const feedbacksCollection = db.collection("feedback");

    const SECRET_KEY = process.env.JWT_SECRET;

    // JWT Verify Middleware
    const verifyJWT = (req, res, next) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).send({ message: "Unauthorized" });

      jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).send({ message: "Forbidden" });
        req.decoded = decoded;
        next();
      });
    };

    // Organizer Verify Middleware
    const verifyOrganizer = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email });
      if (!user || user.role !== "organizer")
        return res.status(403).send({ message: "Forbidden: Not an organizer" });
      req.user = user;
      next();
    };

    // JWT Token API
    app.post("/jwt", (req, res) => {
      const { email } = req.body;
      const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "7d" });
      res.send({ token });
    });

    // Create user
    app.post("/users", async (req, res) => {
      const user = req.body;
      if (!user?.email) return res.status(400).send({ message: "Email required" });
      const existingUser = await usersCollection.findOne({ email: user.email });
      if (existingUser) return res.status(409).send({ message: "User exists" });
      const result = await usersCollection.insertOne(user);
      res.status(201).send(result);
    });

    // Get user role
    app.get("/users/role/:email", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.params.email });
      res.send({ role: user?.role || "participant" });
    });

    // ================= Organizer Routes =================
    app.get("/organizer-camps", verifyJWT, verifyOrganizer, async (req, res) => {
      const camps = await campsCollection.find({ organizerEmail: req.query.email }).toArray();
      res.send(camps);
    });

    app.post("/camps", verifyJWT, verifyOrganizer, async (req, res) => {
      const campData = { ...req.body, participants: 0 };
      const result = await campsCollection.insertOne(campData);
      res.send(result);
    });

    app.delete("/delete-camp/:id", verifyJWT, verifyOrganizer, async (req, res) => {
      const result = await campsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    // ================= Participant Routes =================
    app.get("/participant-analytics", verifyJWT, async (req, res) => {
      const userEmail = req.decoded.email;
      const registrations = await campsJoinCollection.find({ email: userEmail }).toArray();
      const enrichedData = await Promise.all(
        registrations.map(async (reg) => {
          const camp = await campsCollection.findOne({ _id: new ObjectId(reg.campId) });
          return { ...reg, campName: camp?.campName || "N/A" };
        })
      );
      res.send(enrichedData);
    });

    // Camp registration
    app.post("/camps-join", verifyJWT, async (req, res) => {
      const { email, campId } = req.body;
      const existing = await campsJoinCollection.findOne({ email, campId });
      if (existing) return res.status(400).send({ message: "Already registered" });

      const result = await campsJoinCollection.insertOne({ ...req.body, status: "unpaid", confirmationStatus: "Pending", registeredAt: new Date() });
      await campsCollection.updateOne({ _id: new ObjectId(campId) }, { $inc: { participants: 1 } });
      res.send(result);
    });

    // Default route
    app.get("/", (req, res) => res.send("🚑 Medical Camp API is running!"));

  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

run().catch(console.error);

// Export for serverless deployment
module.exports = app;
