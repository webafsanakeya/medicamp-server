// server.js
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.3g5ecwq.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function run() {
  try {
    await client.connect();
    console.log("✅ MongoDB connected");

    const db = client.db("campDB");
    const campsCollection = db.collection("camps");
    const campsJoinCollection = db.collection("campsJoin");
    const usersCollection = db.collection("users");
    const feedbacksCollection = db.collection("feedback");
    const SECRET_KEY = process.env.JWT_SECRET;

    // --- Middleware ---
    const verifyJWT = (req, res, next) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).send({ message: "Unauthorized: No token provided" });

      jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).send({ message: "Forbidden: Invalid token" });
        req.decoded = decoded;
        next();
      });
    };

    const verifyOrganizer = async (req, res, next) => {
      try {
        const email = req.decoded.email;
        if (!email) return res.status(401).send({ message: "Unauthorized: No email found" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });
        if (user.role !== "organizer") return res.status(403).send({ message: "Forbidden: Not an organizer" });

        req.user = user;
        next();
      } catch (error) {
        console.error("verifyOrganizer error:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    };

    // --- Routes ---

    app.get("/", (req, res) => res.send("🚑 Medical Camp API is running!"));

    // JWT Token API
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "7d" });
      res.send({ token });
    });

    // --- Users ---
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
        res.send({ role: user?.role || "user" });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.patch("/update-profile", verifyJWT, async (req, res) => {
      if (req.decoded.email !== req.body.email) {
        return res.status(403).send({ message: "Forbidden: You can only update your own profile." });
      }

      const { email, name, photoURL, contact } = req.body;
      const updateFields = { updatedAt: new Date() };
      if (name) updateFields.name = name;
      if (photoURL) updateFields.photoURL = photoURL;
      if (contact !== undefined) updateFields.contact = contact;

      try {
        const result = await usersCollection.updateOne({ email }, { $set: updateFields });
        if (result.matchedCount === 0) return res.status(404).send({ error: "User not found" });
        res.send({ success: true, message: "Profile updated successfully" });
      } catch (error) {
        console.error("Update profile error:", error);
        res.status(500).send({ error: "Failed to update profile" });
      }
    });

    // --- Camps ---
    app.get("/camps", async (req, res) => {
      const result = await campsCollection.find().sort({ participants: -1 }).limit(6).toArray();
      res.send(result);
    });

    app.get("/available-camps", async (req, res) => {
      const { search, sort } = req.query;

      const query = search
        ? { $or: [{ campName: { $regex: search, $options: "i" } }, { location: { $regex: search, $options: "i" } }, { doctorName: { $regex: search, $options: "i" } }] }
        : {};

      const sortMap = { "most-registered": { participants: -1 }, "lowest-fee": { fees: 1 }, "highest-fee": { fees: -1 } };
      const result = await campsCollection.find(query).sort(sortMap[sort] || { campName: 1 }).toArray();
      res.send(result);
    });

    app.get("/available-camps/:id", async (req, res) => {
      const result = await campsCollection.findOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.post("/camps", verifyJWT, verifyOrganizer, async (req, res) => {
      const campData = { ...req.body, participants: 0 };
      const result = await campsCollection.insertOne(campData);
      res.send(result);
    });

    app.patch("/update-camp/:id", verifyJWT, verifyOrganizer, async (req, res) => {
      const { _id, ...updateData } = req.body;
      const result = await campsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });
      res.send(result);
    });

    app.delete("/delete-camp/:id", verifyJWT, verifyOrganizer, async (req, res) => {
      const result = await campsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.get("/organizer-camps", verifyJWT, verifyOrganizer, async (req, res) => {
      const result = await campsCollection.find({ organizerEmail: req.query.email }).toArray();
      res.send(result);
    });

    // --- Camp Registration ---
    app.post("/camps-join", async (req, res) => {
      const { email, campId } = req.body;
      const session = client.startSession();

      try {
        await session.withTransaction(async () => {
          const existing = await campsJoinCollection.findOne({ email, campId }, { session });
          if (existing) throw new Error("You have already registered for this camp");

          const registrationData = { ...req.body, status: "unpaid", confirmationStatus: "Pending", registeredAt: new Date() };
          const result = await campsJoinCollection.insertOne(registrationData, { session });

          await campsCollection.updateOne({ _id: new ObjectId(campId) }, { $inc: { participants: 1 } }, { session });

          res.send({ success: true, insertedId: result.insertedId, message: "Registration successful" });
        });
      } catch (error) {
        if (error.message.includes("already registered")) res.status(400).send({ success: false, message: error.message });
        else res.status(500).send({ success: false, message: error.message || "Registration failed" });
      } finally {
        await session.endSession();
      }
    });

    app.get("/check-join-status", async (req, res) => {
      const { email, campId } = req.query;
      const existing = await campsJoinCollection.findOne({ email, campId });
      res.send({ joined: !!existing });
    });

    app.get("/registered-camps", async (req, res) => {
      const registered = await campsJoinCollection.find({ organizerEmail: req.query.email }).toArray();
      const campIds = registered.map(r => r.campId);
      const camps = await campsCollection.find({ _id: { $in: campIds.map(id => new ObjectId(id)) } }).toArray();

      const result = registered.map(r => {
        const camp = camps.find(c => c._id.toString() === r.campId);
        return { ...r, campName: camp?.campName || "Unknown Camp" };
      });

      res.send(result);
    });

    app.patch("/update-confirmation/:id", async (req, res) => {
      const { confirmationStatus } = req.body;
      if (!confirmationStatus) return res.status(400).send({ error: "confirmationStatus is required" });

      const result = await campsJoinCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { confirmationStatus } });
      if (result.matchedCount === 0) return res.status(404).send({ error: "Registration not found" });
      res.send(result);
    });

    app.delete("/cancel-registration/:id", async (req, res) => {
      const registration = await campsJoinCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!registration) return res.status(404).send({ message: "Registration not found" });
      if (registration.status === "paid") return res.status(400).send({ message: "Cannot cancel paid registration" });

      const session = client.startSession();
      await session.withTransaction(async () => {
        await campsJoinCollection.deleteOne({ _id: new ObjectId(req.params.id) }, { session });
        await campsCollection.updateOne({ _id: new ObjectId(registration.campId) }, { $inc: { participants: -1 } }, { session });
      });
      await session.endSession();
      res.send({ success: true });
    });

    // --- Participant APIs ---
    app.get("/participant-profile", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.query.email });
      const registration = await campsJoinCollection.findOne({ email: req.query.email });
      res.send({ name: user?.name, photoURL: user?.photoURL, contact: registration?.emergencyContact || "" });
    });

    app.get("/participant-analytics", async (req, res) => {
      const registrations = await campsJoinCollection.find({ email: req.query.email }).toArray();
      const enrichedData = await Promise.all(registrations.map(async r => {
        const camp = await campsCollection.findOne({ _id: new ObjectId(r.campId) });
        return { ...r, campName: camp?.campName || "N/A", fees: camp?.fees || 0, location: camp?.location || "N/A", doctorName: camp?.doctorName || "N/A" };
      }));
      res.send(enrichedData);
    });

    app.get("/user-registered-camps", async (req, res) => {
      const registrations = await campsJoinCollection.find({ email: req.query.email }).toArray();
      const enrichedData = await Promise.all(registrations.map(async r => {
        const camp = await campsCollection.findOne({ _id: new ObjectId(r.campId) });
        return { _id: r._id, campId: r.campId, campName: camp?.campName || "Unknown Camp", fees: camp?.fees || 0, location: camp?.location || "Unknown Location", doctorName: camp?.doctorName || "Unknown Doctor", status: r.status || "unpaid", confirmationStatus: r.confirmationStatus || "Pending" };
      }));
      res.send(enrichedData);
    });

    // --- Payments ---
    app.post("/create-payment-intent", async (req, res) => {
      const { amount } = req.body;
      const paymentIntent = await stripe.paymentIntents.create({ amount: Math.round(amount * 100), currency: "usd" });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.patch("/update-payment-status/:id", async (req, res) => {
      const { status, transactionId } = req.body;
      const result = await campsJoinCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { status, transactionId } });
      res.send(result);
    });

    app.get("/payment-history", async (req, res) => {
      const { email } = req.query;
      if (!email) return res.status(400).send({ error: "Email is required" });
      const paymentHistory = await campsJoinCollection.find({ email, status: { $regex: /^paid$/i } }).toArray();
      if (!paymentHistory.length) return res.status(404).send({ error: "No payment history found" });
      res.send(paymentHistory);
    });

    // --- Feedback ---
    app.post("/submit-feedback", async (req, res) => {
      const feedback = { ...req.body, submittedAt: new Date() };
      const result = await feedbacksCollection.insertOne(feedback);
      res.send(result);
    });

    app.get("/participant-feedbacks", verifyJWT, async (req, res) => {
      if (req.decoded.email !== req.query.email) return res.status(403).send({ message: "Forbidden" });
      const result = await feedbacksCollection.find({ participantEmail: req.query.email }).sort({ submittedAt: -1 }).toArray();
      res.send(result);
    });

    app.get("/feedbacks", async (req, res) => {
      const result = await feedbacksCollection.find().toArray();
      res.send(result);
    });

    // --- Organizer Stats ---
    app.get("/organizer-stats", verifyJWT, verifyOrganizer, async (req, res) => {
      try {
        const campStats = await campsCollection.aggregate([
          { $group: { _id: null, totalCamps: { $sum: 1 }, totalParticipants: { $sum: "$participants" }, upcomingCamps: { $sum: { $cond: [{ $gt: ["$dateTime", new Date().toISOString()] }, 1, 0] } } } }
        ]).toArray();

        const revenueStats = await campsJoinCollection.aggregate([
          { $match: { status: "paid" } },
          { $lookup: { from: "camps", let: { camp_id: { $toObjectId: "$campId" } }, pipeline: [{ $match: { $expr: { $eq: ["$_id", "$$camp_id"] } } }], as: "campDetails" } },
          { $unwind: "$campDetails" },
          { $group: { _id: null, totalRevenue: { $sum: "$campDetails.fees" } } }
        ]).toArray();

        const sixMonthsAgo = new Date(); sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
        const registrationsOverTime = await campsJoinCollection.aggregate([
          { $match: { registeredAt: { $gte: sixMonthsAgo } } },
          { $group: { _id: { year: { $year: "$registeredAt" }, month: { $month: "$registeredAt" } }, count: { $sum: 1 } } },
          { $sort: { "_id.year": 1, "_id.month": 1 } },
          { $project: { _id: 0, month: { $let: { vars: { monthsInYear: ["", "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"] }, in: { $arrayElemAt: ["$$monthsInYear", "$_id.month"] } } }, count: 1 } }
        ]).toArray();

        const campsByLocation = await campsCollection.aggregate([
          { $group: { _id: "$location", count: { $sum: 1 } } },
          { $project: { _id: 0, location: "$_id", count: 1 } }
        ]).toArray();

        const recentRegistrations = await campsJoinCollection.find().sort({ registeredAt: -1 }).limit(5).toArray();

        res.send({
          totalCamps: campStats[0]?.totalCamps || 0,
          totalParticipants: campStats[0]?.totalParticipants || 0,
          upcomingCampsCount: campStats[0]?.upcomingCamps || 0,
          totalRevenue: revenueStats[0]?.totalRevenue || 0,
          registrationsOverTime,
          campsByLocation,
          recentRegistrations
        });
      } catch (error) {
        console.error("Organizer stats error:", error);
        res.status(500).send({ message: "Failed to fetch stats" });
      }
    });

  } finally {
    // client.close(); // keep connection open for Render
  }
}

run().catch(console.dir);

// Start server
app.listen(port, () => console.log(`🚑 Medicamp server running on port ${port}`));
