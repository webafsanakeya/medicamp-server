// index.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");

// Use STRIPE_SECRET_KEY in .env (not STRIPE_SK_KEY)
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

// ======================= Middleware =======================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "https://medicamp-app.web.app",
  "https://medicamp-app.firebaseapp.com",
];

// Safer CORS: allow if origin undefined (Postman) or included in allowedOrigins
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// ======================= MongoDB =======================
// Provide full MONGODB_URI in .env (recommended)
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1 },
});

let db;
let usersCollection;
let campsCollection;
let campsJoinCollection;
let feedbacksCollection;

async function run() {
  try {
    await client.connect();
    // optional ping to verify connection
    await client.db("admin").command({ ping: 1 });
    db = client.db("campdb");
    usersCollection = db.collection("users");
    campsCollection = db.collection("camps");
    campsJoinCollection = db.collection("campsJoin");
    feedbacksCollection = db.collection("feedback");
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    throw err;
  }
}
run().catch((e) => console.error(e));

// ======================= Auth Middleware =======================
// Expect token in Authorization header: "Bearer <token>"
const verifyJWT = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).send({ message: "Unauthorized: No token" });

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) return res.status(401).send({ message: "Unauthorized: Invalid token" });
      // attach decoded payload consistently as req.decoded
      req.decoded = decoded;
      next();
    });
  } catch (err) {
    console.error("verifyJWT error:", err);
    res.status(401).send({ message: "Unauthorized" });
  }
};

// Organizer middleware uses req.decoded.email
const verifyOrganizer = async (req, res, next) => {
  try {
    const email = req.decoded?.email;
    if (!email) {
      return res.status(401).send({ message: "Unauthorized: No email found" });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.role !== "organizer")
      return res.status(403).send({ message: "Forbidden access: Not an organizer" });

    // attach full user object for route usage
    req.user = user;
    next();
  } catch (error) {
    console.error("Error in verifyOrganizer middleware:", error);
    res.status(500).send({ message: "Internal server error" });
  }
};

// ======================= Auth: JWT token route =======================
app.post("/jwt", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).send({ message: "Email is required" });

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    const token = jwt.sign(
      { email: user.email, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    res.send({ token, role: user.role });
  } catch (err) {
    console.error("POST /jwt error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// ======================= USERS =======================
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

// Return full user (you can change to return only role if you want)
app.get("/users/role/:email", async (req, res) => {
  const email = req.params.email;
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }
    res.send({ role: user.role });
  } catch (error) {
    console.error("Error fetching user role:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

// ======================= CAMPS & DASHBOARD =======================
// Organizer Dashboard
app.get("/organizer-camps", verifyJWT, verifyOrganizer, async (req, res) => {
  try {
    const result = await campsCollection.find({ organizerEmail: req.query.email }).toArray();
    res.send(result);
  } catch (err) {
    console.error("GET /organizer-camps error:", err);
    res.status(500).send({ message: "Failed to fetch organizer camps" });
  }
});

// Add camp (organizer only)
app.post("/camps", verifyJWT, verifyOrganizer, async (req, res) => {
  try {
    const campData = { ...req.body, participants: 0 };
    const result = await campsCollection.insertOne(campData);
    res.send(result);
  } catch (err) {
    console.error("POST /camps error:", err);
    res.status(500).send({ message: "Failed to add camp" });
  }
});

// Get top camps (limit 6)
app.get("/camps", async (req, res) => {
  try {
    const result = await campsCollection.find().sort({ participants: -1 }).limit(6).toArray();
    res.send(result);
  } catch (err) {
    console.error("GET /camps error:", err);
    res.status(500).send({ message: "Failed to fetch camps" });
  }
});

// Check join status
app.get("/check-join-status", async (req, res) => {
  try {
    const { email, campId } = req.query;
    const existing = await campsJoinCollection.findOne({ email, campId });
    res.send({ joined: !!existing });
  } catch (err) {
    console.error("GET /check-join-status error:", err);
    res.status(500).send({ joined: false });
  }
});

// Available camps with search & sort
app.get("/available-camps", async (req, res) => {
  try {
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

    const result = await campsCollection.find(query).sort(sortMap[sort] || { campName: 1 }).toArray();
    res.send(result);
  } catch (err) {
    console.error("GET /available-camps error:", err);
    res.status(500).send({ message: "Failed to fetch camps" });
  }
});

app.get("/available-camps/:id", async (req, res) => {
  try {
    const result = await campsCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error("GET /available-camps/:id error:", err);
    res.status(500).send({ message: "Failed to fetch camp" });
  }
});

// ======================= CAMP REGISTRATION =======================
app.post("/camps-join", async (req, res) => {
  const data = req.body;
  const { email, campId } = data;
  const session = client.startSession();

  try {
    await session.withTransaction(async () => {
      const existing = await campsJoinCollection.findOne({ email, campId }, { session });
      if (existing) throw new Error("You have already registered for this camp");

      const registrationData = {
        ...data,
        status: "unpaid",
        confirmationStatus: "Pending",
        registeredAt: new Date(),
      };

      const result = await campsJoinCollection.insertOne(registrationData, { session });

      const updateResult = await campsCollection.updateOne(
        { _id: new ObjectId(campId) },
        { $inc: { participants: 1 } },
        { session }
      );

      if (updateResult.matchedCount === 0) throw new Error("Camp not found for participant count update");

      res.send({ success: true, insertedId: result.insertedId, message: "Registration successful" });
    });
  } catch (error) {
    console.error("POST /camps-join error:", error);
    if (error.message.includes("already registered")) {
      return res.status(400).send({ success: false, message: "You have already registered for this camp" });
    }
    res.status(500).send({ success: false, message: error.message || "Registration failed" });
  } finally {
    await session.endSession();
  }
});

// Registered camps (merge campName)
app.get("/registered-camps", async (req, res) => {
  try {
    const registered = await campsJoinCollection.find({ organizerEmail: req.query.email }).toArray();

    const campIds = registered.map((r) => r.campId).filter(Boolean);
    const camps = campIds.length
      ? await campsCollection.find({ _id: { $in: campIds.map((id) => new ObjectId(id)) } }).toArray()
      : [];

    const result = registered.map((record) => {
      const camp = camps.find((c) => c._id.toString() === record.campId);
      return { ...record, campName: camp?.campName || "Unknown Camp" };
    });

    res.send(result);
  } catch (err) {
    console.error("GET /registered-camps error:", err);
    res.status(500).send({ message: "Failed to fetch registered camps" });
  }
});

// Delete camp
app.delete("/delete-camp/:id", verifyJWT, verifyOrganizer, async (req, res) => {
  try {
    const result = await campsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error("DELETE /delete-camp/:id error:", err);
    res.status(500).send({ message: "Failed to delete camp" });
  }
});

// Update camp
app.patch("/update-camp/:id", verifyJWT, verifyOrganizer, async (req, res) => {
  try {
    const { _id, ...updateData } = req.body;
    const result = await campsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });
    res.send(result);
  } catch (err) {
    console.error("PATCH /update-camp/:id error:", err);
    res.status(500).send({ message: "Failed to update camp" });
  }
});

// Update confirmation status
app.patch("/update-confirmation/:id", async (req, res) => {
  try {
    const { confirmationStatus } = req.body;
    if (!confirmationStatus) return res.status(400).send({ error: "confirmationStatus is required" });

    const result = await campsJoinCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { confirmationStatus } }
    );

    if (result.matchedCount === 0) return res.status(404).send({ error: "Registration not found" });

    res.send(result);
  } catch (err) {
    console.error("PATCH /update-confirmation/:id error:", err);
    res.status(500).send({ error: "Failed to update confirmation status" });
  }
});

// Cancel registration (only if unpaid)
app.delete("/cancel-registration/:id", async (req, res) => {
  const session = client.startSession();
  try {
    const registration = await campsJoinCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!registration) return res.status(404).send({ message: "Registration not found" });
    if (registration.status === "paid") return res.status(400).send({ message: "Cannot cancel paid registration" });

    await session.withTransaction(async () => {
      await campsJoinCollection.deleteOne({ _id: new ObjectId(req.params.id) }, { session });
      await campsCollection.updateOne({ _id: new ObjectId(registration.campId) }, { $inc: { participants: -1 } }, { session });
    });

    res.send({ success: true });
  } catch (err) {
    console.error("DELETE /cancel-registration/:id error:", err);
    res.status(500).send({ message: "Failed to cancel registration" });
  } finally {
    await session.endSession();
  }
});

// ======================= PARTICIPANT =======================
app.get("/participant-profile", async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.query.email });
    const registration = await campsJoinCollection.findOne({ email: req.query.email });
    res.send({
      name: user?.name,
      photoURL: user?.photoURL,
      contact: registration?.emergencyContact || "",
    });
  } catch (err) {
    console.error("GET /participant-profile error:", err);
    res.status(500).send({ message: "Failed to fetch participant profile" });
  }
});

app.get("/participant-analytics", async (req, res) => {
  try {
    const userEmail = req.query.email;
    const registrations = await campsJoinCollection.find({ email: userEmail }).toArray();

    const enrichedData = await Promise.all(
      registrations.map(async (reg) => {
        const camp = await campsCollection.findOne({ _id: new ObjectId(reg.campId) });
        return {
          ...reg,
          campName: camp?.campName || "N/A",
          fees: camp?.fees || 0,
          location: camp?.location || "N/A",
          doctorName: camp?.doctorName || "N/A",
        };
      })
    );

    res.send(enrichedData);
  } catch (err) {
    console.error("GET /participant-analytics error:", err);
    res.status(500).send({ message: "Failed to fetch participant analytics" });
  }
});



// Update profile (authenticated)
app.patch("/update-profile", verifyJWT, async (req, res) => {
  try {
    if (req.decoded.email !== req.body.email) {
      return res.status(403).send({ message: "Forbidden: You can only update your own profile." });
    }

    const { email, name, photoURL, contact } = req.body;
    const updateFields = { updatedAt: new Date() };
    if (name) updateFields.name = name;
    if (photoURL) updateFields.photoURL = photoURL;
    if (contact !== undefined) updateFields.contact = contact;

    const result = await usersCollection.updateOne({ email }, { $set: updateFields }, { upsert: false });
    if (result.matchedCount === 0) return res.status(404).send({ error: "User not found" });

    res.send({ success: true, message: "Profile updated successfully in the database" });
  } catch (err) {
    console.error("PATCH /update-profile error:", err);
    res.status(500).send({ error: "Failed to update profile in database" });
  }
});

// ======================= PAYMENTS =======================
app.get("/user-registered-camps", async (req, res) => {
  try {
    const userEmail = req.query.email;
    const registrations = await campsJoinCollection.find({ email: userEmail }).toArray();

    const enrichedData = await Promise.all(
      registrations.map(async (reg) => {
        const camp = await campsCollection.findOne({ _id: new ObjectId(reg.campId) });
        return {
          _id: reg._id,
          campId: reg.campId,
          campName: camp?.campName || "Unknown Camp",
          fees: camp?.fees || 0,
          location: camp?.location || "Unknown Location",
          doctorName: camp?.doctorName || "Unknown Doctor",
          status: reg.status || "unpaid",
          confirmationStatus: reg.confirmationStatus || "Pending",
        };
      })
    );

    res.send(enrichedData);
  } catch (err) {
    console.error("GET /user-registered-camps error:", err);
    res.status(500).send({ message: "Failed to fetch user registered camps" });
  }
});

app.post("/create-payment-intent", async (req, res) => {
  try {
    const { amount } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: "usd",
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error("POST /create-payment-intent error:", err);
    res.status(500).send({ message: "Failed to create payment intent" });
  }
});

app.patch("/update-payment-status/:id", async (req, res) => {
  try {
    const { status, transactionId } = req.body;
    const result = await campsJoinCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, transactionId } }
    );
    res.send(result);
  } catch (err) {
    console.error("PATCH /update-payment-status/:id error:", err);
    res.status(500).send({ message: "Failed to update payment status" });
  }
});

app.get("/payment-history", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).send({ error: "Email is required" });

    const paymentHistory = await campsJoinCollection
      .find({ email, status: { $regex: /^paid$/i } })
      .toArray();

    if (!paymentHistory.length) return res.status(404).send({ error: "No payment history found" });
    res.send(paymentHistory);
  } catch (err) {
    console.error("GET /payment-history error:", err);
    res.status(500).send({ error: "Failed to fetch payment history" });
  }
});

// ======================= FEEDBACK =======================
app.get("/participant-feedbacks", verifyJWT, async (req, res) => {
  try {
    if (req.decoded.email !== req.query.email)
      return res.status(403).send({ message: "Forbidden: You can only access your own feedback." });

    const participantEmail = req.query.email;
    const result = await feedbacksCollection.find({ participantEmail }).sort({ submittedAt: -1 }).toArray();
    res.send(result);
  } catch (err) {
    console.error("GET /participant-feedbacks error:", err);
    res.status(500).send({ message: "Failed to fetch feedback" });
  }
});

app.post("/submit-feedback", async (req, res) => {
  try {
    const feedback = { ...req.body, submittedAt: new Date() };
    const result = await feedbacksCollection.insertOne(feedback);
    res.send(result);
  } catch (err) {
    console.error("POST /submit-feedback error:", err);
    res.status(500).send({ message: "Failed to submit feedback" });
  }
});

app.get("/feedbacks", async (req, res) => {
  try {
    const result = await feedbacksCollection.find().toArray();
    res.send(result);
  } catch (err) {
    console.error("GET /feedbacks error:", err);
    res.status(500).send({ message: "Failed to fetch feedbacks" });
  }
});

// ======================= ORGANIZER STATS =======================
app.get("/organizer-stats", verifyJWT, verifyOrganizer, async (req, res) => {
  try {
    const campStats = await campsCollection
      .aggregate([
        {
          $group: {
            _id: null,
            totalCamps: { $sum: 1 },
            totalParticipants: { $sum: "$participants" },
            upcomingCamps: {
              $sum: {
                $cond: [{ $gt: ["$dateTime", new Date().toISOString()] }, 1, 0],
              },
            },
          },
        },
      ])
      .toArray();

    const revenueStats = await campsJoinCollection
      .aggregate([
        { $match: { status: "paid" } },
        {
          $lookup: {
            from: "camps",
            let: { camp_id: { $toObjectId: "$campId" } },
            pipeline: [{ $match: { $expr: { $eq: ["$_id", "$$camp_id"] } } }],
            as: "campDetails",
          },
        },
        { $unwind: "$campDetails" },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: "$campDetails.fees" },
          },
        },
      ])
      .toArray();

    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const registrationsOverTime = await campsJoinCollection
      .aggregate([
        { $match: { registeredAt: { $gte: sixMonthsAgo } } },
        {
          $group: {
            _id: { year: { $year: "$registeredAt" }, month: { $month: "$registeredAt" } },
            count: { $sum: 1 },
          },
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } },
        {
          $project: {
            _id: 0,
            month: {
              $let: {
                vars: {
                  monthsInYear: [
                    "",
                    "Jan",
                    "Feb",
                    "Mar",
                    "Apr",
                    "May",
                    "Jun",
                    "Jul",
                    "Aug",
                    "Sep",
                    "Oct",
                    "Nov",
                    "Dec",
                  ],
                },
                in: { $arrayElemAt: ["$$monthsInYear", "$_id.month"] },
              },
            },
            count: 1,
          },
        },
      ])
      .toArray();

    const campsByLocation = await campsCollection
      .aggregate([
        { $group: { _id: "$location", count: { $sum: 1 } } },
        { $project: { _id: 0, location: "$_id", count: 1 } },
      ])
      .toArray();

    const recentRegistrations = await campsJoinCollection.find().sort({ registeredAt: -1 }).limit(5).toArray();

    const stats = {
      totalCamps: campStats[0]?.totalCamps || 0,
      totalParticipants: campStats[0]?.totalParticipants || 0,
      upcomingCampsCount: campStats[0]?.upcomingCamps || 0,
      totalRevenue: revenueStats[0]?.totalRevenue || 0,
      registrationsOverTime,
      campsByLocation,
      recentRegistrations,
    };

    res.send(stats);
  } catch (err) {
    console.error("GET /organizer-stats error:", err);
    res.status(500).send({ message: "Failed to fetch stats" });
  }
});

// ======================= HEALTH =======================
app.get("/", (req, res) => {
  res.send("🚑 Medical Camp API is running!");
});

// Only listen when running locally (not when imported by serverless platforms)
if (require.main === module) {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
}

module.exports = app;
