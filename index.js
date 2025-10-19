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

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// ======================= Auth =======================
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).send({ message: "Unauthorized access" });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized access" });
    req.user = decoded;
    next();
  });
};

const verifyRole = (role) => async (req, res, next) => {
  const email = req.user?.email;
  const user = await usersCollection.findOne({ email });
  if (!user || user.role !== role)
    return res.status(403).send({ message: `${role} only action!` });
  next();
};

// ======================= MongoDB =======================
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let campsCollection, registeredCollection, usersCollection, feedbackCollection;

async function run() {
  const db = client.db("campdb");
  campsCollection = db.collection("camps");
  registeredCollection = db.collection("registered");
  usersCollection = db.collection("users");
  feedbackCollection = db.collection("feedback");

  try {
    // ======================= JWT Routes =======================
    app.post("/jwt", async (req, res) => {
      const email = req.body;
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "365d" });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    app.get("/logout", (req, res) => {
      res
        .clearCookie("token", {
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    // ======================= Camp Routes =======================
    app.post("/add-camp", verifyToken, verifyRole("organizer"), async (req, res) => {
      const camp = req.body;
      const result = await campsCollection.insertOne(camp);
      res.send(result);
    });

    app.get("/camps", async (req, res) => {
      const result = await campsCollection.find().toArray();
      res.send(result);
    });

    app.get("/camps/:id", async (req, res) => {
      const id = req.params.id;
      const camp = await campsCollection.findOne({ _id: new ObjectId(id) });
      res.send(camp);
    });

    app.get("/camps/popular", async (req, res) => {
      const popularCamps = await campsCollection.find().sort({ participantCount: -1 }).limit(6).toArray();
      res.send(popularCamps);
    });

    app.get("/camps-by-organizer", verifyToken, verifyRole("organizer"), async (req, res) => {
      const email = req.query.email;
      if (!email) return res.status(400).send({ message: "Email is required" });
      const camps = await campsCollection.find({ "organizer.email": email }).toArray();
      res.send(camps);
    });

    app.patch("/camp/:id", verifyToken, verifyRole("organizer"), async (req, res) => {
      const id = req.params.id;
      const result = await campsCollection.updateOne({ _id: new ObjectId(id) }, { $set: req.body });
      res.send(result);
    });

    app.delete("/camp/:id", verifyToken, verifyRole("organizer"), async (req, res) => {
      const id = req.params.id;
      const result = await campsCollection.deleteOne({ _id: new ObjectId(id) });
      if (result.deletedCount === 1) res.send({ success: true });
      else res.status(404).send({ message: "Camp not found" });
    });

    // ======================= Stripe Payment =======================
    app.post("/create-payment-intent", async (req, res) => {
      const { campId, participantCount } = req.body;
      const camp = await campsCollection.findOne({ _id: new ObjectId(campId) });
      if (!camp) return res.status(404).send({ message: "Camp not found" });

      const amount = participantCount * camp.fees * 100;
      const { client_secret } = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        automatic_payment_methods: { enabled: true },
      });

      res.send({ clientSecret: client_secret });
    });

    // ======================= Registration / Bookings =======================
    app.post("/registered", async (req, res) => {
      const data = { ...req.body, createdAt: new Date() };
      const result = await registeredCollection.insertOne(data);
      res.send(result);
    });

    app.patch("/registered/:id/pay", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { paymentStatus: "paid" } }
      );
      if (result.modifiedCount > 0) res.send({ success: true });
      else res.status(404).send({ message: "Registration not found" });
    });

    app.patch("/registered/:id/confirm", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { confirmationStatus: "confirmed" } }
      );
      if (result.modifiedCount > 0) res.send({ success: true });
      else res.status(404).send({ message: "Registration not found" });
    });

    app.delete("/registered/:id", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // ======================= My Bookings =======================
    app.get("/registers/participant/:email", verifyToken, async (req, res) => {
  const email = req.params.email;

  const bookings = await registeredCollection
    .aggregate([
      { $match: { "participant.email": email } },
      {
        $lookup: {
          from: "camps",
          localField: "campId",
          foreignField: "_id",
          as: "campDetails",
        },
      },
      { $unwind: "$campDetails" }, // flatten the array
      {
        $project: {
          _id: 1,
          paymentStatus: 1,
          date: "$campDetails.date",
          location: "$campDetails.location",
          campName: "$campDetails.name",
        },
      },
    ])
    .toArray();

  res.send(bookings);
});

    // ======================= Users =======================
    app.post("/user", async (req, res) => {
      const userData = { ...req.body, role: "participant", created_at: new Date(), last_loggedIn: new Date() };
      const query = { email: userData.email };
      const existing = await usersCollection.findOne(query);

      if (existing) {
        const result = await usersCollection.updateOne(query, { $set: { last_loggedIn: new Date() } });
        return res.send(result);
      }

      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });

    app.get("/user/role/:email", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.params.email });
      if (!user) return res.status(404).send({ message: "User not found." });
      res.send({ role: user.role });
    });

    app.patch("/users/:email", async (req, res) => {
      const result = await usersCollection.updateOne({ email: req.params.email }, { $set: req.body });
      res.send(result);
    });

    app.patch("/become/organizer-request/:email", verifyToken, async (req, res) => {
      const result = await usersCollection.updateOne(
        { email: req.params.email },
        { $set: { status: "requested" } }
      );
      res.send(result);
    });

    app.patch("/user/role/update/:email", verifyToken, verifyRole("admin"), async (req, res) => {
      const { role } = req.body;
      const result = await usersCollection.updateOne({ email: req.params.email }, { $set: { role, status: "verified" } });
      res.send(result);
    });

    app.get("/all-users", verifyToken, verifyRole("admin"), async (req, res) => {
      const users = await usersCollection.find({ email: { $ne: req.user.email } }).toArray();
      res.send(users);
    });

    // ======================= Feedback =======================
    app.post("/feedback", verifyToken, async (req, res) => {
      const { campId, participantEmail, rating, comment } = req.body;

      const registered = await registeredCollection.findOne({
        "participant.email": participantEmail,
        campId,
        paymentStatus: "paid",
      });
      if (!registered) return res.status(403).send({ message: "Paid participants only" });

      const feedback = { campId, participantEmail, rating, comment, createdAt: new Date() };
      const result = await feedbackCollection.insertOne(feedback);
      res.send(result);
    });

    app.get("/feedback/camp/:campId", async (req, res) => {
      const feedbacks = await feedbackCollection.find({ campId: req.params.campId }).sort({ createdAt: -1 }).toArray();
      res.send(feedbacks);
    });

    app.get("/feedback/participant/:email", verifyToken, async (req, res) => {
      const feedbacks = await feedbackCollection.find({ participantEmail: req.params.email }).toArray();
      res.send(feedbacks);
    });

    app.patch("/feedback/:id", verifyToken, async (req, res) => {
      const { rating, comment } = req.body;
      const result = await feedbackCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { rating, comment, updatedAt: new Date() } }
      );
      res.send(result);
    });

    app.delete("/feedback/:id", verifyToken, async (req, res) => {
      const result = await feedbackCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    

    // ======================= Admin Stats =======================
    app.get("/admin-stats", verifyToken, verifyRole("admin"), async (req, res) => {
      const totalUser = await usersCollection.estimatedDocumentCount();
      const totalCamp = await campsCollection.estimatedDocumentCount();
      const totalRegistered = await registeredCollection.estimatedDocumentCount();

      const result = await registeredCollection
        .aggregate([
          { $addFields: { createdAt: { $toDate: "$_id" } } },
          { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, revenue: { $sum: "$fees" }, registered: { $sum: 1 } } },
        ])
        .toArray();

      const barChartData = result.map((d) => ({ date: d._id, revenue: d.revenue, registered: d.registered }));
      const totalRevenue = result.reduce((sum, d) => sum + d.revenue, 0);

      res.send({ totalUser, totalCamp, totalRegistered, barChartData, totalRevenue });
    });

    console.log("MongoDB connected successfully!");
  } finally {
    // No need to close client, keep server running
  }
}
run().catch(console.dir);

app.get("/", (req, res) => res.send("Hello from mediCamp Server.."));

app.listen(port, () => console.log(`mediCamp running on port ${port}`));
