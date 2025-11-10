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
    const { email } = req.decoded;
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.role !== role) {
      return res.status(403).send({ message: `Access restricted to ${role}` });
    }

    req.user = user; // attach full user info
    next();
  } catch (err) {
    res.status(500).send({ message: "Role verification failed" });
  }
};
   // Organizer Verify Middleware
    const verifyOrganizer = async (req, res, next) => {
      try {
        const email = req.decoded.email;
        if (!email) {
          return res
            .status(401)
            .send({ message: "Unauthorized: No email found" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        if (user.role !== "organizer") {
          return res
            .status(403)
            .send({ message: "Forbidden access: Not an organizer" });
        }

        // Attach user data to request object for further use in routes
        req.user = user;
        next();
      } catch (error) {
        console.error("Error in verifyOrganizer middleware:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    };

// JWT Token API
app.post("/jwt", async (req, res) => {
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
});

//==================all USERS API==================
    // Users info
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email) {
          return res.status(400).json({ message: "Email is required" });
        }
        const usersCollection = db.collection("users");
        // Check if user already exists
        const existingUser = await usersCollection.findOne({
          email: user.email,
        });
        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }
        const result = await usersCollection.insertOne(user);
        res
          .status(201)
          .json({ message: "User added successfully", data: result });
      } catch (err) {
        console.error("Add User Error:", err);
        res
          .status(500)
          .json({ message: "Internal Server Error", error: err.message });
      }
    });
    //finding user info api using with user email
    app.get("/users/role/:email", async (req, res) => {
      const { email } = req.params;
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        res.json(user); // send full user details
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
// // ======================= Demo Login =======================
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

// // ======================= Profile =======================
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

 //==============CAMPS & DASHBOARD RELATED=================
    // Organizer Dashboard API
app.get("/organizer-camps", verifyJWT, verifyRole("organizer"), async (req, res) => {
  const result = await campsCollection
    .find({ organizerEmail: req.user.email })
    .toArray();
  res.send(result);
});

app.post("/camps", verifyJWT, verifyRole("organizer"), async (req, res) => {
  const campData = { ...req.body, participants: 0, organizerEmail: req.user.email };
  const result = await campsCollection.insertOne(campData);
  res.send(result);
});

//add camps to dbms
    app.post("/camps", verifyJWT, verifyOrganizer, async (req, res) => {
      const campData = { ...req.body, participants: 0 };
      const result = await campsCollection.insertOne(campData);
      res.send(result);
    });
    //get camps
    app.get("/camps", async (req, res) => {
      const result = await campsCollection
        .find()
        .sort({ participants: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });
    //  check users join status
    app.get("/check-join-status", async (req, res) => {
      const { email, campId } = req.query;
      try {
        const existing = await campsJoinCollection.findOne({ email, campId });
        res.send({ joined: !!existing });
      } catch (error) {
        console.error("Error checking join status:", error);
        res.status(500).send({ joined: false });
      }
    });
    // available api
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

      const result = await campsCollection
        .find(query)
        .sort(sortMap[sort] || { campName: 1 })
        .toArray();

      res.send(result);
    });
   
    // Camp Registration API
    app.post("/camps-join", async (req, res) => {
      const data = req.body;
      const { email, campId } = data;
      const session = client.startSession();
      try {
        await session.withTransaction(async () => {
          const existing = await campsJoinCollection.findOne(
            { email, campId },
            { session }
          );

          if (existing) {
            throw new Error("You have already registered for this camp");
          }

          const registrationData = {
            ...data,
            status: "unpaid",
            confirmationStatus: "Pending",
            registeredAt: new Date(),
          };

          const result = await campsJoinCollection.insertOne(registrationData, {
            session,
          });

          const updateResult = await campsCollection.updateOne(
            { _id: new ObjectId(campId) },
            { $inc: { participants: 1 } },
            { session }
          );

          if (updateResult.matchedCount === 0) {
            throw new Error("Camp not found for participant count update");
          }

          res.send({
            success: true,
            insertedId: result.insertedId,
            message: "Registration successful",
          });
        });
      } catch (error) {
        if (
          error.message.includes("duplicate key") ||
          error.message.includes("already registered")
        ) {
          res.status(400).send({
            success: false,
            message: "You have already registered for this camp",
          });
        } else {
          console.error("Registration error:", error);
          res.status(500).send({
            success: false,
            message: error.message || "Registration failed",
          });
        }
      } finally {
        await session.endSession();
      }
    });

    // Registered Camps API
    app.get("/registered-camps", async (req, res) => {
      const registered = await campsJoinCollection
        .find({ organizerEmail: req.query.email })
        .toArray();

      // Fetch all camp names from camps collection
      const campIds = registered.map((r) => r.campId);
      const camps = await campsCollection
        .find({ _id: { $in: campIds.map((id) => new ObjectId(id)) } })
        .toArray();

      // Merge campName into registered records
      const result = registered.map((record) => {
        const camp = camps.find((c) => c._id.toString() === record.campId);
        return {
          ...record,
          campName: camp?.campName || "Unknown Camp",
        };
      });

      res.send(result);
    });

    //delete the camps
    app.delete(
      "/delete-camp/:id",
      verifyJWT,
      verifyOrganizer,
      async (req, res) => {
        const result = await campsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send(result);
      }
    );
    // Update Camp API
    app.patch(
      "/update-camp/:id",
      verifyJWT,
      verifyOrganizer,
      async (req, res) => {
        const { _id, ...updateData } = req.body;
        const result = await campsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: updateData }
        );
        res.send(result);
      }
    );
    // Update Confirmation Status API
    app.patch("/update-confirmation/:id", async (req, res) => {
      const { confirmationStatus } = req.body;
      if (!confirmationStatus) {
        return res
          .status(400)
          .send({ error: "confirmationStatus is required" });
      }

      try {
        const result = await campsJoinCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { confirmationStatus: confirmationStatus } }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "Registration not found" });
        }
        res.send(result);
      } catch (error) {
        console.error("Error updating confirmation status:", error);
        res.status(500).send({ error: "Failed to update confirmation status" });
      }
    });
    app.get("/available-camps/:id", async (req, res) => {
      const result = await campsCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });


    //=======================participant==================
    // Profile API
    app.get("/participant-profile", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.query.email });
      const registration = await campsJoinCollection.findOne({
        email: req.query.email,
      });
      res.send({
        name: user?.name,
        photoURL: user?.photoURL,
        contact: registration?.emergencyContact || "",
      });
    });

    // Participant Dashboard API
    app.get("/participant-analytics", async (req, res) => {
      const userEmail = req.query.email;
      // 1. Get registrations
      const registrations = await campsJoinCollection
        .find({ email: userEmail })
        .toArray();
      // 2. Fetch camp details for each registration
      const enrichedData = await Promise.all(
        registrations.map(async (reg) => {
          const camp = await campsCollection.findOne({
            _id: new ObjectId(reg.campId),
          });
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
    });
    app.get("/users/role/:email", async (req, res) => {
      const email = req.params.email;
      const user = await usersCollection.findOne({ email });
      res.send({ role: user?.role || "user" });
    });

    //update profile users
    app.patch("/update-profile", verifyJWT, async (req, res) => {
      // Security check: Only allow users to update their own profile
      if (req.decoded.email !== req.body.email) {
        return res.status(403).send({
          message: "Forbidden: You can only update your own profile.",
        });
      }

      const { email, name, photoURL, contact } = req.body;

      // Construct the fields to be updated in the 'users' collection
      const updateFields = {
        updatedAt: new Date(), // Always update the timestamp
      };
      if (name) updateFields.name = name;
      if (photoURL) updateFields.photoURL = photoURL;
      // This will add or update the contact field in the users collection
      if (contact !== undefined) updateFields.contact = contact;

      try {
        // --- THE FIX: Use usersCollection instead of participantCollection ---
        const result = await usersCollection.updateOne(
          { email: email },
          { $set: updateFields },
          { upsert: false } // Do not create a new user if one doesn't exist
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "User not found" });
        }

        res.send({
          success: true,
          message: "Profile updated successfully in the database",
        });
      } catch (error) {
        console.error("Error updating profile in DB:", error);
        res.status(500).send({ error: "Failed to update profile in database" });
      }
    });
    ///payments
    app.get("/user-registered-camps", async (req, res) => {
      const userEmail = req.query.email;

      // 1. Get user registrations
      const registrations = await campsJoinCollection
        .find({ email: userEmail })
        .toArray();

      // 2. Fetch camp details for each registration
      const enrichedData = await Promise.all(
        registrations.map(async (reg) => {
          const camp = await campsCollection.findOne({
            _id: new ObjectId(reg.campId),
          });
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
    });

    // Payment API
    app.post("/create-payment-intent", async (req, res) => {
      const { amount } = req.body;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency: "usd",
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.patch("/update-payment-status/:id", async (req, res) => {
      const { status, transactionId } = req.body;
      const result = await campsJoinCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status, transactionId } }
      );
      res.send(result);
    });

    // Payment History API
    app.get("/payment-history", async (req, res) => {
      const { email } = req.query;
      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      try {
        const paymentHistory = await campsJoinCollection
          .find({
            email,
            status: { $regex: /^paid$/i }, // Case-insensitive match for "paid"
          })
          .toArray();
        if (paymentHistory.length === 0) {
          return res.status(404).send({ error: "No payment history found" });
        }
        res.send(paymentHistory);
      } catch (error) {
        res.status(500).send({ error: "Failed to fetch payment history" });
      }
    });
    app.delete("/cancel-registration/:id", async (req, res) => {
      const registration = await campsJoinCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      if (!registration) {
        return res.status(404).send({ message: "Registration not found" });
      }
      if (registration.status === "paid") {
        return res
          .status(400)
          .send({ message: "Cannot cancel paid registration" });
      }
      const session = client.startSession();
      try {
        await session.withTransaction(async () => {
          // Delete registration
          await campsJoinCollection.deleteOne(
            { _id: new ObjectId(req.params.id) },
            { session }
          );
          // Decrement participant count
          await campsCollection.updateOne(
            { _id: new ObjectId(registration.campId) },
            { $inc: { participants: -1 } },
            { session }
          );
        });
        res.send({ success: true });
      } finally {
        await session.endSession();
      }
    });

    //feedback
    app.get("/participant-feedbacks", verifyJWT, async (req, res) => {
      // Security check: ensure the user is only requesting their own feedback
      if (req.decoded.email !== req.query.email) {
        return res
          .status(403)
          .send({
            message: "Forbidden: You can only access your own feedback.",
          });
      }

      try {
        const participantEmail = req.query.email;
        const result = await feedbacksCollection
          .find({ participantEmail: participantEmail })
          .sort({ submittedAt: -1 }) // Show most recent first
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching participant feedback:", error);
        res.status(500).send({ message: "Failed to fetch feedback" });
      }
    });
    // Feedback API
    app.post("/submit-feedback", async (req, res) => {
      const feedback = {
        ...req.body,
        submittedAt: new Date(),
      };
      const result = await feedbacksCollection.insertOne(feedback);
      res.send(result);
    });

    app.get("/feedbacks", async (req, res) => {
      const result = await feedbacksCollection.find().toArray();
      res.send(result);
    });
   // ================== ORGANIZER OVERVIEW STATS API ==================
app.get(
  "/organizer-stats",
  verifyJWT,
  verifyOrganizer,
  async (req, res) => {
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
                  $cond: [
                    { $gt: ["$dateTime", new Date().toISOString()] },
                    1,
                    0,
                  ],
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
              pipeline: [
                { $match: { $expr: { $eq: ["$_id", "$$camp_id"] } } },
              ],
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
              _id: {
                year: { $year: "$registeredAt" },
                month: { $month: "$registeredAt" },
              },
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
          {
            $group: {
              _id: "$location",
              count: { $sum: 1 },
            },
          },
          {
            $project: {
              _id: 0,
              location: "$_id",
              count: 1,
            },
          },
        ])
        .toArray();

      const recentRegistrations = await campsJoinCollection
        .find()
        .sort({ registeredAt: -1 })
        .limit(5)
        .toArray();

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
    } catch (error) {
      console.error("Error fetching organizer stats:", error);
      res.status(500).send({ message: "Failed to fetch stats" });
    }
  }
);

// ✅ Root route for health check
app.get("/", (req, res) => {
  res.send("🚑 Medical Camp API is running!");
});

if (require.main === module) {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
}

module.exports = app;