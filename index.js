// server.js (Main Application File)

const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// --- Configuration & Initialization ---
const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.3g5ecwq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// --- Global Middleware ---
app.use(cors());
app.use(express.json());

// --- Database Connection Setup ---
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let dbCollections = {}; // Store all collections here

async function connectDB() {
  try {
    await client.connect();
    const db = client.db("campDB");
    dbCollections = {
      campsCollection: db.collection("camps"),
      campsJoinCollection: db.collection("campsJoin"),
      usersCollection: db.collection("users"),
      feedbacksCollection: db.collection("feedback"),
      participantCollection: db.collection("participants"), // Original code mentioned this
      client: client // Pass client for transactions
    };
    console.log("✅ Connected to MongoDB");
    return dbCollections;
  } catch (error) {
    console.error("❌ Failed to connect to MongoDB:", error);
    // In a real app, you might want to exit the process here: process.exit(1);
    throw error;
  }
}

// =======================================================================
//                           I. MIDDLEWARE
// =======================================================================

// A utility wrapper to catch errors in async route handlers
const asyncWrapper = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// JWT Verification Middleware (Reads from Authorization Header)
const verifyJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .send({ message: "Unauthorized: No token provided" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err)
      return res.status(403).send({ message: "Forbidden: Invalid token" });
    req.decoded = decoded;
    next();
  });
};

// Organizer Role Verification Middleware
const verifyOrganizer = asyncWrapper(async (req, res, next) => {
  const { usersCollection } = dbCollections;
  const email = req.decoded?.email;

  if (!email) {
    return res.status(401).send({ message: "Unauthorized: No email found" });
  }

  const user = await usersCollection.findOne({ email });

  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }
  if (user.role !== "organizer") {
    return res.status(403).send({ message: "Forbidden access: Not an organizer" });
  }

  req.user = user; // Attach full user data for route use (e.g., getting organizer's email)
  next();
});

// =======================================================================
//                           II. CONTROLLERS
// =======================================================================

const authController = {
  // JWT Token API
  generateToken: asyncWrapper(async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).send({ message: "Email is required" });

    // Note: The original code only signed the email, but best practice is to include role
    // If the user's role is not available here, it should be fetched first.
    // Assuming the client doesn't need the role in the token for simplicity,
    // following the structure of the original code's signing process.
    const user = { email };
    const token = jwt.sign(user, SECRET_KEY, { expiresIn: "7d" });
    res.send({ token });
  }),
};

const userController = {
  // Create User
  createUser: asyncWrapper(async (req, res) => {
    const { usersCollection } = dbCollections;
    const user = req.body;
    if (!user?.email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const existingUser = await usersCollection.findOne({
      email: user.email,
    });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }
    const result = await usersCollection.insertOne(user);
    res.status(201).json({ message: "User added successfully", data: result });
  }),

  // Get User Role/Info by Email
  getUserInfo: asyncWrapper(async (req, res) => {
    const { usersCollection } = dbCollections;
    const { email } = req.params;
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  }),
  
  // Get User Role (The simplified route for role check)
  getUserRole: asyncWrapper(async (req, res) => {
    const { usersCollection } = dbCollections;
    const email = req.params.email;
    const user = await usersCollection.findOne({ email });
    res.send({ role: user?.role || "user" });
  }),

  // Update User Profile
  updateProfile: asyncWrapper(async (req, res) => {
    const { usersCollection } = dbCollections;
    // Security check: Only allow users to update their own profile
    if (req.decoded.email !== req.body.email) {
      return res.status(403).send({
        message: "Forbidden: You can only update your own profile.",
      });
    }

    const { email, name, photoURL, contact } = req.body;
    const updateFields = { updatedAt: new Date() };

    if (name) updateFields.name = name;
    if (photoURL) updateFields.photoURL = photoURL;
    if (contact !== undefined) updateFields.contact = contact;

    const result = await usersCollection.updateOne(
      { email: email },
      { $set: updateFields },
      { upsert: false }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ error: "User not found" });
    }

    res.send({ success: true, message: "Profile updated successfully" });
  }),
};

const campController = {
  // Add Camp
  addCamp: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    const campData = { ...req.body, participants: 0, createdAt: new Date() };
    const result = await campsCollection.insertOne(campData);
    res.status(201).send(result);
  }),

  // Get Popular Camps (Top 6)
  getPopularCamps: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    const result = await campsCollection
      .find()
      .sort({ participants: -1 })
      .limit(6)
      .toArray();
    res.send(result);
  }),

  // Get Single Camp by ID
  getCampById: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    const result = await campsCollection.findOne({
      _id: new ObjectId(req.params.id),
    });
    if (!result) return res.status(404).send({ message: "Camp not found" });
    res.send(result);
  }),

  // Get All Available Camps (with Search/Sort)
  getAvailableCamps: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
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
  }),
  
  // Delete Camp
  deleteCamp: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    const result = await campsCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });
    if (result.deletedCount === 0) {
      return res.status(404).send({ message: "Camp not found" });
    }
    res.send(result);
  }),

  // Update Camp
  updateCamp: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    const { _id, ...updateData } = req.body;
    const result = await campsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );
    if (result.matchedCount === 0) {
        return res.status(404).send({ message: "Camp not found for update" });
    }
    res.send(result);
  }),
};

const registrationController = {
  // Check Join Status
  checkJoinStatus: asyncWrapper(async (req, res) => {
    const { campsJoinCollection } = dbCollections;
    const { email, campId } = req.query;
    const existing = await campsJoinCollection.findOne({ email, campId });
    res.send({ joined: !!existing });
  }),
    
  // Camp Registration API (Transaction)
  registerCamp: asyncWrapper(async (req, res) => {
    const { campsJoinCollection, campsCollection, client } = dbCollections;
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
  }),

  // Update Confirmation Status
  updateConfirmationStatus: asyncWrapper(async (req, res) => {
    const { campsJoinCollection } = dbCollections;
    const { confirmationStatus } = req.body;
    if (!confirmationStatus) {
      return res
        .status(400)
        .send({ error: "confirmationStatus is required" });
    }

    const result = await campsJoinCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { confirmationStatus: confirmationStatus } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).send({ error: "Registration not found" });
    }
    res.send(result);
  }),
  
  // Cancel Registration (Transaction)
  cancelRegistration: asyncWrapper(async (req, res) => {
    const { campsJoinCollection, campsCollection, client } = dbCollections;
    const registrationId = req.params.id;
    const registration = await campsJoinCollection.findOne({
      _id: new ObjectId(registrationId),
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
          { _id: new ObjectId(registrationId) },
          { session }
        );
        // Decrement participant count
        await campsCollection.updateOne(
          { _id: new ObjectId(registration.campId) },
          { $inc: { participants: -1 } },
          { session }
        );
      });
      res.send({ success: true, message: "Registration cancelled successfully" });
    } finally {
      await session.endSession();
    }
  }),
};

const dashboardController = {
  // Organizer's Camps
  getOrganizerCamps: asyncWrapper(async (req, res) => {
    const { campsCollection } = dbCollections;
    // req.user is set by verifyOrganizer middleware
    const result = await campsCollection
      .find({ organizerEmail: req.user.email }) // Use req.user.email, not req.query.email
      .toArray();
    res.send(result);
  }),

  // Registered Camps (All registrations for a camp organizer's camps)
  getRegisteredCamps: asyncWrapper(async (req, res) => {
    const { campsJoinCollection, campsCollection } = dbCollections;
    const organizerEmail = req.query.email;

    const registered = await campsJoinCollection
      .find({ organizerEmail })
      .toArray();

    // Fetch all camp names from camps collection
    const campIds = [...new Set(registered.map((r) => r.campId))];
    const camps = await campsCollection
      .find({ _id: { $in: campIds.map((id) => new ObjectId(id)) } })
      .toArray();
    
    const campMap = new Map(camps.map(c => [c._id.toString(), c]));

    // Merge campName into registered records
    const result = registered.map((record) => {
      const camp = campMap.get(record.campId);
      return {
        ...record,
        campName: camp?.campName || "Unknown Camp",
      };
    });

    res.send(result);
  }),

  // Participant Dashboard API (Detailed Registered Camps)
  getParticipantAnalytics: asyncWrapper(async (req, res) => {
    const { campsJoinCollection, campsCollection } = dbCollections;
    const userEmail = req.query.email;
    
    // 1. Get registrations
    const registrations = await campsJoinCollection
      .find({ email: userEmail })
      .toArray();
    
    // 2. Extract camp details
    const campIds = [...new Set(registrations.map((r) => r.campId))];
    const camps = await campsCollection
        .find({ _id: { $in: campIds.map((id) => new ObjectId(id)) } })
        .toArray();
    const campMap = new Map(camps.map(c => [c._id.toString(), c]));

    // 3. Enrich registration data
    const enrichedData = registrations.map((reg) => {
      const camp = campMap.get(reg.campId);
      return {
        ...reg,
        campName: camp?.campName || "N/A",
        fees: camp?.fees || 0,
        location: camp?.location || "N/A",
        doctorName: camp?.doctorName || "N/A",
      };
    });
    res.send(enrichedData);
  }),
  
  // Participant Profile API
  getParticipantProfile: asyncWrapper(async (req, res) => {
    const { usersCollection, campsJoinCollection } = dbCollections;
    const user = await usersCollection.findOne({ email: req.query.email });
    // Note: The original code only took contact from the first registration found
    const registration = await campsJoinCollection.findOne({ email: req.query.email });
    
    res.send({
      name: user?.name,
      photoURL: user?.photoURL,
      contact: registration?.emergencyContact || user?.contact || "",
    });
  }),
};

const paymentController = {
    // Payment API
    createPaymentIntent: asyncWrapper(async (req, res) => {
      const { amount } = req.body;
      if (!amount || amount <= 0) {
        return res.status(400).send({ error: "Valid amount is required" });
      }
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency: "usd",
        payment_method_types: ['card']
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    }),

    // Update Payment Status
    updatePaymentStatus: asyncWrapper(async (req, res) => {
      const { campsJoinCollection } = dbCollections;
      const { status, transactionId } = req.body;
      if (!status || !transactionId) {
        return res.status(400).send({ error: "Status and Transaction ID are required" });
      }
      const result = await campsJoinCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status, transactionId } }
      );
      if (result.matchedCount === 0) {
        return res.status(404).send({ error: "Registration not found" });
      }
      res.send(result);
    }),

    // Payment History API
    getPaymentHistory: asyncWrapper(async (req, res) => {
      const { campsJoinCollection } = dbCollections;
      const { email } = req.query;
      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      const paymentHistory = await campsJoinCollection
        .find({
          email,
          status: { $regex: /^paid$/i }, // Case-insensitive match for "paid"
        })
        .sort({ registeredAt: -1 }) // Sort by most recent payment
        .toArray();
        
      if (paymentHistory.length === 0) {
        return res.status(404).send({ error: "No payment history found" });
      }
      // Note: In a production app, you'd merge camp details here as well for a richer history view.
      res.send(paymentHistory);
    }),
};

const feedbackController = {
  // Submit Feedback
  submitFeedback: asyncWrapper(async (req, res) => {
    const { feedbacksCollection } = dbCollections;
    const feedback = {
      ...req.body,
      submittedAt: new Date(),
    };
    const result = await feedbacksCollection.insertOne(feedback);
    res.status(201).send(result);
  }),

  // Get Participant's Feedbacks
  getParticipantFeedbacks: asyncWrapper(async (req, res) => {
    const { feedbacksCollection } = dbCollections;
    // Security check: ensure the user is only requesting their own feedback
    if (req.decoded.email !== req.query.email) {
      return res
        .status(403)
        .send({ message: "Forbidden: You can only access your own feedback." });
    }

    const participantEmail = req.query.email;
    const result = await feedbacksCollection
      .find({ participantEmail: participantEmail })
      .sort({ submittedAt: -1 })
      .toArray();
    res.send(result);
  }),

  // Get All Feedbacks
  getAllFeedbacks: asyncWrapper(async (req, res) => {
    const { feedbacksCollection } = dbCollections;
    const result = await feedbacksCollection.find().toArray();
    res.send(result);
  }),
};

const statsController = {
    // Organizer Overview Stats API
    getOrganizerStats: asyncWrapper(async (req, res) => {
        const { campsCollection, campsJoinCollection } = dbCollections;
        const organizerEmail = req.user.email; // Email from verifyOrganizer middleware

        // 1. Total Camps, Participants, and Upcoming Camps (Filtered by organizer)
        const campStats = await campsCollection
          .aggregate([
             { $match: { organizerEmail: organizerEmail } }, // Filter by organizer
            {
              $group: {
                _id: null,
                totalCamps: { $sum: 1 },
                totalParticipants: { $sum: "$participants" },
                // Upcoming Camps logic relies on ISO string comparison
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

        // 2. Total Revenue (from paid registrations for *this organizer's* camps)
        const revenueStats = await campsJoinCollection
          .aggregate([
            { $match: { status: "paid", organizerEmail: organizerEmail } }, // Filter by paid and organizer
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

        // 3. Registrations over the last 6 months (Filtered by organizer)
        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

        const registrationsOverTime = await campsJoinCollection
          .aggregate([
            { $match: { organizerEmail: organizerEmail, registeredAt: { $gte: sixMonthsAgo } } }, // Filter
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
                      monthsInYear: ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
                    },
                    in: { $arrayElemAt: ["$$monthsInYear", "$_id.month"] },
                  },
                },
                count: 1,
              },
            },
          ])
          .toArray();

        // 4. Camps by Location (Filtered by organizer)
        const campsByLocation = await campsCollection
          .aggregate([
            { $match: { organizerEmail: organizerEmail } }, // Filter by organizer
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

        // 5. Recent Registrations (Filtered by organizer)
        const recentRegistrations = await campsJoinCollection
          .find({ organizerEmail: organizerEmail })
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
    }),
};

// =======================================================================
//                           III. ROUTES
// =======================================================================

// Auth & User Routes
app.post("/jwt", authController.generateToken);
app.post("/users", userController.createUser);
app.get("/users/role/:email", userController.getUserRole); // Simplified role check
app.get("/users/info/:email", userController.getUserInfo); // Full user info
app.patch("/update-profile", verifyJWT, userController.updateProfile);

// Public Camp Routes
app.get("/camps", campController.getPopularCamps);
app.get("/available-camps", campController.getAvailableCamps);
app.get("/available-camps/:id", campController.getCampById);
app.get("/check-join-status", registrationController.checkJoinStatus);
app.post("/camps-join", registrationController.registerCamp);
app.delete("/cancel-registration/:id", registrationController.cancelRegistration);

// Organizer Protected Camp & Dashboard Routes
app.post("/camps", verifyJWT, verifyOrganizer, campController.addCamp);
app.get("/organizer-camps", verifyJWT, verifyOrganizer, dashboardController.getOrganizerCamps);
app.delete("/delete-camp/:id", verifyJWT, verifyOrganizer, campController.deleteCamp);
app.patch("/update-camp/:id", verifyJWT, verifyOrganizer, campController.updateCamp);
app.get("/organizer-stats", verifyJWT, verifyOrganizer, statsController.getOrganizerStats);

// Registration/Participant Routes
app.get("/registered-camps", dashboardController.getRegisteredCamps); // Organizer's view of registrations
app.patch("/update-confirmation/:id", registrationController.updateConfirmationStatus);
app.get("/participant-analytics", dashboardController.getParticipantAnalytics);
app.get("/participant-profile", dashboardController.getParticipantProfile);
app.get("/user-registered-camps", dashboardController.getParticipantAnalytics); // Used for payment, same logic as analytics

// Payment Routes
app.post("/create-payment-intent", paymentController.createPaymentIntent);
app.patch("/update-payment-status/:id", paymentController.updatePaymentStatus);
app.get("/payment-history", paymentController.getPaymentHistory);

// Feedback Routes
app.post("/submit-feedback", feedbackController.submitFeedback);
app.get("/feedbacks", feedbackController.getAllFeedbacks);
app.get("/participant-feedbacks", verifyJWT, feedbackController.getParticipantFeedbacks);


// =======================================================================
//                           IV. ERROR HANDLER & BOOTSTRAP
// =======================================================================

// Global Error Handler Middleware
app.use((err, req, res, next) => {
  console.error("Global Error Handler:", err.stack);
  const statusCode = err.status || 500;
  res.status(statusCode).send({
    message: err.message || "An unexpected error occurred",
    status: statusCode,
  });
});

// Root route for health check
app.get("/", (req, res) => {
  res.send("🚑 Medical Camp API is running! 🚀");
});


// Start the server only after connecting to the database
async function startServer() {
  await connectDB();
  
  // Only start listening if running directly (not required for Vercel/serverless)
  if (require.main === module) {
    app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
  }
}

// Execute the bootstrap function
startServer().catch(console.error);

// For Vercel/serverless: export the app instance
module.exports = app;