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
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err);
      return res.status(401).send({ message: "unauthorized access" });
    }
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

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  const db = client.db("campdb");
  const campsCollection = db.collection("camps");
  const campsJoinCollection = db.collection("campsJoin");
  const registeredCollection = db.collection("registered");
  const usersCollection = db.collection("users");
  const feedbackCollection = db.collection("feedback");
  const SECRET_KEY = process.env.JWT_SECRET;

  try {
    // verify admin
    const verifyAdmin = async (req, res, next) => {
      const email = req?.user?.email;
      const user = await usersCollection.findOne({ email });
      console.log(user?.role);
      if (!user || user?.role !== "admin")
        return res
          .status(403)
          .send({ message: "Admin only actions!", role: user?.role });
      next();
    };
    // verify organizer
    const verifyOrganizer = async (req, res, next) => {
      const email = req?.user?.email;
      const user = await usersCollection.findOne({ email });
      console.log(user?.role);
      if (!user || user?.role !== "organizer")
        return res
          .status(403)
          .send({ message: "Admin only actions!", role: user?.role });
      next();
    };
    // Generate jwt token
    app.post("/jwt", async (req, res) => {
      const email = req.body;
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "365d",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

//==============CAMPS & DASHBOARD RELATED=================
    // Organizer Dashboard API
    app.get(
      "/organizer-camps",
      verifyToken,
      verifyOrganizer,
      async (req, res) => {
        const result = await campsCollection
          .find({ organizerEmail: req.query.email })
          .toArray();
        res.send(result);
      }
    );
    //add camps to dbms
    app.post("/camps", verifyToken, verifyOrganizer, async (req, res) => {
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
      verifyToken,
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
      verifyToken,
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
    app.patch("/update-profile", verifyToken, async (req, res) => {
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

    // confirm registration
    app.patch("/registered/:id/confirm", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { confirmationStatus: "confirmed" } }
      );
      if (result.modifiedCount > 0) {
        res.send({ success: true });
      } else {
        res.status(404).send({ message: "Registration not found" });
      }
    });
    // cancel registration
    app.delete("/registered/:id", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });
    // Example patch route to mark payment as paid
    app.patch("/registered/:id/pay", async (req, res) => {
      const id = req.params.id;
      const result = await registeredCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { paymentStatus: "paid" } }
      );
      if (result.modifiedCount > 0) {
        res.send({ success: true });
      } else {
        res.status(404).send({ message: "Registration not found" });
      }
    });
    // ✅ Register or update a user
app.post("/user", async (req, res) => {
  try {
    const user = req.body;
    if (!user?.email) return res.status(400).send({ message: "Email required" });

    const existing = await usersCollection.findOne({ email: user.email });

    if (existing) {
      // Update last login timestamp if user already exists
      const result = await usersCollection.updateOne(
        { email: user.email },
        { $set: { last_loggedIn: new Date().toISOString() } }
      );
      return res.send({ message: "User updated", result });
    }

    user.role = "participant";
    user.status = "active";
    user.created_at = new Date().toISOString();
    user.last_loggedIn = new Date().toISOString();

    const result = await usersCollection.insertOne(user);
    res.send({ message: "User created successfully", result });
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

// ✅ Get a single user's full info (role, status, etc.)
app.get("/user/:email", async (req, res) => {
  const email = req.params.email;
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(404).send({ message: "User not found" });
  res.send(user);
});

// ✅ Get role only (for frontend role-based routing)
app.get("/user/role/:email", async (req, res) => {
  const email = req.params.email;
  const user = await usersCollection.findOne({ email });
  res.send({ role: user?.role || "participant" });
});

// ✅ Update user profile (secured)
app.patch("/user/update/:email", verifyToken, async (req, res) => {
  const email = req.params.email;
  if (req.user.email !== email)
    return res.status(403).send({ message: "Forbidden access" });

  const updateData = req.body;
  const result = await usersCollection.updateOne(
    { email },
    { $set: updateData }
  );
  res.send(result);
});

// ✅ Admin: Get all users
app.get("/all-users", verifyToken, verifyRole("admin"), async (req, res) => {
  const result = await usersCollection
    .find({ email: { $ne: req.user.email } })
    .toArray();
  res.send(result);
});

// ✅ Admin: Update user role
app.patch(
  "/user/role/update/:email",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    const email = req.params.email;
    const { role } = req.body;
    const result = await usersCollection.updateOne(
      { email },
      { $set: { role, status: "verified" } }
    );
    res.send(result);
  }
);
    // update camp quantity (increase/decrease)
    app.patch("/participantCount-update/:id", async (req, res) => {
      const id = req.params.id;
      const { participantCountToUpdate, status } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $inc: {
          participantCount:
            status === "increase"
              ? participantCountToUpdate
              : -participantCountToUpdate,
        },
      };
      const result = await campsCollection.updateOne(filter, updateDoc);
      res.send(result);
    });
    // get all users for admin
    app.get("/all-users", verifyToken, verifyAdmin, async (req, res) => {
      console.log(req.user);
      const filter = { email: { $ne: req?.user?.email } };
      const result = await usersCollection.find(filter).toArray();
      res.send(result);
    });
    // updates a user's role
    app.patch(
      "/user/role/update/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const { role } = req.body;
        console.log(role);
        const filter = { email: email };
        const updateDoc = { $set: { role, status: "verified" } };
        const result = await usersCollection.updateOne(filter, updateDoc);
        console.log(result);
        res.send(result);
      }
    );
    // PATCH /users/:email
    app.patch("/users/:email", async (req, res) => {
      const email = req.params.email;
      const updatedInfo = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: updatedInfo }
      );
      res.send(result);
    });
    // become organizer request
    app.patch(
      "/become/organizer-request/:email",
      verifyToken,
      async (req, res) => {
        const email = req.params.email;
        const filter = { email: email };
        const updateDoc = { $set: { status: "requested" } };
        const result = await usersCollection.updateOne(filter, updateDoc);
        console.log(result);
        res.send(result);
      }
    );
    // // admin stats
    app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
      const totalUser = await usersCollection.estimatedDocumentCount();
      const totalCamp = await campsCollection.estimatedDocumentCount();
      const totalRegistered =
        await registeredCollection.estimatedDocumentCount();
      // mongodb aggregation
      const result = await registeredCollection
        .aggregate([
          {
            // convert id into date
            $addFields: { createdAt: { $toDate: "$_id" } },
          },
          {
            // group data by date
            $group: {
              _id: {
                $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
              },
              revenue: { $sum: "$fees" },
              registered: { $sum: 1 },
            },
          },
        ])
        .toArray();
      const barChartData = result.map((data) => ({
        date: data._id,
        revenue: data.revenue,
        registered: data.registered,
      }));
      const totalRevenue = result.reduce((sum, data) => sum + data?.revenue, 0);
      res.send({
        totalUser,
        totalCamp,
        totalRegistered,
        barChartData,
        totalRevenue,
      });
    });

  // Send a ping to confirm a successful connection // await client.db("admin").command({ ping: 1 }); // console.log( // "Pinged your deployment. You successfully connected to MongoDB!" // );
  }finally { 
    // Ensures that the client will close when you finish/error 
    } } run().catch(console.dir);
    app.get("/", (req, res) => { res.send("Hello from mediCamp Server.."); 
    }); 
    app.listen(port, ()=>{
      console.log(`mediCamp is running on port ${port}`);
    });