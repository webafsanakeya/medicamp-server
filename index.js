require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");

const stripe = require("stripe")(process.env.STRIPE_SK_KEY);

const port = process.env.PORT || 3000;
const app = express();
// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://medicamp-app.web.app", //  Firebase Hosting
    "https://medicamp-app.firebaseapp.com", //  Firebase Alternative Domain
  ],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

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
  const registeredCollection = db.collection("registered");
  const usersCollection = db.collection("users");

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
    // Logout
    app.get("/logout", async (req, res) => {
      try {
        res
          .clearCookie("token", {
            maxAge: 0,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
      } catch (err) {
        res.status(500).send(err);
      }
    });

    // add a camp in db
    app.post("/add-camp", verifyToken, verifyOrganizer, async (req, res) => {
      const camp = req.body;
      const result = await campsCollection.insertOne(camp);

      res.send(result);
    });

    // get all camps data from db
    app.get("/camps", async (req, res) => {
      const result = await campsCollection.find().toArray();
      res.send(result);
    });

    // get all camps by organizer email
    app.get(
      "/camps-by-organizer",

      verifyToken,
      verifyOrganizer,
      async (req, res) => {
         console.log("✅ Route hit");
         
        const email = req.query.email;
        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }
        try {
          const filter = { organizerEmail: email };
          const result = await campsCollection.find(filter).toArray();
          res.send(result);
        } catch (error) {
          console.error("Error fetching Organizer's camps:", error);
          res.status(500).send({ message: "Failed to fetch organizer's camp" });
        }
      }
    );

    // sorted 6 camps
    app.get("/camps/popular", async (req, res) => {
      try {
        const popularCamps = await campsCollection
          .find()
          .sort({ participantCount: -1 })
          .limit(6)
          .toArray();

        res.send(popularCamps);
      } catch (error) {
        res.status(500).send({ error: "Failed to fetch popular camps" });
      }
    });

    // get a single camps data from db
    app.get("/camp/:id", async (req, res) => {
      const id = req.params.id;
      const result = await campsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // create payment intent for registration
    app.post("/create-payment-intent", async (req, res) => {
      const { campId, participantCount } = req.body;
      const camp = await campsCollection.findOne({
        _id: new ObjectId(campId),
      });
      if (!camp) return res.status(404).send({ message: "Camp not found" });
      const totalFees = participantCount * camp?.fees * 100;
      // stripe...
      const { client_secret } = await stripe.paymentIntents.create({
        amount: totalFees,
        currency: "usd",
        automatic_payment_methods: {
          enabled: true,
        },
      });

      res.send({ clientSecret: client_secret });
    });

    // save registered data in registered collection in db
    app.post("/registered", async (req, res) => {
      const registeredData = req.body;
      const result = await registeredCollection.insertOne(registeredData);
      res.send(result);
    });

    // get all registered info for participant
    app.get("/registers/participant/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const filter = { "participant.email": email };
      const result = await registeredCollection.find(filter).toArray();
      res.send(result);
    });

    // update registered info for participant

    // get all order info for organizer
    app.get(
      "/registers/organizer/:email",
      verifyToken,
      verifyOrganizer,
      async (req, res) => {
        const email = req.params.email;
        const filter = { "organizer.email": email };
        const result = await registeredCollection.find(filter).toArray();
        res.send(result);
      }
    );

    // save or update a user info in db
    app.post("/user", async (req, res) => {
      const userData = req.body;
      userData.role = "participant";
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      const query = {
        email: userData?.email,
      };

      const alreadyExists = await usersCollection.findOne(query);
      console.log("Users already exists: ", !!alreadyExists);

      if (!!alreadyExists) {
        console.log("Updating user data...");
        const result = await usersCollection.updateOne(query, {
          $set: { last_loggedIn: new Date().toISOString() },
        });
        return res.send(result);
      }

      console.log("Creating user data");

      // return console.log(userData);
      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });

    // get a user's role
    app.get("/user/role/:email", async (req, res) => {
      const email = req.params.email;
      const result = await usersCollection.findOne({ email });
      if (!result) return res.status(404).send({ message: "User not found." });
      res.send({ role: result?.role });
    });

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
      const filter = {
        email: {
          $ne: req?.user?.email,
        },
      };
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
        const updateDoc = {
          $set: {
            role,
            status: "verified",
          },
        };
        const result = await usersCollection.updateOne(filter, updateDoc);
        console.log(result);
        res.send(result);
      }
    );

    // become organizer request
    app.patch(
      "/become/organizer-request/:email",
      verifyToken,
      async (req, res) => {
        const email = req.params.email;

        const filter = { email: email };
        const updateDoc = {
          $set: {
            status: "requested",
          },
        };
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

      //  mongodb aggregation
      const result = await registeredCollection
        .aggregate([
          {
            // convert id into date
            $addFields: {
              createdAt: { $toDate: "$_id" },
            },
          },
          {
            // group data by date
            $group: {
              _id: {
                $dateToString: {
                  format: "%Y-%m-%d",
                  date: "$createdAt",
                },
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

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from mediCamp Server..");
});

app.listen(port, () => {
  console.log(`mediCamp is running on port ${port}`);
});
