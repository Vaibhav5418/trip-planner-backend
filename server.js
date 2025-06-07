const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const axios = require("axios");
const chalk = require("chalk");
const morgan = require("morgan");
const compression = require("compression");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://sonivaibhav037:cwYn9YtHxHwtAlAv@tripplanner.irqhho2.mongodb.net/?retryWrites=true&w=majority&appName=tripPlanner";
const SERVER_START_TIME = new Date();

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(compression());
app.use(helmet());
app.use(morgan("dev"));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    status: 429,
    error: "Too many requests, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/trip-plan", apiLimiter);

// Server Banner
const printServerBanner = () => {
  console.clear();
  console.log(chalk.blue.bold("┌────────────────────────────────────────┐"));
  console.log(chalk.blue.bold("│                                        │"));
  console.log(chalk.blue.bold("│  ") + chalk.green.bold("TRIP PLANNER AI SERVER") + chalk.blue.bold("               │"));
  console.log(chalk.blue.bold("│  ") + chalk.yellow(`Version 1.0.0`) + chalk.blue.bold("                       │"));
  console.log(chalk.blue.bold("│                                        │"));
  console.log(chalk.blue.bold("└────────────────────────────────────────┘"));
};

// MongoDB Connection
mongoose.set("strictQuery", true);
const connectToMongoDB = async () => {
  console.log(chalk.yellow("🔄 Connecting to MongoDB..."));

  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
    });
    console.log(chalk.green("✅ Connected to MongoDB successfully"));
  } catch (error) {
    console.error(chalk.red("❌ MongoDB connection error:"), error.message);
    console.log(chalk.yellow("🔄 Retrying connection in 5 seconds..."));
    setTimeout(connectToMongoDB, 5000);
  }
};

mongoose.connection.on("error", (err) => {
  console.error(chalk.red("MongoDB error:"), err.message);
});

mongoose.connection.on("disconnected", () => {
  console.log(chalk.yellow("⚠️ MongoDB disconnected. Attempting to reconnect..."));
  connectToMongoDB();
});

// TripPlan Schema
const tripSchema = new mongoose.Schema(
  {
    user: { type: String, required: true, trim: true },
    city: { type: String, required: true, trim: true },
    type: { type: String, required: true, enum: ["budget", "luxury"], default: "budget" },
    days: { type: Number, required: true, min: 1 },
    plan: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, index: true },
    lastAccessed: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

tripSchema.virtual("isRecent").get(function () {
  const ONE_WEEK = 7 * 24 * 60 * 60 * 1000;
  return Date.now() - this.createdAt < ONE_WEEK;
});

const TripPlan = mongoose.model("TripPlan", tripSchema);

// Server status route
app.get("/status", (req, res) => {
  const uptime = Math.floor((new Date() - SERVER_START_TIME) / 1000);
  res.json({
    status: "operational",
    uptime,
    databaseConnected: mongoose.connection.readyState === 1,
    serverTime: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Generate trip plan route
app.post("/trip-plan", async (req, res) => {
  const { city, type, days } = req.body;

  if (!city || !type || !days) {
    return res.status(400).json({
      status: "error",
      message: "Missing required parameters: city, type, and days are required",
    });
  }

  console.log(chalk.blue(`🔍 Generating ${type} trip plan for ${city} (${days} days)`));

  try {
    const cachedPlan = await TripPlan.findOne({
      city: { $regex: new RegExp(city, "i") },
      type,
      days,
      createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    });

    if (cachedPlan) {
      cachedPlan.lastAccessed = new Date();
      await cachedPlan.save();

      console.log(chalk.green(`✅ Found cached plan for ${city}`));
      return res.json({
        tripPlan: cachedPlan.plan,
        source: "cache",
      });
    }
  } catch (err) {
    console.error(chalk.yellow("⚠️ Cache check failed, proceeding with API request"));
  }

  const prompt = `Create a ${type} travel plan for ${city}, India.
Include:
- 3 must-visit places
- 2 good hotels
- 2 restaurants
- A ${days}-day itinerary (day-wise plan)
Make it short, helpful, and friendly.`;

  const startTime = Date.now();
  let requestSuccessful = false;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const response = await axios.post(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        model: "mistralai/mistral-7b-instruct",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 1000,
        temperature: 0.7,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "http://localhost:5000",
          "X-Title": "Trip Planner",
        },
        signal: controller.signal,
      }
    );

    clearTimeout(timeoutId);
    requestSuccessful = true;

    const tripPlan = response.data.choices[0].message.content;
    const responseTime = Date.now() - startTime;

    console.log(chalk.green(`✅ Generated plan for ${city} in ${responseTime}ms`));

    res.json({
      tripPlan,
      source: "api",
      responseTime: `${responseTime}ms`,
    });
  } catch (error) {
    const responseTime = Date.now() - startTime;

    if (error.name === "AbortError" || error.code === "ECONNABORTED") {
      console.error(chalk.red(`❌ API request timed out after ${responseTime}ms`));
      return res.status(503).json({
        error: "The trip planning service is currently slow. Please try again later.",
      });
    }

    if (error.response) {
      console.error(chalk.red(`❌ API error ${error.response.status}:`), error.response.data);
      return res.status(error.response.status).json({
        error: `Failed to generate trip plan: ${error.response.data.error || "API error"}`,
      });
    } else if (error.request) {
      console.error(chalk.red("❌ No response from OpenRouter API"));
      return res.status(502).json({
        error: "Unable to reach the trip planning service. Please try again later.",
      });
    } else {
      console.error(chalk.red("❌ Error generating trip plan:"), error.message);
      return res.status(500).json({
        error: "An unexpected error occurred while planning your trip.",
      });
    }
  } finally {
    console.log(
      requestSuccessful
        ? chalk.green(`✅ Successfully processed trip plan request for ${city}`)
        : chalk.red(`❌ Failed to process trip plan request for ${city}`)
    );
  }
});

// Save trip plan route
app.post("/save-plan", async (req, res) => {
  let { user, city, type, days, plan } = req.body;

  if (!user || !city || !type || !days || !plan) {
    return res.status(400).json({
      status: "error",
      message: "Missing required fields",
    });
  }

  days = parseInt(days);
  console.log("📩 Received body:", req.body);

  try {
    const existingPlan = await TripPlan.findOne({ user, city, type, days, plan });

    if (existingPlan) {
      console.log(chalk.yellow(`⚠️ Plan already exists for ${user}`));
      return res.status(200).json({
        message: "This plan is already saved in your collection!",
        alreadyExists: true,
        planId: existingPlan._id,
      });
    }

    const newPlan = new TripPlan({ user, city, type, days, plan });
    console.log("🛠️ New plan to save:", newPlan);

    await newPlan.save();

    console.log(chalk.green(`✅ Plan saved for ${user}`));

    res.status(201).json({
      message: "Trip plan saved successfully!",
      planId: newPlan._id,
      timestamp: new Date(),
    });
  } catch (err) {
    console.error(chalk.red("❌ Error saving plan:"), err.message);
    res.status(500).json({
      error: "An error occurred while saving your trip plan. Please try again.",
    });
  }
});

// Get saved plans route
app.get("/get-plans/:user", async (req, res) => {
  const { user } = req.params;
  
  if (!user) {
    return res.status(400).json({
      status: "error",
      message: "User parameter is required",
    });
  }

  console.log(chalk.blue(`🔍 Fetching saved plans for user: ${user}`));

  try {
    const plans = await TripPlan.find({ user })
      .sort({ createdAt: -1 })
      .select("-__v")
      .lean();
    
    console.log(chalk.green(`✅ Retrieved ${plans.length} plans for ${user}`));
    
    res.status(200).json(plans);
  } catch (err) {
    console.error(chalk.red("❌ Error fetching plans:"), err.message);
    res.status(500).json({
      error: "Failed to retrieve saved plans. Please try again.",
    });
  }
});

// Delete trip plan route
app.delete("/delete-plan/:id", async (req, res) => {
  const { id } = req.params;
  
  if (!id) {
    return res.status(400).json({
      status: "error",
      message: "Plan ID is required",
    });
  }

  console.log(chalk.blue(`🗑️ Deleting plan with ID: ${id}`));

  try {
    const result = await TripPlan.findByIdAndDelete(id);
    
    if (!result) {
      console.log(chalk.yellow(`⚠️ Plan with ID ${id} not found`));
      return res.status(404).json({
        status: "error",
        message: "Plan not found",
      });
    }
    
    console.log(chalk.green(`✅ Successfully deleted plan for ${result.user}`));
    
    res.status(200).json({
      status: "success",
      message: "Trip plan deleted successfully!",
    });
  } catch (err) {
    console.error(chalk.red("❌ Error deleting plan:"), err.message);
    res.status(500).json({
      error: "Failed to delete trip plan. Please try again.",
    });
  }
});

// Start server
connectToMongoDB().then(() => {
  app.listen(PORT, () => {
    printServerBanner();
    console.log(chalk.cyan(`🚀 Server is running on http://localhost:${PORT}`));
  });
});