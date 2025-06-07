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

// CORS configuration for your specific frontend
const corsOptions = {
  origin: [
    'https://trip-planner-frontend-ten.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5000'
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Middleware setup
app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());

// Helmet configuration with proper CSP for your frontend
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "https://trip-planner-frontend-ten.vercel.app"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  }
}));

app.use(morgan("combined"));

// Rate limiting with better configuration
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    status: 429,
    error: "Too many requests from this IP, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log(chalk.yellow(`⚠️ Rate limit exceeded for IP: ${req.ip}`));
    res.status(429).json({
      status: 429,
      error: "Too many requests from this IP, please try again later.",
    });
  }
});

app.use("/trip-plan", apiLimiter);
app.use("/save-plan", apiLimiter);

// Server Banner
const printServerBanner = () => {
  console.clear();
  console.log(chalk.blue.bold("┌────────────────────────────────────────┐"));
  console.log(chalk.blue.bold("│                                        │"));
  console.log(chalk.blue.bold("│  ") + chalk.green.bold("TRIP PLANNER AI SERVER") + chalk.blue.bold("               │"));
  console.log(chalk.blue.bold("│  ") + chalk.yellow(`Version 1.0.0`) + chalk.blue.bold("                       │"));
  console.log(chalk.blue.bold("│  ") + chalk.cyan(`Port: ${PORT}`) + chalk.blue.bold("                            │"));
  console.log(chalk.blue.bold("│                                        │"));
  console.log(chalk.blue.bold("└────────────────────────────────────────┘"));
};

// MongoDB Connection with better error handling
mongoose.set("strictQuery", true);
const connectToMongoDB = async () => {
  console.log(chalk.yellow("🔄 Connecting to MongoDB..."));

  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      bufferCommands: false,
      bufferMaxEntries: 0
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

mongoose.connection.on("reconnected", () => {
  console.log(chalk.green("✅ MongoDB reconnected successfully"));
});

// TripPlan Schema with better validation
const tripSchema = new mongoose.Schema(
  {
    user: { 
      type: String, 
      required: [true, 'User is required'], 
      trim: true,
      maxlength: [100, 'User name cannot exceed 100 characters']
    },
    city: { 
      type: String, 
      required: [true, 'City is required'], 
      trim: true,
      maxlength: [100, 'City name cannot exceed 100 characters']
    },
    type: { 
      type: String, 
      required: [true, 'Trip type is required'], 
      enum: {
        values: ["budget", "luxury"],
        message: 'Trip type must be either budget or luxury'
      },
      default: "budget" 
    },
    days: { 
      type: Number, 
      required: [true, 'Number of days is required'], 
      min: [1, 'Trip must be at least 1 day'],
      max: [30, 'Trip cannot exceed 30 days'],
      validate: {
        validator: Number.isInteger,
        message: 'Days must be a whole number'
      }
    },
    plan: { 
      type: String, 
      required: [true, 'Trip plan is required'],
      maxlength: [10000, 'Trip plan is too long']
    },
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

// Index for better query performance
tripSchema.index({ user: 1, createdAt: -1 });
tripSchema.index({ city: 1, type: 1, days: 1, createdAt: -1 });

const TripPlan = mongoose.model("TripPlan", tripSchema);

// Health check route
app.get("/", (req, res) => {
  res.json({
    message: "Trip Planner AI Server is running!",
    status: "healthy",
    timestamp: new Date().toISOString()
  });
});

// Server status route
app.get("/status", (req, res) => {
  const uptime = Math.floor((new Date() - SERVER_START_TIME) / 1000);
  res.json({
    status: "operational",
    uptime: `${uptime}s`,
    databaseConnected: mongoose.connection.readyState === 1,
    serverTime: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    frontend: "https://trip-planner-frontend-ten.vercel.app",
    backend: "https://trip-planner-backend-wlvx.onrender.com"
  });
});

// Input validation middleware
const validateTripPlanInput = (req, res, next) => {
  const { city, type, days } = req.body;
  
  if (!city || typeof city !== 'string' || city.trim().length === 0) {
    return res.status(400).json({
      status: "error",
      message: "City is required and must be a valid string",
    });
  }
  
  if (!type || !['budget', 'luxury'].includes(type)) {
    return res.status(400).json({
      status: "error",
      message: "Type must be either 'budget' or 'luxury'",
    });
  }
  
  const numDays = parseInt(days);
  if (!days || isNaN(numDays) || numDays < 1 || numDays > 30) {
    return res.status(400).json({
      status: "error",
      message: "Days must be a number between 1 and 30",
    });
  }
  
  // Sanitize inputs
  req.body.city = city.trim();
  req.body.type = type.toLowerCase();
  req.body.days = numDays;
  
  next();
};

// Generate trip plan route
app.post("/trip-plan", validateTripPlanInput, async (req, res) => {
  const { city, type, days } = req.body;

  console.log(chalk.blue(`🔍 Generating ${type} trip plan for ${city} (${days} days)`));

  try {
    // Check for cached plan within last 24 hours
    const cachedPlan = await TripPlan.findOne({
      city: { $regex: new RegExp(`^${city}$`, "i") },
      type,
      days,
      createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    }).lean();

    if (cachedPlan) {
      console.log(chalk.green(`✅ Found cached plan for ${city}`));
      return res.json({
        tripPlan: cachedPlan.plan,
        source: "cache",
        cachedAt: cachedPlan.createdAt
      });
    }
  } catch (err) {
    console.error(chalk.yellow("⚠️ Cache check failed:"), err.message);
  }

  // Enhanced prompt for better results
  const prompt = `Create a detailed ${type} travel plan for ${city}, India for ${days} ${days === 1 ? 'day' : 'days'}.

Please include:
1. **Top 3 Must-Visit Places**: Brief description of each attraction
2. **Recommended Hotels**: 2 ${type} hotels with approximate price range
3. **Food Recommendations**: 2 popular restaurants/food spots
4. **Day-wise Itinerary**: Detailed ${days}-day plan with timing suggestions
5. **Local Tips**: Transportation and cultural tips
6. **Budget Estimate**: Approximate ${type} budget breakdown

Keep the response well-structured, informative, and traveler-friendly.`;

  const startTime = Date.now();
  let requestSuccessful = false;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000); // Increased timeout

    const response = await axios.post(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        model: "mistralai/mistral-7b-instruct",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 1500, // Increased for more detailed response
        temperature: 0.7,
        top_p: 0.9,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://trip-planner-frontend-ten.vercel.app",
          "X-Title": "Trip Planner AI",
        },
        signal: controller.signal,
        timeout: 20000
      }
    );

    clearTimeout(timeoutId);
    requestSuccessful = true;

    if (!response.data?.choices?.[0]?.message?.content) {
      throw new Error("Invalid response format from AI service");
    }

    const tripPlan = response.data.choices[0].message.content;
    const responseTime = Date.now() - startTime;

    console.log(chalk.green(`✅ Generated plan for ${city} in ${responseTime}ms`));

    // Optionally cache the generated plan
    try {
      const newCachedPlan = new TripPlan({
        user: "system_cache",
        city,
        type,
        days,
        plan: tripPlan
      });
      await newCachedPlan.save();
      console.log(chalk.cyan(`💾 Cached plan for future requests`));
    } catch (cacheError) {
      console.log(chalk.yellow(`⚠️ Failed to cache plan: ${cacheError.message}`));
    }

    res.json({
      tripPlan,
      source: "api",
      responseTime: `${responseTime}ms`,
      generatedAt: new Date().toISOString()
    });

  } catch (error) {
    const responseTime = Date.now() - startTime;

    if (error.name === "AbortError" || error.code === "ECONNABORTED") {
      console.error(chalk.red(`❌ API request timed out after ${responseTime}ms`));
      return res.status(503).json({
        status: "error",
        error: "The trip planning service is taking longer than expected. Please try again.",
      });
    }

    if (error.response) {
      const status = error.response.status;
      console.error(chalk.red(`❌ API error ${status}:`), error.response.data);
      
      if (status === 401) {
        return res.status(500).json({
          status: "error",
          error: "AI service authentication failed. Please try again later.",
        });
      } else if (status === 429) {
        return res.status(429).json({
          status: "error",
          error: "AI service is busy. Please try again in a few minutes.",
        });
      } else {
        return res.status(500).json({
          status: "error",
          error: "Failed to generate trip plan. Please try again.",
        });
      }
    } else if (error.request) {
      console.error(chalk.red("❌ No response from AI service"));
      return res.status(502).json({
        status: "error",
        error: "Unable to reach the AI service. Please check your connection and try again.",
      });
    } else {
      console.error(chalk.red("❌ Error generating trip plan:"), error.message);
      return res.status(500).json({
        status: "error",
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

// Save trip plan route with better validation
app.post("/save-plan", async (req, res) => {
  let { user, city, type, days, plan } = req.body;

  // Validation
  if (!user || !city || !type || !days || !plan) {
    return res.status(400).json({
      status: "error",
      message: "All fields are required: user, city, type, days, plan",
    });
  }

  // Sanitize and validate inputs
  user = user.toString().trim();
  city = city.toString().trim();
  type = type.toString().toLowerCase();
  days = parseInt(days);

  if (!['budget', 'luxury'].includes(type)) {
    return res.status(400).json({
      status: "error",
      message: "Type must be either 'budget' or 'luxury'",
    });
  }

  if (isNaN(days) || days < 1 || days > 30) {
    return res.status(400).json({
      status: "error",
      message: "Days must be a number between 1 and 30",
    });
  }

  console.log(chalk.blue(`💾 Saving plan for user: ${user}`));

  try {
    // Check if identical plan already exists
    const existingPlan = await TripPlan.findOne({ 
      user, 
      city: { $regex: new RegExp(`^${city}$`, "i") }, 
      type, 
      days 
    });

    if (existingPlan) {
      console.log(chalk.yellow(`⚠️ Similar plan already exists for ${user}`));
      return res.status(200).json({
        status: "info",
        message: "A similar plan already exists in your collection!",
        alreadyExists: true,
        planId: existingPlan._id,
      });
    }

    const newPlan = new TripPlan({ user, city, type, days, plan });
    const savedPlan = await newPlan.save();

    console.log(chalk.green(`✅ Plan saved for ${user} - ID: ${savedPlan._id}`));

    res.status(201).json({
      status: "success",
      message: "Trip plan saved successfully!",
      planId: savedPlan._id,
      timestamp: savedPlan.createdAt,
    });
  } catch (err) {
    console.error(chalk.red("❌ Error saving plan:"), err.message);
    
    if (err.name === 'ValidationError') {
      return res.status(400).json({
        status: "error",
        message: "Invalid data provided",
        details: err.message
      });
    }
    
    res.status(500).json({
      status: "error",
      error: "Failed to save trip plan. Please try again.",
    });
  }
});

// Get saved plans route with pagination
app.get("/get-plans/:user", async (req, res) => {
  const { user } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  
  if (!user || user.trim().length === 0) {
    return res.status(400).json({
      status: "error",
      message: "User parameter is required",
    });
  }

  console.log(chalk.blue(`🔍 Fetching saved plans for user: ${user} (page ${page})`));

  try {
    const [plans, totalCount] = await Promise.all([
      TripPlan.find({ user: user.trim() })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select("-__v")
        .lean(),
      TripPlan.countDocuments({ user: user.trim() })
    ]);
    
    console.log(chalk.green(`✅ Retrieved ${plans.length} plans for ${user} (${totalCount} total)`));
    
    res.status(200).json({
      status: "success",
      plans,
      pagination: {
        current: page,
        total: Math.ceil(totalCount / limit),
        count: plans.length,
        totalPlans: totalCount
      }
    });
  } catch (err) {
    console.error(chalk.red("❌ Error fetching plans:"), err.message);
    res.status(500).json({
      status: "error",
      error: "Failed to retrieve saved plans. Please try again.",
    });
  }
});

// Delete trip plan route
app.delete("/delete-plan/:id", async (req, res) => {
  const { id } = req.params;
  
  if (!id || !mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      status: "error",
      message: "Valid plan ID is required",
    });
  }

  console.log(chalk.blue(`🗑️ Deleting plan with ID: ${id}`));

  try {
    const result = await TripPlan.findByIdAndDelete(id);
    
    if (!result) {
      console.log(chalk.yellow(`⚠️ Plan with ID ${id} not found`));
      return res.status(404).json({
        status: "error",
        message: "Plan not found or already deleted",
      });
    }
    
    console.log(chalk.green(`✅ Successfully deleted plan for ${result.user}`));
    
    res.status(200).json({
      status: "success",
      message: "Trip plan deleted successfully!",
      deletedPlan: {
        id: result._id,
        city: result.city,
        user: result.user
      }
    });
  } catch (err) {
    console.error(chalk.red("❌ Error deleting plan:"), err.message);
    res.status(500).json({
      status: "error",
      error: "Failed to delete trip plan. Please try again.",
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(chalk.red('❌ Unhandled error:'), err.stack);
  res.status(500).json({
    status: "error",
    error: "Something went wrong on the server!",
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: "error",
    message: "Route not found",
    availableRoutes: [
      'GET /',
      'GET /status',
      'POST /trip-plan',
      'POST /save-plan',
      'GET /get-plans/:user',
      'DELETE /delete-plan/:id'
    ]
  });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(chalk.yellow(`\n📶 Received ${signal}. Starting graceful shutdown...`));
  
  mongoose.connection.close(() => {
    console.log(chalk.green('✅ MongoDB connection closed'));
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const startServer = async () => {
  try {
    await connectToMongoDB();
    
    app.listen(PORT, '0.0.0.0', () => {
      printServerBanner();
      console.log(chalk.cyan(`🚀 Server is running on port ${PORT}`));
      console.log(chalk.cyan(`🌐 Frontend: https://trip-planner-frontend-ten.vercel.app`));
      console.log(chalk.cyan(`🔗 Backend: https://trip-planner-backend-wlvx.onrender.com`));
      console.log(chalk.green(`✅ Server ready to accept connections`));
    });
  } catch (error) {
    console.error(chalk.red('❌ Failed to start server:'), error.message);
    process.exit(1);
  }
};

startServer();