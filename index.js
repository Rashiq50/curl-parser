import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Joi from "joi";
// const converter = require("curl-to-postmanv2");
import * as curlconverter from "curlconverter";
import cors from "cors";
import xml2js from "xml2js";
import fs from "fs";
import crypto from "crypto";
import multer from "multer";
import { fileURLToPath } from "url";
import { dirname } from "path";
import cookieParser from "cookie-parser";
import Redis from "ioredis";

const userName = "admin";
const password = "Admin123!";
const COOKIE_NAME = "auth_token";
const COOKIE_VALUE = "secure_auth_token";

// Redis client
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

redis.on("connect", () => console.log("Connected to Redis"));
redis.on("error", (err) => console.error("Redis connection error:", err));

// Get current file path (ES module equivalent of __dirname)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
// need to use cors to allow call from any origin
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(cookieParser());
// For handling binary files
const upload = multer({ dest: "uploads/" });

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});

app.use(limiter);

// Parse XML middleware
const xmlParser = express.text({ type: "application/xml" });

const schema = Joi.object({
  curlCommand: Joi.string().trim().required().regex(/^curl/).messages({
    "string.empty": "The cURL command cannot be empty.",
    "string.pattern.base": "Invalid cURL command format.",
    "any.required": "The cURL command is required.",
  }),
});

app.post("/parse-curl", async (req, res) => {
  const { error, value } = schema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ success: false, message: error.details[0].message });
  }

  const { curlCommand } = value;

  try {
    const result = curlconverter.toJsonObject(curlCommand);
    console.log(result);
    res.status(200).json({
      success: true,
      data: result,
    });
  } catch (err) {
    console.error("Conversion error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to parse the cURL command. Please ensure it is valid.",
    });
  }
});

// In-memory user database for CRUD operations
let users = [
  { id: 1, name: "John Doe", email: "john@example.com" },
  { id: 2, name: "Jane Smith", email: "jane@example.com" },
];

// CRUD API endpoints
// Get all users
app.get("/api/users", (req, res) => {
  res.json({ success: true, data: users });
});

// Get user by ID
app.get("/api/users/:id", (req, res) => {
  const user = users.find((u) => u.id === parseInt(req.params.id));
  if (!user)
    return res.status(404).json({ success: false, message: "User not found" });
  res.json({ success: true, data: user });
});

// Create new user
app.post("/api/users", (req, res) => {
  const userSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
  });

  const { error, value } = userSchema.validate(req.body);
  if (error)
    return res
      .status(400)
      .json({ success: false, message: error.details[0].message });

  const newUser = {
    id: users.length > 0 ? Math.max(...users.map((u) => u.id)) + 1 : 1,
    name: value.name,
    email: value.email,
  };

  users.push(newUser);
  res.status(201).json({ success: true, data: newUser });
});

// Update user
app.put("/api/users/:id", (req, res) => {
  const user = users.find((u) => u.id === parseInt(req.params.id));
  if (!user)
    return res.status(404).json({ success: false, message: "User not found" });

  const userSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
  });

  const { error, value } = userSchema.validate(req.body);
  if (error)
    return res
      .status(400)
      .json({ success: false, message: error.details[0].message });

  user.name = value.name;
  user.email = value.email;

  res.json({ success: true, data: user });
});

// Delete user
app.delete("/api/users/:id", (req, res) => {
  const userIndex = users.findIndex((u) => u.id === parseInt(req.params.id));
  if (userIndex === -1)
    return res.status(404).json({ success: false, message: "User not found" });

  const deletedUser = users.splice(userIndex, 1)[0];
  res.json({
    success: true,
    data: deletedUser,
    message: "User deleted successfully",
  });
});

// Special endpoints for different content types

// Handle x-www-form-urlencoded
app.post("/api/form-data", (req, res) => {
  res.json({
    success: true,
    message: "Form data received successfully",
    data: req.body,
  });
});

// Handle binary data
app.post("/api/binary", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res
      .status(400)
      .json({ success: false, message: "No file uploaded" });
  }

  res.json({
    success: true,
    message: "Binary file received successfully",
    fileDetails: {
      filename: req.file.originalname || req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size,
    },
  });
});

// Handle XML data
app.post("/api/xml", xmlParser, (req, res) => {
  try {
    // Parse the XML data (in a real app, you'd do something with this)
    xml2js.parseString(req.body, (err, result) => {
      if (err) {
        return res.status(400).json({
          success: false,
          message: "Invalid XML format",
          error: err.message,
        });
      }

      // For testing, echo the parsed XML as JSON
      const receivedData = {
        parsedXml: result,
      };

      // Return sample XML response
      const builder = new xml2js.Builder();
      const sampleResponse = {
        response: {
          status: "success",
          message: "XML processed successfully",
          timestamp: new Date().toISOString(),
          data: {
            items: [
              { id: 1, name: "Item One", category: "Electronics" },
              { id: 2, name: "Item Two", category: "Books" },
            ],
          },
        },
      };

      const xml = builder.buildObject(sampleResponse);

      res.type("application/xml");
      res.send(xml);
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error processing XML data",
      error: error.message,
    });
  }
});

app.post("/login", (req, res) => {
  if (!req.body?.username || !req.body?.password) {
    return res
      .status(400)
      .json({ message: "Username and Password is required!" });
  }
  const { username, password: pwd } = req.body;
  if (username === userName && pwd === password) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true });
    return res.json({ message: "Login successful" });
  }
  res.status(401).json({ message: "Invalid credentials" });
});

app.get("/users", (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token === COOKIE_VALUE) {
    return res.json({ data: [{ _id: "1233", name: "test" }] });
  }
  res.status(401).json({ message: "Unauthorized" });
});

app.post("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ message: "Logged out successfully" });
});

// --- Shareable Link APIs ---

const REDIS_KEY_PREFIX = "shareable-link:";
const REDIS_REVERSE_KEY_PREFIX = "shareable-link-bug:";

function parseExpiration(expiration) {
  const match = expiration.match(/^(\d+)(d|h|m)$/);
  if (!match) return null;
  const value = parseInt(match[1]);
  const unit = match[2];
  const multipliers = { d: 86400, h: 3600, m: 60 };
  return value * multipliers[unit];
}

const generateLinkSchema = Joi.object({
  bugId: Joi.string().trim().required().messages({
    "string.empty": "Bug ID cannot be empty.",
    "any.required": "Bug ID is required.",
  }),
  expiration: Joi.string()
    .trim()
    .required()
    .pattern(/^\d+(d|h|m)$/)
    .messages({
      "string.empty": "Expiration cannot be empty.",
      "string.pattern.base":
        'Invalid expiration format. Use a number followed by d (days), h (hours), or m (minutes), e.g. "7d", "24h", "30m".',
      "any.required": "Expiration is required.",
    }),
  type: Joi.string()
    .valid("VIDEO", "SCREENSHOT", "BOTH", "WIDGET")
    .required()
    .messages({
      "any.only": 'Type must be "VIDEO", "SCREENSHOT", "BOTH", or "WIDGET".',
      "any.required": "Type is required.",
    }),
  withAudio: Joi.boolean().required().messages({
    "any.required": "withAudio is required.",
  }),
  message: Joi.string().trim().allow("").optional(),
});

app.post("/generate-link", async (req, res) => {
  const { error, value } = generateLinkSchema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ success: false, message: error.details[0].message });
  }

  const { bugId, expiration, type, withAudio, message } = value;
  const ttlSeconds = parseExpiration(expiration);

  if (!ttlSeconds || ttlSeconds <= 0) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid expiration value." });
  }

  try {
    // Invalidate any existing token for this bugId
    const reverseKey = `${REDIS_REVERSE_KEY_PREFIX}${bugId}`;
    const existingToken = await redis.get(reverseKey);
    if (existingToken) {
      await redis.del(`${REDIS_KEY_PREFIX}${existingToken}`);
    }

    // Create new token
    const token = crypto.randomBytes(32).toString("hex");
    const redisKey = `${REDIS_KEY_PREFIX}${token}`;

    await redis.set(
      redisKey,
      JSON.stringify({ bugId, type, withAudio, message }),
      "EX",
      ttlSeconds
    );
    await redis.set(reverseKey, token, "EX", ttlSeconds);

    res.status(201).json({
      success: true,
      data: { token, expiresIn: ttlSeconds },
    });
  } catch (err) {
    console.error("Error generating shareable link:", err);
    res.status(500).json({
      success: false,
      message: "Failed to generate shareable link.",
    });
  }
});

app.get("/validate-link/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const redisKey = `${REDIS_KEY_PREFIX}${token}`;
    const data = await redis.get(redisKey);

    if (!data) {
      return res.status(404).json({
        success: false,
        message: "Token is invalid or has expired.",
      });
    }

    const { bugId, type, withAudio, message: devMessage } = JSON.parse(data);

    res.json({
      success: true,
      data: { bugId, type, withAudio, message: devMessage, valid: true },
    });
  } catch (err) {
    console.error("Error validating link:", err);
    res.status(500).json({
      success: false,
      message: "Failed to validate link.",
    });
  }
});

const dismissLinkSchema = Joi.object({
  token: Joi.string().trim().required().messages({
    "string.empty": "Token cannot be empty.",
    "any.required": "Token is required.",
  }),
});

app.post("/dismiss-link", async (req, res) => {
  const { error, value } = dismissLinkSchema.validate(req.body);
  if (error) {
    return res
      .status(400)
      .json({ success: false, message: error.details[0].message });
  }

  const { token } = value;

  try {
    const redisKey = `${REDIS_KEY_PREFIX}${token}`;

    // Read forward key to get bugId for reverse key cleanup
    const data = await redis.get(redisKey);
    if (!data) {
      return res.status(404).json({
        success: false,
        message: "Token not found or already expired.",
      });
    }

    const { bugId } = JSON.parse(data);

    // Delete both forward and reverse keys
    await redis.del(redisKey);
    if (bugId) {
      await redis.del(`${REDIS_REVERSE_KEY_PREFIX}${bugId}`);
    }

    res.json({
      success: true,
      message: "Token dismissed successfully.",
    });
  } catch (err) {
    console.error("Error dismissing link:", err);
    res.status(500).json({
      success: false,
      message: "Failed to dismiss link.",
    });
  }
});

// Catch-all route for invalid endpoints
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "The requested endpoint does not exist.",
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
