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

// Mount parameterization router
app.use('/parameterization', createParameterizationRouter());

// Catch-all route for invalid endpoints
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "The requested endpoint does not exist.",
  });
});


/** @param {string} url */
function safeParseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** @param {any} value */
function safeJsonParse(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'object') return value;
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

/** @param {string} resource */
function singularize(resource) {
  if (!resource) return resource;
  if (resource.endsWith('ies')) return `${resource.slice(0, -3)}y`;
  if (resource.endsWith('s') && resource.length > 1) return resource.slice(0, -1);
  return resource;
}

/**
 * @param {string[]} segments
 * @param {number} idSegmentIndex
 */
function guessVarNameFromPathSegments(segments, idSegmentIndex) {
  const prev = segments[idSegmentIndex - 1] || 'resource';
  const base = singularize(prev.replace(/[^a-zA-Z0-9]/g, '')) || 'resource';
  return `${base}Id`;
}

/**
 * @param {string} pathname
 * @param {string} targetSegment
 * @param {string} replacement
 */
function replaceAllExactSegment(pathname, targetSegment, replacement) {
  const parts = pathname.split('/');
  const out = parts.map((seg) => (seg === targetSegment ? replacement : seg));
  return out.join('/');
}

/** @param {string} str */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * @param {string} parentPath
 * @param {string} key
 */
function jsonPathForKey(parentPath, key) {
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)) return `${parentPath}.${key}`;
  return `${parentPath}[${JSON.stringify(key)}]`;
}

// ---------------------------------------------------------------------------
// URL helpers (boundary-aware)
// ---------------------------------------------------------------------------

/**
 * @param {string} url
 * @param {string} rawValue
 * @returns {boolean}
 */
function valueAppearsAsCompleteUrlComponent(url, rawValue) {
  const urlObj = safeParseUrl(url);
  if (!urlObj) return url.includes(rawValue);

  const segments = urlObj.pathname.split('/').filter(Boolean);
  if (segments.includes(rawValue)) return true;

  for (const [, paramValue] of urlObj.searchParams.entries()) {
    if (paramValue === rawValue) return true;
  }
  return false;
}

/**
 * @param {string} url
 * @param {string} rawValue
 * @param {string} replacement
 * @returns {string}
 */
function replaceInUrlBoundaryAware(url, rawValue, replacement) {
  const urlObj = safeParseUrl(url);
  if (!urlObj) return url;

  const pathname = replaceAllExactSegment(urlObj.pathname, rawValue, replacement);

  const newParams = new URLSearchParams();
  for (const [key, paramValue] of urlObj.searchParams.entries()) {
    newParams.append(key, paramValue === rawValue ? replacement : paramValue);
  }

  const queryString = newParams.toString();
  const decodedQuery = queryString
    .replace(/%7B%7B/g, '{{')
    .replace(/%7D%7D/g, '}}');

  const search = decodedQuery ? `?${decodedQuery}` : '';
  return `${urlObj.origin}${pathname}${search}${urlObj.hash}`;
}

// ---------------------------------------------------------------------------
// JSON body helpers (boundary-aware)
// ---------------------------------------------------------------------------

/**
 * Check if value exists as an exact match anywhere in an object.
 * Uses iterative stack to avoid stack overflow on deep JSON.
 * @param {any} obj
 * @param {string} rawValue
 * @returns {boolean}
 */
function checkValueExistsInObject(obj, rawValue) {
  const stack = [obj];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || current === undefined) continue;
    if (Array.isArray(current)) {
      for (let i = current.length - 1; i >= 0; i--) stack.push(current[i]);
      continue;
    }
    if (typeof current === 'object') {
      const values = Object.values(current);
      for (let i = values.length - 1; i >= 0; i--) stack.push(values[i]);
      continue;
    }
    if (typeof current === 'string' && current === rawValue) return true;
  }
  return false;
}

/**
 * Replace exact string values in a JSON object (iterative).
 * @param {any} obj
 * @param {string} rawValue
 * @param {string} replacement
 * @returns {any}
 */
function replaceExactValuesInObject(obj, rawValue, replacement) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return obj === rawValue ? replacement : obj;
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map((item) => replaceExactValuesInObject(item, rawValue, replacement));
  }

  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = replaceExactValuesInObject(value, rawValue, replacement);
  }
  return result;
}

/**
 * @param {string} body
 * @param {string} rawValue
 * @returns {boolean}
 */
function valueAppearsAsCompleteJsonValue(body, rawValue) {
  if (!body || !rawValue) return false;

  const parsed = safeJsonParse(body);
  if (parsed && typeof parsed === 'object') {
    return checkValueExistsInObject(parsed, rawValue);
  }

  const escaped = escapeRegex(rawValue);
  const jsonStringPattern = new RegExp(`"${escaped}"`);
  return jsonStringPattern.test(body);
}

/**
 * @param {string|null} body
 * @param {string} rawValue
 * @param {string} replacement
 * @returns {string|null}
 */
function replaceInBodyBoundaryAware(body, rawValue, replacement) {
  if (!body || typeof body !== 'string') return body;

  const parsed = safeJsonParse(body);
  if (parsed && typeof parsed === 'object') {
    const replaced = replaceExactValuesInObject(parsed, rawValue, replacement);
    try {
      return JSON.stringify(replaced, null, 2);
    } catch {
      return JSON.stringify(replaced);
    }
  }

  const escaped = escapeRegex(rawValue);
  const jsonStringPattern = new RegExp(`"${escaped}"`, 'g');
  return body.replace(jsonStringPattern, `"${replacement}"`);
}

// ---------------------------------------------------------------------------
// Header helpers (boundary-aware)
// ---------------------------------------------------------------------------

/**
 * @param {Array<{key:string,value:string,enabled?:boolean}>} headers
 * @param {string} rawValue
 * @returns {boolean}
 */
function valueAppearsAsCompleteHeaderValue(headers, rawValue) {
  if (!Array.isArray(headers) || headers.length === 0) return false;

  return headers.some((h) => {
    const value = typeof h?.value === 'string' ? h.value : '';
    if (!value) return false;
    if (value === rawValue) return true;
    if (value === `Bearer ${rawValue}`) return true;
    const segments = value.split(',').map((s) => s.trim());
    if (segments.includes(rawValue)) return true;
    return false;
  });
}

/**
 * @param {Array<{key:string,value:string,enabled?:boolean}>} headers
 * @param {string} rawValue
 * @param {string} replacement
 * @returns {Array<{key:string,value:string,enabled?:boolean}>}
 */
function replaceInHeadersBoundaryAware(headers, rawValue, replacement) {
  if (!Array.isArray(headers) || headers.length === 0) return headers;

  return headers.map((h) => {
    const value = typeof h?.value === 'string' ? h.value : '';
    if (!value) return h;

    if (value === rawValue) return { ...h, value: replacement };
    if (value === `Bearer ${rawValue}`) return { ...h, value: `Bearer ${replacement}` };

    if (value.includes(',') && value.includes(rawValue)) {
      const segments = value.split(',').map((s) => s.trim());
      if (segments.includes(rawValue)) {
        const newSegments = segments.map((s) => (s === rawValue ? replacement : s));
        return { ...h, value: newSegments.join(', ') };
      }
    }

    return h;
  });
}

// ---------------------------------------------------------------------------
// Response body extraction
// ---------------------------------------------------------------------------

/** @param {any} req */
function getResponseBodyObjectFromRequest(req) {
  if (!req) return undefined;

  const candidate =
    req?.responseData?.responseBody ??
    req?.responseData?.payload ??
    req?.responseData?.body ??
    req?.responseData?.resBody ??
    req?.response?.responseBody ??
    req?.response?.body ??
    req?.response?.data ??
    req?.response?.payload ??
    req?.response ??
    undefined;

  return safeJsonParse(candidate) ?? (typeof candidate === 'object' ? candidate : undefined);
}

// ---------------------------------------------------------------------------
// Leaf collection — iterative (stack-based) to avoid stack overflow on deep JSON
// ---------------------------------------------------------------------------

/** Max response candidates per request to prevent blowup */
const MAX_CANDIDATES_PER_REQUEST = 200;

/**
 * Collect all leaf values from a JSON object using an iterative approach.
 * @param {any} root
 * @returns {Array<{value:string, path:string, key:string}>}
 */
function collectJsonLeaves(root) {
  const out = [];
  if (root === null || root === undefined) return out;

  /** @type {Array<{node:any, path:string, parentKey:string}>} */
  const stack = [{ node: root, path: '$', parentKey: '' }];

  while (stack.length > 0) {
    const { node, path, parentKey } = stack.pop();

    if (node === null || node === undefined) continue;

    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) {
        stack.push({ node: node[i], path: `${path}[${i}]`, parentKey });
      }
      continue;
    }

    if (typeof node === 'object') {
      const entries = Object.entries(node);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [k, v] = entries[i];
        stack.push({ node: v, path: jsonPathForKey(path, k), parentKey: k });
      }
      continue;
    }

    if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
      out.push({ value: String(node), path, key: parentKey });
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Variable name guessing
// ---------------------------------------------------------------------------

/** Pre-compiled regex for ID-like keys */
const ID_KEY_REGEX = /(id|_id|uuid|token|code)$/;

/** Generic path segment names to skip when building variable names */
const GENERIC_NAMES = new Set([
  'data', 'items', 'item', 'result', 'results', 'response',
  'payload', 'body', 'content', 'value', 'values', 'list',
  'array', 'object', 'localdata',
]);

/**
 * @param {string} extractionPath
 * @returns {string|null}
 */
function guessVarNameFromExtractionPath(extractionPath) {
  if (!extractionPath) return null;

  const normalized = extractionPath
    .replace(/^\$\.?/, '')
    .replace(/\[(\d+)\]/g, '.')
    .replace(/\["([^"]+)"\]/g, '.$1')
    .replace(/\['([^']+)'\]/g, '.$1');

  const segments = normalized.split('.').filter(Boolean);
  if (segments.length === 0) return null;

  const lastSegment = segments[segments.length - 1];
  const lastLower = lastSegment.toLowerCase();

  if (lastLower === 'id' || lastLower === '_id') {
    for (let i = segments.length - 2; i >= 0; i--) {
      const segment = segments[i];
      if (!segment || /^\d+$/.test(segment) || GENERIC_NAMES.has(segment.toLowerCase())) {
        continue;
      }
      const cleaned = segment.replace(/[^a-zA-Z0-9]/g, '');
      if (cleaned) return `${cleaned}Id`;
    }
    return 'id';
  }

  return null;
}

/**
 * @param {string} key
 * @param {string} requestUrl
 * @param {string} [extractionPath]
 * @returns {string}
 */
function guessVarNameFromKeyAndUrl(key, requestUrl, extractionPath) {
  if (extractionPath) {
    const pathDerivedName = guessVarNameFromExtractionPath(extractionPath);
    if (pathDerivedName) return pathDerivedName;
  }

  const lower = (key || '').toLowerCase();
  if (lower === 'accesstoken') return 'accessToken';
  if (lower === 'refreshtoken') return 'refreshToken';
  if (lower === 'rolecode') return 'roleCode';
  if (lower === 'id' || lower === '_id') {
    const url = safeParseUrl(requestUrl);
    if (url) {
      const segments = url.pathname.split('/').filter(Boolean);
      const nonNumeric = segments.filter((s) => !/^\d+$/.test(s));
      const resource = nonNumeric[nonNumeric.length - 1] || 'resource';
      return `${singularize(resource)}Id`;
    }
    return 'id';
  }
  if (lower.includes('token')) return 'token';
  if (lower.includes('uuid')) return 'uuid';
  const cleaned = key.replace(/[^a-zA-Z0-9_]/g, '');
  return cleaned || 'var';
}

// ---------------------------------------------------------------------------
// Input mapper — converts raw network tab objects to interceptor format
// ---------------------------------------------------------------------------

/**
 * @param {Record<string,string>|null|undefined} headers
 * @returns {Array<{key:string, value:string}>}
 */
function headersObjectToArray(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return [];
  return Object.entries(headers).map(([key, value]) => ({
    key,
    value: String(value ?? ''),
  }));
}

/**
 * @param {string} url
 * @returns {Array<{key:string, value:string}>}
 */
function extractQueryParams(url) {
  try {
    const u = new URL(url);
    return Array.from(u.searchParams.entries()).map(([key, value]) => ({ key, value }));
  } catch {
    return [];
  }
}

/**
 * Converts NetworkTab request objects (from browser extension capture)
 * into the shape expected by `analyzeNetworkInterceptorRequests`.
 *
 * @param {any[]} requests
 * @returns {Array<Object>} Array of NetworkInterceptorCapturedRequest-shaped objects
 */
export function mapNetworkRequestsToInterceptorFormat(requests) {
  return (requests || []).map((req) => {
    const hasPayload =
      req.requestPayload &&
      req.requestPayload !== '[No payload]' &&
      req.requestPayload !== null;

    let bodyString = null;
    if (hasPayload) {
      bodyString =
        typeof req.requestPayload === 'string'
          ? req.requestPayload
          : JSON.stringify(req.requestPayload);
    }

    return {
      uniqueId: req.id || String(Math.random()),
      reqApiUrl: req.fullUrl || '',
      reqMethod: req.method || 'GET',
      timestamp: req.startTime || req.timestamp,
      status: req.status,
      requestData: {
        reqApiUrl: req.fullUrl || '',
        reqMethod: req.method || 'GET',
        reqBody: { reqData: bodyString },
        reqHeaders: headersObjectToArray(req.headers?.request),
        reqParams: extractQueryParams(req.fullUrl || ''),
      },
      responseData: {
        resHeaders: headersObjectToArray(req.headers?.response),
        responseBody: req.responseContent,
      },
    };
  });
}

// ---------------------------------------------------------------------------
// Core analysis
// ---------------------------------------------------------------------------

/**
 * Analyzes captured network requests and produces parameterized output.
 *
 * @param {Array<Object>} requests — NetworkInterceptorCapturedRequest-shaped objects
 * @returns {{ requests: Array<Object>, allExtractedParams: Array<Object> }}
 */
export function analyzeNetworkInterceptorRequests(requests) {
  const toFiniteNumber = (v) => {
    const n = typeof v === 'number' ? v : Number(v);
    return Number.isFinite(n) ? n : undefined;
  };

  // Normalize to chronological order
  const normalized = (requests || [])
    .map((r, idx) => ({ r, idx, ts: toFiniteNumber(r?.timestamp) }))
    .sort((a, b) => {
      if (a.ts !== undefined && b.ts !== undefined) return a.ts - b.ts;
      if (a.ts !== undefined) return -1;
      if (b.ts !== undefined) return 1;
      return a.idx - b.idx;
    })
    .map((x) => x.r);

  /** @type {Map<string, number>} */
  const producerIndexById = new Map();
  normalized.forEach((req, idx) => producerIndexById.set(req.uniqueId, idx));

  const parsed = normalized.map((r) => ({ r, url: safeParseUrl(r.reqApiUrl) }));

  // ---- Response-based extraction candidates ----

  /**
   * @typedef {{ value:string, key:string, extractionPath:string, producerUniqueId:string, paramNameGuess:string }} ResponseCandidate
   */

  /** @type {ResponseCandidate[]} */
  const responseCandidates = [];

  for (const r of normalized) {
    const responseObj = getResponseBodyObjectFromRequest(r);
    if (!responseObj) continue;

    const leaves = collectJsonLeaves(responseObj);
    let candidateCount = 0;

    for (const leaf of leaves) {
      if (candidateCount >= MAX_CANDIDATES_PER_REQUEST) break;

      const keyLower = (leaf.key || '').toLowerCase();
      if (!ID_KEY_REGEX.test(keyLower)) continue;

      // Filter noise
      if (!leaf.value) continue;
      if (keyLower.includes('token') && leaf.value.length < 6) continue;
      if (!keyLower.includes('token') && leaf.value.length > 500) continue;
      if (keyLower.includes('token') && leaf.value.length > 20000) continue;
      if (keyLower.includes('uuid') && leaf.value.length < 8) continue;

      if (keyLower.endsWith('code')) {
        const v = leaf.value.trim();
        if (v.length < 2 || v.length > 120) continue;
        if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(v)) continue;
        if (/^\d{2,4}$/.test(v)) continue;
      }

      responseCandidates.push({
        value: leaf.value,
        key: leaf.key,
        extractionPath: leaf.path,
        producerUniqueId: r.uniqueId,
        paramNameGuess: guessVarNameFromKeyAndUrl(leaf.key || 'var', r.reqApiUrl, leaf.path),
      });
      candidateCount++;
    }
  }

  // ---- Collect numeric path segment occurrences ----

  /**
   * @typedef {{ requestUniqueId:string, method:string, url:URL, idSegmentIndex:number, segments:string[], idValue:string }} Occurrence
   */

  /** @type {Occurrence[]} */
  const occurrences = [];
  for (const p of parsed) {
    if (!p.url) continue;
    const segments = p.url.pathname.split('/').filter(Boolean);
    segments.forEach((seg, idx) => {
      if (/^\d+$/.test(seg)) {
        occurrences.push({
          requestUniqueId: p.r.uniqueId,
          method: p.r.reqMethod,
          url: p.url,
          idSegmentIndex: idx,
          segments,
          idValue: seg,
        });
      }
    });
  }

  // Group by host + path template + idValue
  /** @param {Occurrence} o */
  const groupKey = (o) => {
    const templSegments = o.segments.map((s) => (/^\d+$/.test(s) ? ':id' : s));
    return `${o.url.host}|/${templSegments.join('/')}|${o.idValue}`;
  };

  /** @type {Map<string, Occurrence[]>} */
  const groups = new Map();
  for (const o of occurrences) {
    const key = groupKey(o);
    let list = groups.get(key);
    if (!list) {
      list = [];
      groups.set(key, list);
    }
    list.push(o);
  }

  // ---- Candidate variables from repeated numeric segments ----

  /** @type {Array<{name:string, producerRequestUniqueId:string, extractionPath:string, enabled:boolean}>} */
  const extractedParams = [];

  /** @type {Map<string, string>} idValue -> paramName */
  const idValueToParamName = new Map();

  /** @type {Map<string, string>} paramName -> producerUniqueId */
  const producerByParamName = new Map();

  for (const occs of groups.values()) {
    if (occs.length < 2) continue;

    const first = occs[0];
    const guessedName = guessVarNameFromPathSegments(first.segments, first.idSegmentIndex);
    let name = guessedName;
    let i = 2;
    while (extractedParams.some((p) => p.name === name)) {
      name = `${guessedName}${i++}`;
    }

    const host = first.url.host;
    const resourcePath = `/${first.segments
      .filter((_, idx) => idx !== first.idSegmentIndex)
      .join('/')}`;

    const producerCandidate = parsed
      .filter((p) => p.url?.host === host)
      .filter((p) => p.r.reqMethod?.toUpperCase() === 'POST')
      .find((p) => p.url?.pathname === resourcePath);

    const producerUniqueId = producerCandidate?.r.uniqueId ?? occs[0].requestUniqueId;

    extractedParams.push({
      name,
      producerRequestUniqueId: producerUniqueId,
      extractionPath: '$.id',
      enabled: true,
    });

    idValueToParamName.set(first.idValue, name);
    producerByParamName.set(name, producerUniqueId);
  }

  // ---- Track response-derived extracted params ----

  /** @type {Array<{name:string, producerRequestUniqueId:string, extractionPath:string, enabled:boolean}>} */
  const responseExtractedParams = [];

  /** @type {Map<string, string>} value -> paramName */
  const responseValueToParamName = new Map();

  /** @param {string} base */
  const ensureUniqueParamName = (base) => {
    const cleaned = (base || 'var').trim() || 'var';
    let candidate = cleaned;
    let i = 2;
    while (
      responseExtractedParams.some((p) => p.name === candidate) ||
      extractedParams.some((p) => p.name === candidate)
    ) {
      candidate = `${cleaned}${i++}`;
    }
    return candidate;
  };

  // ---- Build per-request models ----

  const perRequest = normalized.map((r) => {
    const originalUrl = r.reqApiUrl;
    const originalBody =
      typeof r.requestData?.reqBody?.reqData === 'string'
        ? r.requestData.reqBody.reqData
        : null;

    const originalHeaders = Array.isArray(r.requestData?.reqHeaders)
      ? r.requestData.reqHeaders.map((h) => ({
          key: String(h?.key ?? ''),
          value: String(h?.value ?? ''),
          enabled: h?.enabled,
        }))
      : [];

    let parameterizedUrl = originalUrl;
    let parameterizedBody = originalBody;
    let parameterizedHeaders = originalHeaders;

    /** @type {Array<{name:string, locations:Array<'url'|'body'|'headers'>}>} */
    const used = [];

    // 1) Response-based substitution (preferred) — sort longest-first
    const currentIdx = producerIndexById.get(r.uniqueId) ?? 0;
    const priorResponseCandidates = responseCandidates
      .filter((c) => (producerIndexById.get(c.producerUniqueId) ?? -1) < currentIdx)
      .sort((a, b) => b.value.length - a.value.length);

    for (const c of priorResponseCandidates) {
      const appearsInUrl = valueAppearsAsCompleteUrlComponent(parameterizedUrl, c.value);
      const appearsInBody =
        !!parameterizedBody && valueAppearsAsCompleteJsonValue(parameterizedBody, c.value);
      const appearsInHeaders = valueAppearsAsCompleteHeaderValue(parameterizedHeaders, c.value);
      if (!appearsInUrl && !appearsInBody && !appearsInHeaders) continue;

      let name = responseValueToParamName.get(c.value);
      if (!name) {
        const existingHeuristicName = /^\d+$/.test(c.value)
          ? idValueToParamName.get(c.value)
          : undefined;
        name = existingHeuristicName || ensureUniqueParamName(c.paramNameGuess);
        responseValueToParamName.set(c.value, name);
        if (/^\d+$/.test(c.value) && !idValueToParamName.has(c.value)) {
          idValueToParamName.set(c.value, name);
        }
        if (!extractedParams.some((p) => p.name === name)) {
          responseExtractedParams.push({
            name,
            producerRequestUniqueId: c.producerUniqueId,
            extractionPath: c.extractionPath || '$.id',
            enabled: true,
          });
        }
      }

      const placeholder = `{{${name}}}`;

      if (appearsInUrl) {
        parameterizedUrl = replaceInUrlBoundaryAware(parameterizedUrl, c.value, placeholder);
      }
      if (appearsInBody && parameterizedBody) {
        parameterizedBody = replaceInBodyBoundaryAware(parameterizedBody, c.value, placeholder);
      }
      if (appearsInHeaders) {
        parameterizedHeaders = replaceInHeadersBoundaryAware(
          parameterizedHeaders,
          c.value,
          placeholder
        );
      }

      /** @type {Array<'url'|'body'|'headers'>} */
      const locations = [];
      if (appearsInUrl) locations.push('url');
      if (appearsInBody) locations.push('body');
      if (appearsInHeaders) locations.push('headers');

      const existing = used.find((u) => u.name === name);
      if (existing) {
        existing.locations = Array.from(new Set([...existing.locations, ...locations]));
      } else {
        used.push({ name, locations });
      }
    }

    // 2) Heuristic fallback: numeric id segments in URLs
    const urlObj = safeParseUrl(originalUrl);
    if (urlObj) {
      const segments = urlObj.pathname.split('/').filter(Boolean);
      let currentPathname = urlObj.pathname;
      const numericSegments = segments.filter((s) => /^\d+$/.test(s));

      for (const idValue of numericSegments) {
        const name = idValueToParamName.get(idValue);
        if (!name) continue;
        const placeholder = `{{${name}}}`;

        currentPathname = replaceAllExactSegment(currentPathname, idValue, placeholder);
        parameterizedUrl = `${urlObj.origin}${currentPathname}${urlObj.search}${urlObj.hash}`;

        const bodyHasExactMatch = valueAppearsAsCompleteJsonValue(parameterizedBody, idValue);
        if (bodyHasExactMatch && parameterizedBody) {
          const newBody = replaceInBodyBoundaryAware(parameterizedBody, idValue, placeholder);
          if (newBody !== parameterizedBody) {
            parameterizedBody = newBody;
          }
        }

        const headersHaveExactMatch = valueAppearsAsCompleteHeaderValue(
          parameterizedHeaders,
          idValue
        );
        let headersChanged = false;
        if (headersHaveExactMatch) {
          const newHeaders = replaceInHeadersBoundaryAware(
            parameterizedHeaders,
            idValue,
            placeholder
          );
          headersChanged = newHeaders !== parameterizedHeaders;
          parameterizedHeaders = newHeaders;
        }

        /** @type {Array<'url'|'body'|'headers'>} */
        const locations = ['url'];
        if (parameterizedBody !== originalBody && parameterizedBody?.includes(placeholder)) {
          locations.push('body');
        }
        if (headersChanged) {
          locations.push('headers');
        }
        const existing = used.find((u) => u.name === name);
        if (existing) {
          existing.locations = Array.from(new Set([...existing.locations, ...locations]));
        } else {
          used.push({ name, locations });
        }
      }
    }

    return {
      uniqueId: r.uniqueId,
      originalUrl,
      parameterizedUrl,
      method: r.reqMethod,
      originalBody,
      parameterizedBody,
      originalHeaders,
      parameterizedHeaders,
      usedParams: used,
      extractedParams: [],
    };
  });

  // Second pass: attach extracted params to producer request
  const allExtractedParams = [...responseExtractedParams, ...extractedParams];
  const requestsWithExtracted = perRequest.map((r) => ({
    ...r,
    extractedParams: allExtractedParams.filter((p) => p.producerRequestUniqueId === r.uniqueId),
  }));

  return {
    requests: requestsWithExtracted,
    allExtractedParams,
  };
}

// ---------------------------------------------------------------------------
// Express Router factory
// ---------------------------------------------------------------------------

/** Route-level timeout (ms) */
const ROUTE_TIMEOUT_MS = 30_000;

/**
 * Creates an Express Router with `POST /analyze`.
 * @returns {import('express').Router}
 */
export function createParameterizationRouter() {
  const router = express.Router();

  router.post('/analyze', (req, res) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(504).json({ success: false, error: 'Analysis timed out (30s limit)' });
      }
    }, ROUTE_TIMEOUT_MS);

    try {
      const { networkRequests } = req.body || {};

      if (!Array.isArray(networkRequests) || networkRequests.length === 0) {
        clearTimeout(timer);
        return res.status(400).json({
          success: false,
          error: 'networkRequests must be a non-empty array',
        });
      }

      const start = Date.now();

      // Filter to Fetch/XHR only (server-side filtering)
      const xhrRequests = networkRequests.filter((r) => r.type === 'Fetch/XHR');

      if (xhrRequests.length === 0) {
        clearTimeout(timer);
        return res.status(400).json({
          success: false,
          error: 'No Fetch/XHR requests found in the provided data',
        });
      }

      const mapped = mapNetworkRequestsToInterceptorFormat(xhrRequests);
      const model = analyzeNetworkInterceptorRequests(mapped);
      const durationMs = Date.now() - start;

      clearTimeout(timer);

      return res.json({
        success: true,
        data: {
          requests: model.requests,
          allExtractedParams: model.allExtractedParams,
        },
        meta: {
          inputCount: networkRequests.length,
          analyzedCount: xhrRequests.length,
          paramCount: model.allExtractedParams.length,
          durationMs,
        },
      });
    } catch (err) {
      clearTimeout(timer);
      console.error('[parameterization] Analysis error:', err);
      if (!res.headersSent) {
        return res.status(500).json({
          success: false,
          error: err?.message || 'Internal analysis error',
        });
      }
    }
  });

  return router;
}


// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
