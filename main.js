import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import userModel from "./user.js";
import { TransactionalEmailsApi, SendSmtpEmail } from "@getbrevo/brevo";

dotenv.config();
const app = express();
app.use(express.json());

// Allow ALL origins and handle preflight requests
app.use(
  cors({
    origin: "*", // allows all origins
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  })
);

// Handle OPTIONS (preflight)
app.options('/*', cors());
app.use(cookieParser());

//  MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const JWT_SECRET = process.env.JWT_SECRET;

const GROQ_KEYS = [
  process.env.GROQ_API_KEY_1,
  process.env.GROQ_API_KEY_2,
  process.env.GROQ_API_KEY_3,
].filter(Boolean);

if (GROQ_KEYS.length === 0) {
  console.warn("No GROQ API keys found in .env. AI features will fail.");
}

let emailAPI = new TransactionalEmailsApi();
emailAPI.authentications.apiKey.apiKey = process.env.BREVO_API_KEY;

// --- Helper Function to Shuffle Keys ---
function shuffleArray(array) {
  let shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// --- Groq AI Helper : Randomized Key Rotation & Logging ---
async function callGroqAPI(prompt) {
  const shuffledKeys = shuffleArray(GROQ_KEYS);
  
  for (const key of shuffledKeys) {
    console.log(`Attempting Groq API call with key ending in: ...${key.slice(-4)}`);
    try {
      const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "llama-3.1-8b-instant",
          messages: [{ role: "user", content: prompt }],
        }),
      });

      if (!resp.ok) {
        throw new Error(`API request failed with status ${resp.status}`);
      }

      const data = await resp.json();
      console.log(`✅ Success with key ...${key.slice(-4)}`);
      return data.choices[0].message.content;

    } catch (error) {
      console.warn(`Groq key ending in ...${key.slice(-4)} failed:`, error.message);
    }
  }
  console.error("🚨 All Groq API keys failed for this request.");
  throw new Error("All Groq API keys failed.");
}

// --- Auth Middleware ---
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (token == null) return res.sendStatus(401); 

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await userModel.findOne({ email: decoded.email }).select("_id");
    if (!user) {
      return res.sendStatus(404);
    }
    req.user = user; 
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
};


app.get("/", (req, res) => {
  res.json({ message: "Hello" });
});



//  Register + otp generation
app.post("/register", async (req, res) => {
  const { username, email } = req.body;
  try {
    const existingUser = await userModel.findOne({
      email,
      otp: { $exists: false },
    });
    if (existingUser)
      return res.status(400).json({ message: "User already registered" });

    const otp = Math.floor(100000 + Math.random() * 900000);
    await userModel.updateOne({ email }, { username, email, otp }, { upsert: true });

    const msg = new SendSmtpEmail();
    msg.subject = "Your Verification OTP";
    msg.textContent = `Your OTP is ${otp}`;
    msg.sender = { email: "rahulvalavoju123@gmail.com" };
    msg.to = [{ email }];
    await emailAPI.sendTransacEmail(msg);

    console.log(`✅ OTP sent to ${email}: ${otp}`);
    res.status(200).json({ message: "OTP sent to email" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Error sending OTP" });
  }
});

//  Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp, password } = req.body;
  try {
    const tempUser = await userModel.findOne({ email });
    if (!tempUser?.otp) return res.status(404).json({ message: "No OTP record" });

    if (parseInt(otp) !== tempUser.otp)
      return res.status(400).json({ message: "Invalid OTP" });

    const hash = await bcrypt.hash(password, 10);
    const updatedUser = await userModel.findOneAndUpdate(
      { email },
      { $set: { password: hash }, $unset: { otp: "" } },
      { new: true }
    );

    const token = jwt.sign({ email: updatedUser.email }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.status(201).json({
      message: "Verified successfully",
      token,
      user: { username: updatedUser.username, email: updatedUser.email },
    });
  } catch (err) {
    console.error("OTP verify error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//  Login
app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;
  try {
    const user = await userModel.findOne({
      $or: [{ email: identifier }, { username: identifier }],
      otp: { $exists: false },
    });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ email: user.email }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.status(200).json({
      message: "Login successful",
      token,
      user: { username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});




app.get("/api/snippets", authenticateToken, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id).select("snippets");
    const sortedSnippets = user.snippets.sort((a, b) => b.createdAt - a.createdAt);
    res.status(200).json(sortedSnippets);
  } catch (err) {
    console.error("Fetch snippets error:", err);
    res.status(500).json({ message: "Error fetching snippets" });
  }
});


app.post("/api/snippets", authenticateToken, async (req, res) => {
  const { code, title } = req.body;
  if (!code) return res.status(400).json({ message: "Code cannot be empty" });

  try {
    const aiPrompt = `
      Analyze the following code snippet.
      Return *only* a valid JSON object (no other text) with two keys:
      1. "language": The programming language (e.g., "Python", "JavaScript", "CSS").
      2. "aiSummary": A very brief, half-line summary (around 5-10 words) of what the code does.

      Code:
      \`\`\`
      ${code}
      \`\`\`
    `;
    
    const aiResponse = await callGroqAPI(aiPrompt);
    const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
    if (!jsonMatch || !jsonMatch[0]) {
      throw new Error("AI did not return a valid JSON object.");
    }
    const jsonString = jsonMatch[0];
    const { language, aiSummary } = JSON.parse(jsonString);

    const newSnippet = {
      code,
      title: title || undefined,
      language,
      aiSummary,
    };

    const user = await userModel.findById(req.user.id);
    user.snippets.push(newSnippet);
    await user.save();

    res.status(201).json(user.snippets[user.snippets.length - 1]);

  } catch (err) {
    console.error("Create snippet error:", err);
    res.status(500).json({ message: "Error saving snippet or contacting AI" });
  }
});


app.delete("/api/snippets/:id", authenticateToken, async (req, res) => {
  try {
    const snippetId = req.params.id;
    const user = await userModel.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.snippets.pull({ _id: snippetId });
    await user.save();
    
    res.status(200).json({ message: "Snippet deleted successfully" });

  } catch (err) {
    console.error("Delete snippet error:", err);
    res.status(500).json({ message: "Error deleting snippet" });
  }
});


app.post("/api/snippets/analyze", authenticateToken, async (req, res) => {
  const { code, action, customInput } = req.body;

  let aiPrompt = "";


  switch (action) {
    case "findBugs":
      aiPrompt = `Find the top 3-5 most critical bugs or potential improvements in this code. 
      Respond *only* in a simple markdown bulleted list (using *). 
      Do not use any headings or bold text.

      Code:
      \`\`\`${code}\`\`\``;
      break;
    case "explainCode":
      aiPrompt = `Explain this code in a single, simple paragraph. 
      Keep it high-level and easy to understand.
      Do not use markdown, bolding, lists, or headings.

      Code:
      \`\`\`${code}\`\`\``;
      break;
    case "custom":
      if (!customInput) {
        return res.status(400).json({ message: "Custom input is required" });
      }
      aiPrompt = `${customInput}\n\nCode:\n\`\`\`${code}\`\`\``;
      break;
    default:
      return res.status(400).json({ message: "Invalid action" });
  }

  try {
    const aiResponse = await callGroqAPI(aiPrompt);
    res.status(200).json({ response: aiResponse });
  } catch (err) {
    console.error("Analyze code error:", err);
    res.status(500).json({ message: "Error analyzing code with AI" });
  }
});



app.listen(3001, () => console.log("Server running on port 3001"));