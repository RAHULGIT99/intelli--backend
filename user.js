import mongoose from "mongoose";

const snippetSchema = new mongoose.Schema({
  code: { 
    type: String, 
    required: true 
  },
  title: { // Optional title from user
    type: String 
  },
  language: { // AI-detected language
    type: String 
  },
  aiSummary: { // AI-generated summary
    type: String 
  },
}, { timestamps: true }); // Adds createdAt and updatedAt

const userSchema = new mongoose.Schema({
  username: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  otp: { type: Number },
  snippets: [snippetSchema], // Embeds snippets in the user
});

export default mongoose.model("user_testapp", userSchema);