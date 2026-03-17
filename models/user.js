module.exports = (conn) => {
  const mongoose = require("mongoose");

  const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: String,
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  });

  return conn.model("User", userSchema, "users");
};
