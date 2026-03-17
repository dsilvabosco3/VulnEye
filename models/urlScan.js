const mongoose = require("mongoose");

const urlScanSchema = new mongoose.Schema({
  target: String,
  type: String,
  severity: String,
  userId: String,
  username: String,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("UrlScan", urlScanSchema);
