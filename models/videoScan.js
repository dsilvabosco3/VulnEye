const mongoose = require("mongoose");

const videoScanSchema = new mongoose.Schema({
  target: String,
  type: String,
  severity: String,
  userId: String,
  username: String,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("VideoScan", videoScanSchema);
