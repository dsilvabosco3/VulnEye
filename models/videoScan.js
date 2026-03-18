module.exports = (conn) => {
  const mongoose = require("mongoose");

  const videoScanSchema = new mongoose.Schema({
    target: String,
    type: String,
    severity: String,
    userId: String,
    username: String,
    timestamp: { type: Date, default: Date.now }
  });

  return conn.model("VideoScan", videoScanSchema, "videoscans");
};
