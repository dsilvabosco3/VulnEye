const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema({
  scanType: String,
  scanId: String,
  reportData: Object,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Report", reportSchema);
