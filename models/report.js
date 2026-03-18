module.exports = (conn) => {
  const mongoose = require("mongoose");

  const reportSchema = new mongoose.Schema({
    scanType: String,
    scanId: String,
    reportData: Object,
    createdAt: { type: Date, default: Date.now }
  });

  return conn.model("Report", reportSchema, "reports");
};
