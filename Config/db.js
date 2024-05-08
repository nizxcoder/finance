const mongoose = require('mongoose');
// const uri = "mongodb://127.0.0.1:27017/finance";
require('dotenv').config();
const uri = process.env.MONGO_URI;
const dbConnect = async () => {
  try {
    await mongoose.connect(uri);
    console.log('Connected to the database');
  } catch (error) {
    console.error('Error connecting to the database');
    console.error(error);
  }
};

module.exports = dbConnect;
