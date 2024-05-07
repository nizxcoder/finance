const mongoose = require("mongoose");

const user = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^[a-zA-Z0-9_]+$/.test(v);
      },
      message: (props) => `${props.value} is not a valid username!`,
    },
  },
  firstname: {
    type: String,
    required: true,
  },
  lastname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    // Add email format validation
    validate: {
      validator: function (v) {
        return /\S+@\S+\.\S+/.test(v);
      },
      message: (props) => `${props.value} is not a valid email address!`,
    },
  },
  otp: {
    type: String,
    required: false,
    default: "0000", // Set a default value
  },
  email_verified: {
    type: Boolean,
    required: false,
    default: false, // Set a default value
  },
  password: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        // Example: Password must contain at least 8 characters, including at least one uppercase letter, one lowercase letter, and one number
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(v);
      },
      message: (props) => `${props.value} is not a valid password!`,
    },
  },
  profilePic: {
    type: String,
    required: false,
    default: "default.jpg", // Set a default value
  },
  dob: {
    type: Date,
    required: true,
  },
  gender: {
    type: String,
    required: true,
    default: "Unknown", // Set a default value
    enum: ["Male", "Female", "Other", "Unknown"], // Add enum validation
  },
  phone: {
    type: String,
    required: true,
    // Add phone number format validation
    validate: {
      validator: function (v) {
        return /\d{3}-\d{3}-\d{4}/.test(v);
      },
      message: (props) => `${props.value} is not a valid phone number!`,
    },
  },
  address: {
    city: {
      type: String,
      required: true,
    },
    country: {
      type: String,
      required: true,
    },
    postalCode: {
      type: String,
      required: true,
    },
    street: {
      type: String,
      required: true,
    },
  },
});

// Example of setting index
// newUser.index({ email: 1 });

// Example of using virtuals
// newUser.virtual('fullName').get(function() {
//   return this.firstName + ' ' + this.lastName;
// });

const User = mongoose.model("User", user);

module.exports = User;
