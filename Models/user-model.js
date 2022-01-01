const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "A user must have a name"],
  },
  email: {
    type: String,
    required: [true, "A user must have an email"],
    unique: true,
    validate: {
      validator: function (val) {
        return validator.isEmail(val);
      },
      message: "Invalid email",
    },
  },
  password: {
    type: String,
    required: [true, "A user must have a password"],
    minLength: [7, "Password must be at least 7 characters"],
    maxLength: [16, "Password must not exceed 16 characters"],
    select: false,
  },
  confirmPassword: {
    type: String,
    required: [true, "A user must confirm his password"],
    validate: {
      validator: function (val) {
        return this.password === val;
      },
      message: "Password didn't match",
    },
  },
  photo: {
    type: String,
    default: "default.jpg"
  },
  role: {
    type: String,
    enum: ["user", "admin", "guide", "lead-guide"],
    default: "user",
  },
  passwordChangedAt: Date,
  passwordChangeToken: String,
  passwordChangeTokenExpiresIn: Date,
  active: {
    default: true,
    type: Boolean,
    select: false,
  },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  this.confirmPassword = undefined;
});

userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

// Instance Method available on all user documents
userSchema.methods.correctPassword = async function (
  decodedPassword,
  encodedPassword
) {
  return await bcrypt.compare(decodedPassword, encodedPassword);
};

userSchema.methods.changedPasswordAfter = function (tokenIssuedAt) {
  if (this.passwordChangedAt) {
    const newPasswordChangedAt = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return tokenIssuedAt > newPasswordChangedAt;
  }

  return false;
};

userSchema.methods.generateToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordChangeToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordChangeTokenExpiresIn = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const userModel = mongoose.model("User", userSchema);

module.exports = userModel;
