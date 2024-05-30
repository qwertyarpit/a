const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Username cannot be blank"],
  },
  password: {
    type: String,
    required: [true, "Password cannot be blank"],
  },
  email: {
    type: String,
    required: [true, "Email cannot be blank"],
    unique: true,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

userSchema.statics.findAndValidate = async function (username, password) {
  const foundUser = await this.findOne({ username });
  if (!foundUser) return false;
  const isValid = await bcrypt.compare(password, foundUser.password);
  return isValid ? foundUser : false;
};

module.exports = mongoose.model("User", userSchema);
