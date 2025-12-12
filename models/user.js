const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },

    // Untuk user yang daftar manual
    password: { type: String, required: false },

    // Untuk user yang login via Google
    googleId: { type: String, required: false },

    // Nama user
    name: { type: String, required: false }
});

module.exports = mongoose.model("User", UserSchema);
