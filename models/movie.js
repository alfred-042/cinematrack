const mongoose = require("mongoose");

const MovieSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    title: { type: String, required: true },
    category: { 
        type: String, 
        enum: ['watched', 'watching', 'want'],
        required: true 
    },
    poster: { type: String } // optional poster URL
}, { timestamps: true });

module.exports = mongoose.model("Movie", MovieSchema);
