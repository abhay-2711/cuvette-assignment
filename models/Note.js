const mongoose = require('mongoose');

const NoteSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },
    title: {
        type: String,
        required: [true, 'Please enter a title'],
        maxLength: [200, 'Title cannot be more than 200 characters']
    },
    content: {
        type: String,
        required: [true, 'Please enter some content'],
    },
    
}, { timestamps: true });

const Note = mongoose.model('Note', NoteSchema);

module.exports = Note;