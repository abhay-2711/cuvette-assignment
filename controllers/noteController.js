const Note = require('../models/Note');

const createNote = async (req, res, next) => {
    const {title, content} = req.body;
    const newNote = new Note({
        userId: req.user.id,
        title,
        content
    });
    try {
        await newNote.save();
        res.status(200).json(newNote);
    } catch (error) {
        // res.status(400).json({ message: error.message });
        next(error);
    }
}

const getAllNotes = async (req, res, next) => {
    const userId = req.user.id;
    try {
        const notes = await Note.find({ userId });
        res.status(200).json(notes);
    } catch (error) {
        next(error);
    }
}

const getNote = async (req, res, next) => {
    const noteId = req.params.id;
    const userId = req.user.id;
    try {
        const note = await Note.findById({_id: noteId, userId});
        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        if (note.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Unauthorized access to this note' });
        }
        res.status(200).json(note);
    } catch (error) {
        next(error);
    }
}

//update note
const updateNote = async (req, res, next) => {
    const noteId = req.params.id;
    const userId = req.user.id;
    const {title, content} = req.body;
    try {
        const note = await Note.findById({_id: noteId, userId});
        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        if (note.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Unauthorized access to this note' });
        }

        note.title = title;
        note.content = content;
        await note.save();

        res.status(200).json(note);
    } catch (error) {
        next(error);
    }
};

const deleteNote = async (req, res, next) => {
    const noteId = req.params.id;
    const userId = req.user.id;
    try {
        const note = await Note.findByIdAndDelete({_id: noteId, userId});
        if (!note) {
            return res.status(404).json({ message: 'Note not found' });
        }
        if (note.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Unauthorized access to this note' });
        }

        res.status(200).json({ message: 'Note deleted successfully' });
    } catch (error) {
        next(error);
    }
};

module.exports = {createNote, getAllNotes, getNote, updateNote, deleteNote};