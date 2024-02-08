const express = require('express');
const router = express.Router();
const verifyToken = require('../utils/verifyToken');
const {createNote, getAllNotes, getNote, updateNote, deleteNote} = require('../controllers/noteController');

router.use(verifyToken);

router.post('/createNote', createNote);
router.get('/getAllNotes', getAllNotes);
router.get('/getNote/:id', getNote);
router.put('/updateNote/:id', updateNote);
router.delete('/deleteNote/:id', deleteNote);

module.exports = router;