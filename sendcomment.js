const express = require('express');
const router = express.Router();
const Comment = require('../models/comment');

// Route to post a comment
router.post('/comment', async (req, res) => {
  try {
    const { userId, commentText } = req.body;

    const newComment = new Comment({
      userId,
      commentText,
    });

    await newComment.save();
    res.status(201).json({ message: 'Comment posted successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Route to get comments (for display)
router.get('/comments/:userId', async (req, res) => {
  try {
    const comments = await Comment.find({ userId: req.params.userId });
    res.status(200).json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;