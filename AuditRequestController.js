const Request = require('../models/Request');

const addComment = async (req, res) => {
  try {
    const { id } = req.params;
    const { comment } = req.body;

    if (!comment) return res.status(400).json({ message: 'Comment cannot be empty' });

    const request = await Request.findById(id);
    if (!request) return res.status(404).json({ message: 'Request not found' });

    request.comments.push({
      text: comment,
      user: req.user.id, // User info from verifyToken middleware
    });

    await request.save();
    res.status(200).json({ message: 'Comment added successfully', comments: request.comments });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

module.exports = { addComment };
