const express = require('express');
const { addComment } = require('../controllers/AuditRequestController');
const { verifyToken } = require('../middlewares/verifyToken');

const router = express.Router();

// Add comment route
router.post('/requests/:id/comment', verifyToken, addComment);

module.exports = router;
