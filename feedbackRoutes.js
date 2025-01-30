
const express = require('express');
const router = express.Router();
const { addFeedback, updateFeedbackStatus } = require('../controllers/feedbackController');
const { verifyToken } = require('../middlewares/verifyToken');

router.post('/feedback', verifyToken, addFeedback);

router.put('/feedback/:feedbackId', verifyToken, updateFeedbackStatus);

module.exports = router;
