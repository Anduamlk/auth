
const Feedback = require('../models/Feedback');
exports.addFeedback = async (req, res) => {
  const { feedback, customerId, requestId } = req.body;
  const divisionHeadId = req.user.id; 

  try {
    const newFeedback = new Feedback({
      divisionHeadId,
      customerId,
      requestId,
      feedback,
    });

    await newFeedback.save();

    return res.status(200).json({ message: 'Feedback sent successfully', feedback: newFeedback });
  } catch (error) {
    console.error('Error adding feedback:', error);
    return res.status(500).json({ message: 'Error adding feedback.' });
  }
};

exports.updateFeedbackStatus = async (req, res) => {
  const { feedbackId } = req.params; 
  try {
    const feedback = await Feedback.findByIdAndUpdate(
      feedbackId,
      { status: 'complete', updatedAt: Date.now() },
      { new: true }
    );

    if (!feedback) {
      return res.status(404).json({ message: 'Feedback not found.' });
    }

    return res.status(200).json({ message: 'Feedback status updated to complete', feedback });
  } catch (error) {
    console.error('Error updating feedback status:', error);
    return res.status(500).json({ message: 'Error updating feedback status.' });
  }
};
