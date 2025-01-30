
const express = require('express');
const mongoose = require('mongoose');
const feedbackRoutes = require('./routes/feedbackRoutes');
const cors = require('cors');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const Feedback =require('./models/Feedback')
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('MongoDB connection error:', err));

app.use(bodyParser.json()); 
app.use('/api', feedbackRoutes); 

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
