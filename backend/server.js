import express from 'express';
import dotenv from 'dotenv';
import { connectDB } from './lib/db.js';

import authRoute from './routes/auth.route.js';


dotenv.config();

const app = express();

app.use("/api/auth", authRoute)

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log('Server is running on http://localhost:' + PORT);
    connectDB();
});