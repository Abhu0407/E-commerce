import express from 'express';
import dotenv from 'dotenv';
import { connectDB } from './lib/db.js';
import cookieParser from 'cookie-parser';

import authRoute from './routes/auth.route.js';


dotenv.config();

const app = express();

app.use(express.json()); // allows you to parse the body of the request
app.use(cookieParser());

app.use("/api/auth", authRoute)

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log('Server is running on http://localhost:' + PORT);
    connectDB();
});