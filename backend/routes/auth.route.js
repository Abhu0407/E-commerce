import express from 'express';
import { login, logout, signup, refreshToken } from '../controllers/auth.controller.js';

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh-token", refreshToken);
// router.get("/profile", getProfile);

export default router;