// src/routes/protected.ts
import { Router, Request, Response } from 'express';
import { verifyUserToken, IsUser, IsAdmin } from '../middleware/auth';
import { JwtPayload } from '../middleware/auth'; // Ensure JwtPayload is imported from auth

const router = Router();

router.get('/events', verifyUserToken, IsUser, (req: Request, res: Response) => {
    res.status(200).json({
        message: "Welcome, regular user! This is your event list.",
        user: req.user
    });
});

router.get('/special', verifyUserToken, IsAdmin, (req: Request, res: Response) => {
    res.status(200).json({
        message: "Welcome, admin! This is special admin content.",
        user: req.user
    });
});

router.get('/profile', verifyUserToken, (req: Request, res: Response) => {
    res.status(200).json({
        message: "Your profile data.",
        user: req.user
    });
});

export default router;
