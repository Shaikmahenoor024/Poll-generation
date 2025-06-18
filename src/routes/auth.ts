// src/routes/auth.ts
import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import User, { IUser } from '../models/user'; // Import Mongoose User Model and IUser interface
import { JwtPayload } from '../middleware/auth'; // Import JwtPayload
import crypto from 'crypto';
import mongoose from 'mongoose'; // Import mongoose to use Types.ObjectId

const router = Router();

// Existing Registration Route
router.post('/register', async (req: Request, res: Response): Promise<any> => {
    const { username, name, password, user_type_id } = req.body;

    if (!username || !name || !password || user_type_id === undefined) {
        return res.status(400).send("All fields (username, name, password, user_type_id) are required.");
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).send("User with this username already exists.");
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user instance using the Mongoose model
        const newUser: IUser = new User({
            username,
            name,
            password: hashedPassword,
            user_type_id: parseInt(user_type_id, 10)
        });

        // Save the user to the database
        await newUser.save();

        // The newUser object will now definitely have an _id populated by Mongoose.
        // We can safely assert its type for the payload.
        const payload: JwtPayload = {
            id: (newUser._id as mongoose.Types.ObjectId).toString(), // Explicitly cast to ObjectId
            user_type_id: newUser.user_type_id
        };

        const token = jwt.sign(payload, config.TOKEN_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: "Registration successful", token });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send("Server error during registration.");
    }
});

// Existing Login Route - MODIFIED
router.post('/login', async (req: Request, res: Response): Promise<any> => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Username and password are required.");
    }

    try {
        // Find user by username
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).send("Invalid username or password.");
        }

        const validPass = await bcrypt.compare(password, user.password);

        if (!validPass) {
            return res.status(401).send("Invalid username or password.");
        }

        // Fix for 'user._id' is of type 'unknown'
        // Since we've already checked if (!user), we can safely assert that user is not null.
        // Mongoose Document type already includes _id, so direct access is usually fine,
        // but explicit casting or non-null assertion can satisfy stricter TS configs.
        const userId = (user._id as mongoose.Types.ObjectId).toString(); // Explicitly cast here
        // Alternatively, if you're certain, you can use the non-null assertion: user._id!.toString()
        // But explicit casting often provides better clarity for type reasons.

        const payload: JwtPayload = {
            id: userId,
            user_type_id: user.user_type_id
        };

        const token = jwt.sign(payload, config.TOKEN_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send("Server error during login.");
    }
});

// Forgot Password Request Route
router.post('/forgot-password', async (req: Request, res: Response) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).send("Username is required to reset password.");
    }

    try {
        const user = await User.findOne({ username });

        if (!user) {
            // For security, always send a generic success message
            // to prevent username enumeration attacks.
            return res.status(200).send("If a user with that username exists, a password reset link has been sent.");
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour in milliseconds

        // Update the user record in the database
        user.resetToken = resetToken;
        user.resetTokenExpiry = resetTokenExpiry;
        await user.save(); // Save changes to the database

        // --- Simulate Email Sending ---
        const resetLink = `http://localhost:${process.env.PORT || 3000}/api/auth/reset-password-page?token=${resetToken}`;
        console.log(`\n--- PASSWORD RESET LINK (FOR ${user.username}) ---`);
        console.log(`Please click this link to reset your password: ${resetLink}`);
        console.log('--------------------------------------------------\n');
        // In a real application, you'd use a service like Nodemailer here.
        // For example:
        // await sendEmail(user.email, 'Password Reset', `Click link: ${resetLink}`);

        res.status(200).send("If a user with that username exists, a password reset link has been sent.");

    } catch (error) {
        console.error("Forgot password error:", error);
        res.status(500).send("Server error during password reset request.");
    }
});

// Reset Password Route
router.post('/reset-password', async (req: Request, res: Response) => {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
        return res.status(400).send("Reset token and new password are required.");
    }

    try {
        const user = await User.findOne({ resetToken });

        if (!user) {
            return res.status(400).send("Invalid or expired reset token.");
        }

        // Check if the token has expired
        if (user.resetTokenExpiry && user.resetTokenExpiry < Date.now()) {
            // Clear the expired token
            user.resetToken = undefined;
            user.resetTokenExpiry = undefined;
            await user.save(); // Save updated user to clear expired token
            return res.status(400).send("Reset token has expired. Please request a new one.");
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;

        // Invalidate the reset token after use
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save(); // Save updated user with new password and invalidated token

        res.status(200).send("Password has been reset successfully.");
    } catch (error) {
        console.error("Reset password error:", error);
        res.status(500).send("Server error during password reset.");
    }
});

export default router;
