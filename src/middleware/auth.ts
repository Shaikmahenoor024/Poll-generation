// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';

// Define JwtPayload here, with 'id' as string
export interface JwtPayload {
    id: string; // Changed from number to string to match MongoDB ObjectId.toString()
    user_type_id: number;
    iat?: number;
    exp?: number;
}

// Extend the Request interface to include the 'user' property
declare global {
    namespace Express {
        interface Request {
            user?: JwtPayload;
        }
    }
}

export const verifyUserToken = (req: Request, res: Response, next: NextFunction): any => {
    let token = req.headers.authorization;

    if (!token) {
        return res.status(401).send("Access Denied / Unauthorized request: No token provided.");
    }

    try {
        token = token.split(' ')[1];

        if (!token) {
            return res.status(401).send('Unauthorized request: Malformed token header.');
        }

        const verifiedUser = jwt.verify(token, config.TOKEN_SECRET) as JwtPayload;

        if (!verifiedUser) {
            return res.status(401).send('Unauthorized request: Invalid token.');
        }

        req.user = verifiedUser;
        next();
    } catch (error) {
        console.error("Token verification error:", error);
        return res.status(400).send("Invalid Token.");
    }
};

export const IsUser = (req: Request, res: Response, next: NextFunction): any => {
    if (!req.user) {
        return res.status(401).send("Unauthorized! User information not found.");
    }
    // Assuming user_type_id 0 is for regular users
    if (req.user.user_type_id === 0) {
        return next();
    }
    return res.status(403).send("Forbidden! Requires User role.");
};

export const IsAdmin = (req: Request, res: Response, next: NextFunction): any => {
    if (!req.user) {
        return res.status(401).send("Unauthorized! User information not found.");
    }
    // Assuming user_type_id 1 is for administrators
    if (req.user.user_type_id === 1) {
        return next();
    }
    return res.status(403).send("Forbidden! Requires Admin role.");
};
