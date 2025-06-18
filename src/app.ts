// src/app.ts
import express from 'express';
import authRoutes from './routes/auth';
import protectedRoutes from './routes/protected';

const app = express();

app.use(express.json());

// API Routes
app.use('/api/auth', authRoutes); // Routes for login and registration
app.use('/api', protectedRoutes); // Routes that require authentication

export default app;
