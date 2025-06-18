// src/config/index.ts
export const config = {
    TOKEN_SECRET: process.env.TOKEN_SECRET || 'aMc2sbSF0X_pJ8Je4hEQo_default_secret', // Use environment variable for secret
    MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/auth_db_fallback' // Fallback for local
};
