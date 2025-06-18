// src/models/user.ts
import mongoose, { Document, Schema } from 'mongoose';

// 1. Extend the User interface to include Mongoose Document properties
export interface IUser extends Document {
    username: string;
    name: string;
    password: string;
    user_type_id: number;
    resetToken?: string;
    resetTokenExpiry?: number; // Unix timestamp
}

// 2. Define the Mongoose Schema
const UserSchema: Schema = new Schema({
    username: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String, required: true },
    user_type_id: { type: Number, required: true, default: 0 }, // 0 for user, 1 for admin
    resetToken: { type: String },
    resetTokenExpiry: { type: Number }
}, {
    timestamps: true // Adds createdAt and updatedAt fields
});

// 3. Create and export the Mongoose Model
const User = mongoose.model<IUser>('User', UserSchema);

export default User; // Export the Mongoose Model
