-----

# 📝 Poll Generation API

[](https://nodejs.org/)
[](https://expressjs.com/)
[](https://www.typescriptlang.org/)
[](https://www.mongodb.com/cloud/atlas)
[](https://opensource.org/licenses/MIT)

## 📝 Project Description

This is a backend API built with Node.js, Express.js, and TypeScript, providing a robust user authentication and authorization system that can serve as the foundation for a **poll generation application**. It integrates with MongoDB Atlas for data persistence and includes features like user registration, login, JWT-based authentication, role-based access control (User/Admin), and a password reset mechanism.

## ✨ Features

  * **User Registration:** Create new user accounts with username, name, password, and user type.
  * **User Login:** Authenticate users and issue JSON Web Tokens (JWTs) for secure session management.
  * **JWT Authentication:** Protect API routes using JWTs, ensuring only authenticated users can access specific resources.
  * **Role-Based Access Control (RBAC):** Implement authorization middleware to restrict access based on user roles (e.g., `User` and `Admin`).
  * **Forgot Password:** Allows users to request a password reset via a simulated email link (console output).
  * **Reset Password:** Enables users to set a new password using a time-limited reset token.
  * **MongoDB Atlas Integration:** Persist user data securely in a cloud-hosted MongoDB database.
  * **Password Hashing:** Securely store passwords using `bcryptjs`.
  * **Clean Architecture:** Organized into modular components (config, middleware, models, routes).

## 🚀 Technologies Used

  * **Node.js**: JavaScript runtime environment.
  * **Express.js**: Fast, unopinionated, minimalist web framework for Node.js.
  * **TypeScript**: Typed superset of JavaScript that compiles to plain JavaScript.
  * **Mongoose**: MongoDB object modeling for Node.js, providing a straightforward, schema-based solution to model your application data.
  * **MongoDB Atlas**: Cloud-hosted MongoDB database service.
  * **Bcryptjs**: Library for hashing passwords.
  * **JSON Web Token (JWT)**: Used for secure authentication and information exchange.
  * **Dotenv**: Loads environment variables from a `.env` file.
  * **Nodemon**: Automatically restarts the Node.js application during development.
  * **Concurrently**: Runs multiple commands concurrently (for `npm run dev`).

-----

## 📁 Folder Structure

```
poll-generation/
├── src/
│   ├── app.ts                  # Main Express app setup
│   ├── config/
│   │   └── index.ts            # Application configurations (JWT secret, Mongo URI)
│   ├── db.ts                   # MongoDB connection logic
│   ├── middleware/
│   │   └── auth.ts             # Authentication and Authorization middleware
│   ├── models/
│   │   └── user.ts             # Mongoose User Schema and Model
│   ├── routes/
│   │   └── auth.ts             # Public routes (register, login, forgot/reset password)
│   │   └── protected.ts        # Protected routes requiring authentication/authorization
│   └── server.ts               # Entry point to start the server
├── package.json
├── tsconfig.json               # TypeScript configuration
└── .env                        # Environment variables (sensitive data)
```

-----

## ⚙️ Setup and Installation

Follow these steps to get the project up and running on your local machine.

### 1\. Clone the repository

```bash
git clone <your-repo-url> # Replace with your actual repository URL
cd poll-generation
```

### 2\. Install Dependencies

```bash
npm install
```

### 3\. Configure Environment Variables

Create a **`.env`** file in the root of your project and add the following variables.
**Important:** Replace placeholder values with your actual credentials.

```dotenv
TOKEN_SECRET=your_super_secret_jwt_key_CHANGE_THIS_TO_A_LONG_RANDOM_STRING
MONGO_URI=mongodb+srv://<username>:<password>@cluster0.abcde.mongodb.net/<dbname>?retryWrites=true&w=majority
PORT=3000
```

  * **`TOKEN_SECRET`**: A strong, random string used to sign your JWTs. Generate a long, complex one.
  * **`MONGO_URI`**: Your MongoDB Atlas connection string.
      * **MongoDB Atlas Setup**:
        1.  Create an account and a free tier cluster on [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
        2.  Navigate to **Database Access** under "Security" and create a new database user. Remember the username and password.
        3.  Go to **Network Access** under "Security" and add your current IP address (or `0.0.0.0/0` for development, but avoid this in production).
        4.  Click "Connect" on your cluster, choose "Connect your application," and copy the connection string. Replace `<username>`, `<password>`, and `<dbname>` in the URI with your details.
  * **`PORT`**: The port on which the server will run.

### 4\. Build TypeScript Code

Compile the TypeScript files into JavaScript:

```bash
npm run build
```

### 5\. Run the Server

**Development Mode (with hot-reloading):**

```bash
npm run dev
```

**Production Mode:**

```bash
npm start
```

The server will start on `http://localhost:3000` (or the port you specified in `.env`). You should see `MongoDB Atlas connected successfully!` in your console.

-----

## ⚡ API Endpoints

Use tools like Postman, Insomnia, or curl to test these endpoints.

### Authentication & Authorization Roles:

  * `user_type_id: 0` = **User**
  * `user_type_id: 1` = **Admin**

| Method | Endpoint | Description | Authentication | Authorization | Request Body | Response Example |
| :----- | :------- | :---------- | :------------- | :------------ | :----------- | :--------------- |
| `POST` | `/api/auth/register` | Registers a new user. | None | None | `{"username": "string", "name": "string", "password": "string", "user_type_id": number}` | `{"message": "Registration successful", "token": "jwt_token"}` |
| `POST` | `/api/auth/login` | Logs in a user and returns a JWT. | None | None | `{"username": "string", "password": "string"}` | `{"message": "Login successful", "token": "jwt_token"}` |
| `POST` | `/api/auth/forgot-password` | Requests a password reset link. | None | None | `{"username": "string"}` | `{"message": "If a user with that username exists, a password reset link has been sent."}` (Check server console for link) |
| `POST` | `/api/auth/reset-password` | Resets user password using a valid token. | None | None | `{"resetToken": "string", "newPassword": "string"}` | `{"message": "Password has been reset successfully."}` |
| `GET` | `/api/profile` | Fetches the authenticated user's profile. | Required | Any User | None | `{"message": "Your profile data.", "user": {...}}` |
| `GET` | `/api/events` | Accesses resources for regular users (can be adapted for user-specific polls). | Required | User (0) | None | `{"message": "Welcome, regular user! This is your event list.", "user": {...}}` |
| `GET` | `/api/special` | Accesses resources for administrators (can be adapted for poll management). | Required | Admin (1) | None | `{"message": "Welcome, admin! This is special admin content.", "user": {...}}` |

-----
