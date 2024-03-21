# Authentication and Session Management

This application implements a secure login and session management system using Node.js, Express, bcrypt for password hashing, and express-session for session management.

## Features

- **User Registration and Login**: Users can register with a unique username and password. Passwords are hashed using bcrypt for security purposes. The login system checks for correct credentials before establishing a session.

- **Login Attempt Limit**: To prevent brute force attacks, the system limits the number of login attempts to 3. Upon reaching this limit, the user's account is locked for 3 minutes.

- **Blocked User Tracking**: The system maintains a `blockedUsers.json` file that records the usernames and IP addresses of users who have been locked out due to excessive login failures. This information is used to prevent further login attempts until the lockout period has expired.

- **Session Validation on Protected Routes**: Access to the `data.html` page is restricted to authenticated users. The system checks for a valid session before granting access. If a user tries to access `data.html` without being logged in, or after a failed login attempt, they are redirected to the login page.

- **Automatic Unblock**: An endpoint `/unblock/:username` is provided to manually unblock a user before the lockout period expires. The system also synchronizes the `loginAttempts` object in memory with the `blockedUsers.json` file to ensure consistency.

- **Direct URL Access Prevention**: The application prevents direct access to `data.html` via URL. Users are required to authenticate first; otherwise, they are redirected to the login page.

## Installation

To install the application, clone the repository and run `npm install` to install the necessary dependencies.

```bash
git clone [repository_url]
cd [repository_name]
npm install
