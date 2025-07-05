# AnDShare - Classroom File Sharing Application

AnDShare is a web application designed for teachers and students to facilitate offline file sharing for assignments and submissions within a local network. It is built with Python using the `aiohttp` asynchronous web framework and SQLite for database storage.

## Current Status

The application is currently under a significant redesign:
*   **Core Authentication:** User authentication (login, logout, password change) and role management (superadmin, teacher, student) are implemented using a database backend.
*   **Database:** SQLite is used for data persistence (`classroom_app.db`).
*   **Classroom Features:** The core classroom, assignment, and submission functionalities are the next major development phase and are currently **not implemented**. Existing file operation endpoints are placeholders.
*   **Frontend:** Basic JavaScript structure for authentication and themes has been set up. UI for classroom features is pending.

## Features (Planned/In-Progress)

*   **User Roles:** Superadmin, Teacher, Student.
*   **Teacher Capabilities:**
    *   Create and manage classrooms.
    *   Enroll students in classrooms.
    *   Upload assignments to classrooms.
    *   View and mark student submissions.
*   **Student Capabilities:**
    *   View assignments in enrolled classrooms.
    *   Submit work for assignments.
    *   View submission status.
*   **Superadmin Capabilities:**
    *   Overall system management (details TBD).
    *   Access to all files (TBD).

## Setup and Installation

1.  **Clone the Repository (if applicable):**
    ```bash
    # git clone <repository-url>
    # cd <repository-directory>
    ```

2.  **Create a Virtual Environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    Make sure you have Python 3.8+ installed.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Database Setup:**
    The SQLite database (`classroom_app.db`) and necessary tables will be automatically created (if they don't exist) when you first run the server.

5.  **Configure Superadmin (Optional):**
    A default superadmin user is created on the first run with:
    *   Username: `superadmin`
    *   Password: `superadminpass`

    You can override these defaults by setting the following environment variables before the first run:
    *   `SUPERADMIN_USERNAME`: Your desired superadmin username.
    *   `SUPERADMIN_PASSWORD`: Your desired superadmin password.

## Running the Application

1.  **Start the Server:**
    ```bash
    python server.py
    ```
    The server will typically run on:
    *   Local: `http://localhost:1819`
    *   Network: `http://<your-local-ip>:1819` (The script will print the network IP)

2.  **Access the Application:**
    Open your web browser and navigate to the provided URL. You should be redirected to the login page.

## Development Notes

*   **Frontend JavaScript:** Main client-side JavaScript files are located in `static/js/`.
    *   `static/js/theme.js`: Handles theme (dark/light mode) toggling.
    *   `static/js/auth.js`: Handles authentication-related UI logic (login, password change, logout).
*   **Database Queries:** All database interaction logic is centralized in `db_queries.py`.
*   **Database Schema:** The database schema is defined and initialized by `db_setup.py` (called automatically on server start).
*   **Uploads:** Uploaded files are stored in the `uploads/` directory. The structure within this directory will be refined as classroom features are implemented.

## Future Development (High Level)

*   Implement full CRUD (Create, Read, Update, Delete) operations for Classrooms, Assignments, and Submissions via backend APIs.
*   Develop the frontend UI for teachers to manage classrooms and assignments.
*   Develop the frontend UI for students to view assignments and make submissions.
*   Refine file handling to associate uploads with specific assignments/submissions and manage permissions accordingly.
*   Implement robust error handling and user feedback on the frontend.
*   Write comprehensive unit and integration tests.
*   Consider security enhancements (e.g., more robust password hashing, CSRF protection if forms are used differently, input validation).

## Deployment (Production)

For a production environment, running the application with `python server.py` is not recommended. You should use a production-grade ASGI server such as Uvicorn or Hypercorn.

Example with Uvicorn:
```bash
# pip install uvicorn
uvicorn server:create_app --host 0.0.0.0 --port 1819 --factory
```
(Note: `server:create_app --factory` tells Uvicorn to use the `create_app` function as an application factory.)

Further production considerations would include setting up HTTPS, managing static files efficiently, and potentially using a more robust database if SQLite limitations are reached.
