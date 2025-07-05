import aiosqlite
import asyncio
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_NAME = os.path.join(BASE_DIR, "classroom_app.db")

async def create_tables():
    """Creates all necessary tables in the SQLite database if they don't already exist."""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        # Users Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('superadmin', 'teacher', 'student'))
            )
        """)

        # Classrooms Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS Classrooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                teacher_id INTEGER NOT NULL,
                FOREIGN KEY (teacher_id) REFERENCES Users(id)
            )
        """)

        # Enrollments Table (linking students to classrooms)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS Enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                classroom_id INTEGER NOT NULL,
                FOREIGN KEY (student_id) REFERENCES Users(id),
                FOREIGN KEY (classroom_id) REFERENCES Classrooms(id),
                UNIQUE (student_id, classroom_id)
            )
        """)

        # Assignments Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS Assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                classroom_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                due_date TIMESTAMP,
                file_path TEXT,
                uploader_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (classroom_id) REFERENCES Classrooms(id),
                FOREIGN KEY (uploader_id) REFERENCES Users(id)
            )
        """)

        # Submissions Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS Submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL CHECK(status IN ('pending', 'submitted', 'completed', 'rejected')) DEFAULT 'submitted',
                FOREIGN KEY (assignment_id) REFERENCES Assignments(id),
                FOREIGN KEY (student_id) REFERENCES Users(id)
            )
        """)

        await db.commit()
    print(f"Database tables checked/created in {DATABASE_NAME}")

async def main():
    await create_tables()

if __name__ == "__main__":
    asyncio.run(main())
