import aiosqlite
import os
import logging
import hashlib # For password hashing

# Configure logging
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_NAME = os.path.join(BASE_DIR, "classroom_app.db")

# --- Utility Functions ---
def hash_password(password):
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# --- User Management ---
async def add_user(username, password, role):
    """Adds a new user to the Users table."""
    password_hash = hash_password(password)
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            await db.execute(
                "INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            await db.commit()
            logger.info(f"User {username} added with role {role}.")
            return True
    except aiosqlite.IntegrityError:
        logger.error(f"Username {username} already exists.")
        return False
    except Exception as e:
        logger.error(f"Error adding user {username}: {e}")
        return False

async def get_user_by_username(username):
    """Retrieves a user by their username."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, username, password_hash, role FROM Users WHERE username = ?", (username,)) as cursor:
                user = await cursor.fetchone()
                if user:
                    return {"id": user[0], "username": user[1], "password_hash": user[2], "role": user[3]}
                return None
    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        return None

async def get_user_by_id(user_id):
    """Retrieves a user by their ID."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, username, password_hash, role FROM Users WHERE id = ?", (user_id,)) as cursor:
                user = await cursor.fetchone()
                if user:
                    return {"id": user[0], "username": user[1], "password_hash": user[2], "role": user[3]}
                return None
    except Exception as e:
        logger.error(f"Error fetching user by ID {user_id}: {e}")
        return None

async def update_user_password(username, new_password):
    """Updates a user's password."""
    new_password_hash = hash_password(new_password)
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            await db.execute(
                "UPDATE Users SET password_hash = ? WHERE username = ?",
                (new_password_hash, username)
            )
            await db.commit()
            logger.info(f"Password updated for user {username}.")
            return True
    except Exception as e:
        logger.error(f"Error updating password for user {username}: {e}")
        return False

# --- Classroom Management ---
async def create_classroom(name, description, teacher_id):
    """Creates a new classroom."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            cursor = await db.execute(
                "INSERT INTO Classrooms (name, description, teacher_id) VALUES (?, ?, ?)",
                (name, description, teacher_id)
            )
            await db.commit()
            classroom_id = cursor.lastrowid
            logger.info(f"Classroom '{name}' created with ID {classroom_id} by teacher ID {teacher_id}.")
            return classroom_id
    except Exception as e:
        logger.error(f"Error creating classroom '{name}': {e}")
        return None

async def get_classrooms_for_teacher(teacher_id):
    """Retrieves all classrooms managed by a specific teacher."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, name, description FROM Classrooms WHERE teacher_id = ?", (teacher_id,)) as cursor:
                classrooms = await cursor.fetchall()
                return [{"id": row[0], "name": row[1], "description": row[2]} for row in classrooms]
    except Exception as e:
        logger.error(f"Error fetching classrooms for teacher ID {teacher_id}: {e}")
        return []

async def get_classroom_by_id(classroom_id):
    """Retrieves a classroom by its ID."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, name, description, teacher_id FROM Classrooms WHERE id = ?", (classroom_id,)) as cursor:
                classroom = await cursor.fetchone()
                if classroom:
                    return {"id": classroom[0], "name": classroom[1], "description": classroom[2], "teacher_id": classroom[3]}
                return None
    except Exception as e:
        logger.error(f"Error fetching classroom by ID {classroom_id}: {e}")
        return None

# --- Enrollment Management ---
async def enroll_student_in_classroom(student_id, classroom_id):
    """Enrolls a student in a classroom."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            await db.execute(
                "INSERT INTO Enrollments (student_id, classroom_id) VALUES (?, ?)",
                (student_id, classroom_id)
            )
            await db.commit()
            logger.info(f"Student ID {student_id} enrolled in classroom ID {classroom_id}.")
            return True
    except aiosqlite.IntegrityError: # Handles UNIQUE constraint violation
        logger.warning(f"Student ID {student_id} already enrolled in classroom ID {classroom_id} or invalid IDs.")
        return False
    except Exception as e:
        logger.error(f"Error enrolling student ID {student_id} in classroom ID {classroom_id}: {e}")
        return False

async def get_student_enrollments(student_id):
    """Retrieves all classrooms a student is enrolled in."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            query = """
                SELECT c.id, c.name, c.description
                FROM Enrollments e
                JOIN Classrooms c ON e.classroom_id = c.id
                WHERE e.student_id = ?
            """
            async with db.execute(query, (student_id,)) as cursor:
                enrollments = await cursor.fetchall()
                return [{"id": row[0], "name": row[1], "description": row[2]} for row in enrollments]
    except Exception as e:
        logger.error(f"Error fetching enrollments for student ID {student_id}: {e}")
        return []

async def get_students_in_classroom(classroom_id):
    """Retrieves all students enrolled in a specific classroom."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            query = """
                SELECT u.id, u.username
                FROM Enrollments e
                JOIN Users u ON e.student_id = u.id
                WHERE e.classroom_id = ?
            """
            async with db.execute(query, (classroom_id,)) as cursor:
                students = await cursor.fetchall()
                return [{"id": row[0], "username": row[1]} for row in students]
    except Exception as e:
        logger.error(f"Error fetching students for classroom ID {classroom_id}: {e}")
        return []

# --- Assignment Management ---
async def create_assignment(classroom_id, title, description, due_date, file_path, uploader_id):
    """Creates a new assignment."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            cursor = await db.execute(
                """INSERT INTO Assignments
                   (classroom_id, title, description, due_date, file_path, uploader_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (classroom_id, title, description, due_date, file_path, uploader_id)
            )
            await db.commit()
            assignment_id = cursor.lastrowid
            logger.info(f"Assignment '{title}' created with ID {assignment_id} in classroom ID {classroom_id}.")
            return assignment_id
    except Exception as e:
        logger.error(f"Error creating assignment '{title}': {e}")
        return None

async def get_assignments_for_classroom(classroom_id):
    """Retrieves all assignments for a specific classroom."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            query = """
                SELECT a.id, a.title, a.description, a.due_date, a.file_path, u.username as uploader_name, a.created_at
                FROM Assignments a
                JOIN Users u ON a.uploader_id = u.id
                WHERE a.classroom_id = ?
                ORDER BY a.created_at DESC
            """
            async with db.execute(query, (classroom_id,)) as cursor:
                assignments = await cursor.fetchall()
                return [
                    {
                        "id": row[0], "title": row[1], "description": row[2],
                        "due_date": row[3], "file_path": row[4], "uploader_name": row[5],
                        "created_at": row[6]
                    } for row in assignments
                ]
    except Exception as e:
        logger.error(f"Error fetching assignments for classroom ID {classroom_id}: {e}")
        return []

async def get_assignment_by_id(assignment_id):
    """Retrieves an assignment by its ID."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, classroom_id, title, description, due_date, file_path, uploader_id FROM Assignments WHERE id = ?", (assignment_id,)) as cursor:
                assignment = await cursor.fetchone()
                if assignment:
                    return {
                        "id": assignment[0], "classroom_id": assignment[1], "title": assignment[2],
                        "description": assignment[3], "due_date": assignment[4],
                        "file_path": assignment[5], "uploader_id": assignment[6]
                    }
                return None
    except Exception as e:
        logger.error(f"Error fetching assignment by ID {assignment_id}: {e}")
        return None

# --- Submission Management ---
async def create_submission(assignment_id, student_id, file_path):
    """Creates a new submission for an assignment."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            cursor = await db.execute(
                "INSERT INTO Submissions (assignment_id, student_id, file_path, status) VALUES (?, ?, ?, 'submitted')",
                (assignment_id, student_id, file_path)
            )
            await db.commit()
            submission_id = cursor.lastrowid
            logger.info(f"Submission ID {submission_id} created for assignment ID {assignment_id} by student ID {student_id}.")
            return submission_id
    except Exception as e:
        logger.error(f"Error creating submission for assignment ID {assignment_id} by student ID {student_id}: {e}")
        return None

async def get_submissions_for_assignment(assignment_id):
    """Retrieves all submissions for a specific assignment."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            query = """
                SELECT s.id, s.student_id, u.username as student_name, s.file_path, s.submission_date, s.status
                FROM Submissions s
                JOIN Users u ON s.student_id = u.id
                WHERE s.assignment_id = ?
                ORDER BY s.submission_date DESC
            """
            async with db.execute(query, (assignment_id,)) as cursor:
                submissions = await cursor.fetchall()
                return [
                    {
                        "id": row[0], "student_id": row[1], "student_name": row[2],
                        "file_path": row[3], "submission_date": row[4], "status": row[5]
                    } for row in submissions
                ]
    except Exception as e:
        logger.error(f"Error fetching submissions for assignment ID {assignment_id}: {e}")
        return []

async def get_submission_by_id(submission_id):
    """Retrieves a submission by its ID."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            async with db.execute("SELECT id, assignment_id, student_id, file_path, submission_date, status FROM Submissions WHERE id = ?", (submission_id,)) as cursor:
                submission = await cursor.fetchone()
                if submission:
                    return {
                        "id": submission[0], "assignment_id": submission[1], "student_id": submission[2],
                        "file_path": submission[3], "submission_date": submission[4], "status": submission[5]
                    }
                return None
    except Exception as e:
        logger.error(f"Error fetching submission by ID {submission_id}: {e}")
        return None

async def get_submissions_by_student_for_assignment(assignment_id, student_id):
    """Retrieves submissions made by a specific student for a specific assignment."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            query = """
                SELECT id, file_path, submission_date, status
                FROM Submissions
                WHERE assignment_id = ? AND student_id = ?
                ORDER BY submission_date DESC
            """
            async with db.execute(query, (assignment_id, student_id)) as cursor:
                submissions = await cursor.fetchall()
                return [
                    {"id": row[0], "file_path": row[1], "submission_date": row[2], "status": row[3]}
                    for row in submissions
                ]
    except Exception as e:
        logger.error(f"Error fetching submissions for assignment {assignment_id} by student {student_id}: {e}")
        return []

async def update_submission_status(submission_id, status):
    """Updates the status of a submission."""
    try:
        async with aiosqlite.connect(DATABASE_NAME) as db:
            await db.execute(
                "UPDATE Submissions SET status = ? WHERE id = ?",
                (status, submission_id)
            )
            await db.commit()
            logger.info(f"Status for submission ID {submission_id} updated to {status}.")
            return True
    except Exception as e:
        logger.error(f"Error updating status for submission ID {submission_id}: {e}")
        return False

# TODO: Add more query functions as needed for classroom management, enrollments, assignments, and submissions.
# For example:
# - Get all files uploaded by a specific user (teacher for assignments, student for submissions)
# - Functions to delete classrooms, assignments, submissions (with appropriate checks)
# - Functions to update classroom/assignment details.
# - Functions to remove a student from a classroom.

# Example of how to use (for testing this file directly):
# async def _test_db():
#     # Ensure tables are created
#     from db_setup import create_tables as setup_db_tables
#     await setup_db_tables()

#     # Test user functions
#     await add_user("teacher1", "pass123", "teacher")
#     await add_user("student1", "pass456", "student")
#     user_t = await get_user_by_username("teacher1")
#     user_s = await get_user_by_username("student1")
#     print("Teacher:", user_t)
#     print("Student:", user_s)

#     if user_t and user_s:
#         # Test classroom functions
#         classroom_id = await create_classroom("Math 101", "Intro to Algebra", user_t['id'])
#         print("Classroom ID:", classroom_id)
#         if classroom_id:
#             classrooms = await get_classrooms_for_teacher(user_t['id'])
#             print("Teacher's classrooms:", classrooms)

#             # Test enrollment
#             await enroll_student_in_classroom(user_s['id'], classroom_id)
#             student_enrolls = await get_student_enrollments(user_s['id'])
#             print("Student's enrollments:", student_enrolls)
#             students_in_class = await get_students_in_classroom(classroom_id)
#             print("Students in Math 101:", students_in_class)

#             # Test assignments
#             assignment_id = await create_assignment(classroom_id, "Homework 1", "Chapter 1 problems", None, "/path/to/hw1.pdf", user_t['id'])
#             print("Assignment ID:", assignment_id)
#             if assignment_id:
#                 assignments_in_class = await get_assignments_for_classroom(classroom_id)
#                 print("Assignments in Math 101:", assignments_in_class)

#                 # Test submissions
#                 submission_id = await create_submission(assignment_id, user_s['id'], "/path/to/student1_hw1.pdf")
#                 print("Submission ID:", submission_id)
#                 if submission_id:
#                     submissions_for_hw = await get_submissions_for_assignment(assignment_id)
#                     print("Submissions for HW1:", submissions_for_hw)
#                     await update_submission_status(submission_id, "completed")
#                     updated_submission = await get_submission_by_id(submission_id)
#                     print("Updated submission:", updated_submission)

# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     asyncio.run(_test_db())
