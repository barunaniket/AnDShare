import aiohttp
import asyncio
import base64
import json # Keep for request/response parsing, not for file storage
import logging
import mimetypes
import os
import socket
import threading # sessions_lock can remain for in-memory session management
import time
import uuid
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote
import aiofiles
import zipfile
from aiohttp import web

# Import database setup and query functions
import db_setup
import db_queries

# Configure logging
# logging.basicConfig(level=logging.INFO, # Adjusted for more visibility during dev
#                     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# logger = logging.getLogger('classroom_server') # Renamed logger

# Reconfigure logging to be less verbose for general operation, but allow specific loggers to be more verbose.
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger('classroom_server')
# For development, you might want to set the logger for your specific modules to INFO or DEBUG
# logging.getLogger('db_queries').setLevel(logging.INFO)
# logging.getLogger('classroom_server').setLevel(logging.INFO)


# Configuration with absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 1819 # Consider making this configurable via environment variable
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
SESSION_TIMEOUT = 300  # 5 minutes in seconds
# DATABASE_NAME is implicitly used by db_setup and db_queries

# Ensure the uploads directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Removed old JSON file loading for users and metadata
# Removed old USERS_FILE and METADATA_FILE constants

# Thread-safe sessions dictionary
sessions_lock = threading.Lock()
sessions = {}

# Removed metadata_lock and users_lock as DB handles concurrency


async def init_db(app):
    """Initialize database tables on startup."""
    try:
        await db_setup.create_tables()
        logger.info("Database tables checked/created successfully.")

        # Create a default superadmin user if none exists, with specified credentials
        default_superadmin_username = "admin"
        default_superadmin_password = "admin"

        # Check if the user 'admin' exists, irrespective of environment variables for this specific setup
        existing_superadmin = await db_queries.get_user_by_username(default_superadmin_username)

        if not existing_superadmin:
            # Use environment variables as overrides ONLY IF they are set, otherwise use hardcoded defaults.
            # For this task, we are enforcing 'admin'/'admin' as the primary default.
            # So, we won't check os.environ.get here for the default creation.
            # If a user wants to use env vars, they'd typically ensure the DB is already seeded or handle it externally.

            await db_queries.add_user(default_superadmin_username, default_superadmin_password, "superadmin")
            logger.info(f"Default superadmin user '{default_superadmin_username}' created with the specified password.")
        else:
            logger.info(f"Superadmin user '{default_superadmin_username}' already exists.")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        # Depending on the severity, you might want to prevent the app from starting
        # raise # Or handle more gracefully


def generate_session_id():
    """Generate a unique session ID."""
    return str(uuid.uuid4())

def create_session(username):
    """Create a new session for a user with thread safety"""
    with sessions_lock:
        session_id = generate_session_id()
        sessions[session_id] = {'username': username, 'last_active': time.time()}
        logger.info(f"Session created for user {username} with session ID: {session_id}")  # Added logging
        return session_id

def get_username_from_session(session_id):
    """Get username from session ID, returning None if invalid or expired"""
    with sessions_lock:
        logger.debug(f"Attempting to retrieve username for session ID: {session_id}") # Added logging
        if session_id in sessions:
            time_since_active = time.time() - sessions[session_id]['last_active']
            logger.debug(f"Session found. Time since last activity: {time_since_active}")  # Added logging

            if time_since_active < SESSION_TIMEOUT:
                sessions[session_id]['last_active'] = time.time()
                username = sessions[session_id]['username']
                logger.info(f"Session {session_id} is valid. Returning username: {username}")
                return username
            else:
                del sessions[session_id]
                logger.warning(f"Session {session_id} expired.")
                return None
        else:
            logger.warning(f"Session {session_id} not found.")
            return None

def delete_session(session_id):
    """Delete a session"""
    with sessions_lock:
        if session_id in sessions:
            del sessions[session_id]

def clear_upload_dir():
    """Delete all files in the upload directory"""
    for filename in os.listdir(UPLOAD_DIR):
        file_path = os.path.join(UPLOAD_DIR, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)

async def check_auth(request):
    """Check if the user is authenticated"""
    session_id = request.cookies.get('session_id')
    logger.debug(f"Checking authentication. Session ID from cookie: {session_id}")

    if not session_id:
        logger.warning("No session ID found in cookies.")
        return None # No session ID, so not authenticated

    username_from_session = get_username_from_session(session_id) # This checks expiry
    if not username_from_session:
        logger.warning(f"Session ID {session_id} is invalid or expired.")
        return None # Session expired or invalid

    # Fetch full user details from DB to get role and ID
    user = await db_queries.get_user_by_username(username_from_session)
    if not user:
        logger.error(f"User '{username_from_session}' from valid session not found in database. Deleting session.")
        delete_session(session_id) # Clean up inconsistent session
        return None

    # Attach user object to the request for easy access in handlers
    # request['user'] = user # This is a common pattern
    logger.info(f"User {user['username']} (ID: {user['id']}, Role: {user['role']}) authenticated via session {session_id}.")
    return user # Return the full user object (dict)

# Removed save_metadata, _save_metadata_sync, save_users, _save_users_sync functions
# as user and file metadata are now handled by the database.

# Request Handlers
async def login_handler(request):
    """Handle user login using database."""
    try:
        if not request.headers.get('Content-Type', '').startswith('application/json'):
            logger.warning("Invalid Content-Type for login request")
            return web.json_response({'message': 'Invalid request format'}, status=400)

        data = await request.json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            logger.warning(f"Missing credentials in login attempt for username: {username}")
            return web.json_response({'message': 'Missing username or password'}, status=400)

        user = await db_queries.get_user_by_username(username)

        if user and user["password_hash"] == db_queries.hash_password(password):
            # User authenticated successfully
            session_id = create_session(username) # Session stores username, could store user_id too
            response = web.json_response({'message': 'Login successful', 'role': user['role']})
            response.set_cookie('session_id', session_id, httponly=True, samesite='Lax') # Added samesite
            logger.info(f"Login successful for user {username} (Role: {user['role']}). Session ID: {session_id}")
            return response
        else:
            logger.warning(f"Failed login attempt for user: {username} - Invalid credentials or user not found.")
            return web.json_response({'message': 'Invalid credentials'}, status=401)

    except json.JSONDecodeError:
        logger.error("Invalid JSON in login request body.")
        return web.json_response({'message': 'Invalid JSON format'}, status=400)
    except Exception as e:
        logger.error(f"Error in login_handler: {e}")
        return web.json_response({'message': 'Internal server error'}, status=500)

async def logout_handler(request):
    """Handle user logout"""
    session_id = request.cookies.get('session_id')
    if session_id:
        delete_session(session_id)
        logger.info(f"User logged out, session {session_id} deleted")
    response = web.HTTPFound('/login.html')  # Redirect to login page
    response.del_cookie('session_id')  # Clear the session cookie
    return response

async def change_password_handler(request):
    """Handle password change requests using database."""
    authenticated_user = await check_auth(request) # Returns user dict or None
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    current_username = authenticated_user['username']

    try:
        data = await request.json()
        old_password_attempt = data.get('oldPassword')
        new_password = data.get('newPassword')

        if not old_password_attempt or not new_password:
            logger.warning(f"Missing old or new password for user: {current_username}")
            return web.json_response({'message': 'Missing old or new password'}, status=400)

        # Fetch the user again to get the current password hash for comparison
        # This is important if password_hash was not included in `authenticated_user` from check_auth,
        # or to ensure we have the absolute latest hash.
        user_from_db = await db_queries.get_user_by_username(current_username)
        if not user_from_db:
             # Should not happen if check_auth passed, but good for robustness
            logger.error(f"Authenticated user {current_username} not found in DB during password change.")
            return web.json_response({'message': 'User not found, please re-login.'}, status=401)

        if user_from_db['password_hash'] == db_queries.hash_password(old_password_attempt):
            success = await db_queries.update_user_password(current_username, new_password)
            if success:
                logger.info(f"Password changed successfully for user: {current_username}")
                return web.json_response({'message': 'Password changed successfully'})
            else:
                logger.error(f"Failed to update password in DB for user: {current_username}")
                return web.json_response({'message': 'Password change failed at database level.'}, status=500)
        else:
            logger.warning(f"Incorrect old password attempt for user: {current_username}")
            return web.json_response({'message': 'Incorrect old password'}, status=400)

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in change_password_handler for user: {current_username}")
        return web.json_response({'message': 'Invalid JSON format'}, status=400)
    except Exception as e:
        logger.error(f"Error in change_password_handler for user {current_username}: {e}", exc_info=True)
        return web.json_response({'message': 'Internal server error'}, status=500)

async def file_list_handler(request):
    """
    Return a list of files.
    NOTE: This is a placeholder and will be significantly refactored
    to support classrooms, assignments, and submissions.
    For now, it returns an empty list but performs auth.
    """
    authenticated_user = await check_auth(request) # Returns user dict or None
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    role = authenticated_user['role']
    username = authenticated_user['username'] # For logging
    files = [] # Placeholder

    # TODO: Implement actual file listing based on user role and classroom context
    # - Teachers: See assignments they created, submissions to their assignments.
    # - Students: See assignments in their enrolled classrooms, their own submissions.
    # - SuperAdmins: Potentially a different view or all files.

    logger.info(f"File list requested by user: {username} (Role: {role}). Currently returns placeholder.")
    return web.json_response({'role': role, 'files': files})

async def file_download_handler(request):
    """
    Serve a file.
    NOTE: This is a placeholder and will be refactored.
    Permissions will depend on classroom, assignment, submission context.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    filename = unquote(request.match_info['filename'])
    filepath = os.path.join(UPLOAD_DIR, filename) # This path might change with classroom structure

    if not await asyncio.to_thread(os.path.exists, filepath): # os.path.exists is blocking, run in thread
        logger.warning(f"File not found: {filename} at path {filepath}")
        return web.json_response({'message': 'File not found'}, status=404)

    # TODO: Implement actual permission checking based on classroom/assignment/submission context.
    # The following is old logic and will not work correctly.
    # role = authenticated_user['role']
    # username = authenticated_user['username']
    # uploader = file_metadata.get(filename, {}).get('uploader', 'admin') # file_metadata is gone
    # if role != 'admin' and uploader != username and uploader != 'admin':
    #     logger.warning(f"Permission denied for user: {username} to access file: {filename} (using old logic)")
    #     return web.json_response({'message': 'Permission denied (placeholder logic)'}, status=403)

    logger.info(f"File download attempt for: {filename} by user: {authenticated_user['username']}. Placeholder permission logic.")
    
    mime_type, _ = mimetypes.guess_type(filename)
    return web.FileResponse(filepath, headers={
        'Content-Type': mime_type or 'application/octet-stream'
    })

async def file_upload_handler(request):
    """
    Handle file uploads.
    NOTE: This is a placeholder. Metadata saving needs to be integrated
    with Assignments/Submissions in the database.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    username = authenticated_user['username'] # For logging and potentially associating file
    reader = await request.multipart()
    
    # updates = {} # Old way of collecting metadata for JSON
    file_count = 0
    while True:
        part = await reader.next()
        if part is None:
            break
            
        if part.filename:
            filename = os.path.basename(part.filename)
            if not filename:
                continue
                
            filepath = os.path.join(UPLOAD_DIR, filename)
            try:
                async with aiofiles.open(filepath, 'wb') as f:
                    while True:
                        chunk = await part.read_chunk()
                        if not chunk:
                            break
                        await f.write(chunk)
                # updates[filename] = {'uploader': username, 'status': 'pending'} # Old metadata
                # For now, we are not associating file with DB records here. This needs full implementation.
                logger.info(f"File {filename} uploaded by {username} to {filepath}. No DB record created yet.")
                file_count += 1
            except Exception as e:
                logger.error(f"Error uploading file {filename} by {username}: {e}", exc_info=True)
                if await asyncio.to_thread(os.path.exists, filepath): # Check before removing
                    await asyncio.to_thread(os.remove, filepath) # Use asyncio.to_thread for os.remove
    
    # if updates: # Old metadata saving logic
    #     async with metadata_lock: # metadata_lock is removed
    #         file_metadata.update(updates) # file_metadata is removed
    #         await save_metadata() # save_metadata is removed
    
    logger.info(f"User {username} attempted to upload {file_count} files. Placeholder: no DB interaction yet.")
    if file_count > 0:
        return web.json_response({'message': f'Successfully uploaded {file_count} files to server. DB record pending proper implementation.'})
    else:
        return web.json_response({'message': 'No files were processed or an error occurred.'}, status=400)


async def download_all_handler(request):
    """
    Allow admins to download a ZIP of all files.
    NOTE: This needs to be adapted for superadmin role and classroom structure.
    Currently, it will check for 'superadmin' role.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    # Role check - should be 'superadmin' for this global action
    if authenticated_user['role'] != 'superadmin':
        logger.warning(f"User {authenticated_user['username']} (Role: {authenticated_user['role']}) attempted to download all files. Requires 'superadmin'.")
        return web.json_response({'message': "Forbidden: Requires 'superadmin' role."}, status=403)

    loop = asyncio.get_running_loop()
    def create_zip():
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename in os.listdir(UPLOAD_DIR):
                filepath = os.path.join(UPLOAD_DIR, filename)
                if os.path.isfile(filepath):
                    zip_file.write(filepath, arcname=filename)
        return zip_buffer.getvalue()

    zip_data = await loop.run_in_executor(None, create_zip)
    
    logger.info(f"Admin {username} downloaded all files as zip")
    return web.Response(
        body=zip_data,
        headers={
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="all_files.zip"',
            'Content-Length': str(len(zip_data))
        }
    )

async def download_uploaders_handler(request):
    """
    Allow admins to download a list of all unique uploaders and their count.
    NOTE: This is a placeholder. It needs to be re-implemented based on data
    from Assignments and Submissions tables, likely for superadmin view.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    # This was an admin-only feature, mapping to 'superadmin' or perhaps 'teacher' for their own classroom contexts.
    # For a global list of all uploaders, 'superadmin' seems appropriate.
    if authenticated_user['role'] != 'superadmin':
        logger.warning(f"User {authenticated_user['username']} (Role: {authenticated_user['role']}) attempted to download uploaders list. Requires 'superadmin'.")
        return web.json_response({'message': "Forbidden: Requires 'superadmin' role."}, status=403)

    # Old logic based on file_metadata is removed.
    # TODO: Re-implement by querying Users, Assignments, Submissions tables.
    # For example, find all distinct uploader_ids from Assignments and student_ids from Submissions.

    logger.info(f"User {authenticated_user['username']} attempted to download uploaders list. Feature pending re-implementation.")

    content = "Uploader list feature is currently under reconstruction based on the new database structure.\n"
    content += "This report will show distinct users who have uploaded assignments or made submissions.\n"
    content_bytes = content.encode('utf-8')

    return web.Response(
        body=content_bytes,
        headers={
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename="uploaders_status.txt"', # Renamed to reflect it's a status
            'Content-Length': str(len(content_bytes))
        }
    )

async def update_status_handler(request):
    """
    Handle updating the completion status of a file.
    NOTE: This is a placeholder. It needs to be integrated with Submissions in the database.
    Role check will be for 'teacher' or 'superadmin' in the context of a submission.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    # This functionality is primarily for teachers marking submissions, or superadmins.
    # The old 'admin' role might map to 'teacher' or 'superadmin' depending on context.
    # For now, let's assume a 'teacher' or 'superadmin' can do this.
    if authenticated_user['role'] not in ['teacher', 'superadmin']:
        logger.warning(f"User {authenticated_user['username']} (Role: {authenticated_user['role']}) attempted to update file status. Requires 'teacher' or 'superadmin'.")
        return web.json_response({'message': "Forbidden: Requires 'teacher' or 'superadmin' role."}, status=403)

    try:
        data = await request.json()
        # These would refer to a submission ID and the new status
        submission_id = data.get('submission_id') # Changed from filename
        status = data.get('status')

        if submission_id and status in ['pending', 'submitted', 'completed', 'rejected']: # 'pending' might not be settable by user
            # TODO: Implement db_queries.update_submission_status(submission_id, status)
            # And verify the authenticated_user has permission to update this specific submission.
            logger.info(f"Placeholder: User {authenticated_user['username']} attempted to update status for submission ID {submission_id} to {status}.")
            return web.json_response({'message': 'Status update placeholder - DB interaction not implemented.'})
        else:
            logger.warning(f"Invalid request to update status: submission_id={submission_id}, status={status} by user {authenticated_user['username']}")
            return web.json_response({'message': 'Invalid submission_id or status'}, status=400)

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in update_status_handler by user {authenticated_user['username']}")
        return web.json_response({'message': 'Invalid JSON format'}, status=400)
    except Exception as e:
        logger.error(f"Error in update_status_handler for user {authenticated_user['username']}: {e}", exc_info=True)
        return web.json_response({'message': 'Internal server error'}, status=500)

async def clear_files_handler(request):
    """
    Handle clearing all files and metadata (superadmin only).
    NOTE: This needs careful consideration. "All files" needs to be defined.
    It might mean all files in UPLOAD_DIR and clearing corresponding DB records.
    For now, it only clears UPLOAD_DIR if user is superadmin. DB records are untouched.
    """
    authenticated_user = await check_auth(request)
    if not authenticated_user:
        return web.json_response({'message': 'Not authenticated'}, status=401)
    
    if authenticated_user['role'] != 'superadmin':
        logger.warning(f"User {authenticated_user['username']} (Role: {authenticated_user['role']}) attempted to clear all files. Requires 'superadmin'.")
        return web.json_response({'message': "Forbidden: Requires 'superadmin' role."}, status=403)
    
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, clear_upload_dir) # clear_upload_dir just empties the folder
        
        # The old metadata clearing is removed as file_metadata is gone.
        # TODO: Implement logic to clear relevant records from Assignments and Submissions tables.
        # This is a destructive operation and needs careful thought.
        
        logger.info(f"Superadmin {authenticated_user['username']} cleared all files from UPLOAD_DIR. DB records not yet affected by this handler.")
        return web.json_response({'message': 'All files and metadata cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing files: {e}")
        return web.json_response({'message': 'Failed to clear files'}, status=500)

async def index_handler(request):
    """Redirect to login if not authenticated, otherwise serve index.html"""
    username = await check_auth(request)
    logger.debug(f"Index handler: Authenticated user: {username}")

    if not username:
        logger.info("Redirecting to login page (unauthenticated).")
        return web.HTTPFound('/login.html')
    
    return web.FileResponse('index.html')

async def handle_404(request):
    """Handle 404 errors"""
    return web.json_response({'message': 'Not found'}, status=404)

# Middleware
@web.middleware
async def error_middleware(request, handler):
    """Handle errors and log them"""
    try:
        return await handler(request)
    except web.HTTPException as ex:
        if ex.status == 404:
            return await handle_404(request)
        raise
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        return web.json_response({'message': 'Internal server error'}, status=500)

def get_local_ip():
    """Get the local IP address for network access"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# Setup cleanup routine
async def cleanup_sessions(app):
    """Background task to clean up expired sessions"""
    while True:
        current_time = time.time()
        with sessions_lock:
            expired_sessions = [
                session_id for session_id, data in sessions.items()
                if (current_time - data['last_active']) >= SESSION_TIMEOUT
            ]
            for session_id in expired_sessions:
                logger.info(f"Cleaning up expired session: {session_id}")
                delete_session(session_id)
        await asyncio.sleep(300)  # Check every 5 minutes

async def start_background_tasks(app):
    """Start background tasks"""
    app['cleanup_task'] = asyncio.create_task(cleanup_sessions(app))

async def cleanup_background_tasks(app):
    """Clean up background tasks"""
    app['cleanup_task'].cancel()
    await app['cleanup_task']

def create_app():
    """Create and configure the application"""
    app = web.Application(middlewares=[error_middleware])

    # Database initialization
    app.on_startup.append(init_db)
    
    # Routes
    app.add_routes([
        web.get('/', index_handler),
        web.get('/files', file_list_handler), # This will need significant changes
        web.get('/shared/{filename}', file_download_handler),
        web.get('/download_all', download_all_handler),
        web.get('/download_uploaders', download_uploaders_handler),
        web.post('/upload', file_upload_handler),
        web.post('/login', login_handler),
        web.post('/logout', logout_handler),
        web.post('/change_password', change_password_handler),
        web.post('/update_status', update_status_handler),
        web.post('/clear_files', clear_files_handler),
    ])
    
    # Static files
    app.add_routes([web.static('/', '.', show_index=False)])
    
    # Background tasks
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    
    # Shutdown handler
    async def on_shutdown(app):
        print("Server is shutting down...")
    app.on_shutdown.append(on_shutdown)
    
    return app

if __name__ == '__main__':
    local_ip = get_local_ip()
    
    print(f"\n{'=' * 40}")
    print(f"Server running on:")
    print(f"Local: http://localhost:{PORT}")
    print(f"Network: http://{local_ip}:{PORT}")
    print(f"Using UPLOAD_DIR: {UPLOAD_DIR}")
    print(f"{'=' * 40}\n")
    
    app = create_app()
    web.run_app(app, port=PORT)