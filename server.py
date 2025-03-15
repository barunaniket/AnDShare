import aiohttp
import asyncio
import base64
import json
import logging
import mimetypes
import os
import socket
import threading
import time
import uuid
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote
import aiofiles
import zipfile
from aiohttp import web

# Configure logging with reduced verbosity
logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('file_server')

# Configuration with absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Directory of this script
PORT = 1819
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")  # Absolute path to uploads directory
USERS_FILE = os.path.join(BASE_DIR, "users.json")  # Absolute path to users file
METADATA_FILE = os.path.join(BASE_DIR, "file_metadata.json")  # Absolute path to metadata file
SESSION_TIMEOUT = 300  # 5 minutes in seconds

# Ensure the uploads directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Load users and metadata with caching
try:
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
    logger.info("Users file loaded successfully.")
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Error loading users file: {e}")
    users = {}
last_users_sync = time.time()

try:
    with open(METADATA_FILE, 'r') as f:
        file_metadata = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    logger.info("No metadata file found or invalid format. Creating new metadata.")
    file_metadata = {}

# Thread-safe sessions dictionary
sessions_lock = threading.Lock()
sessions = {}

# Locks for shared resources
metadata_lock = asyncio.Lock()
users_lock = asyncio.Lock()

def generate_session_id():
    """Generate a unique session ID"""
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
    logger.debug(f"Checking authentication. Session ID from cookie: {session_id}")  # Added logging

    if not session_id:
        logger.warning("No session ID found in cookies.")
        return None

    username = get_username_from_session(session_id)
    logger.info(f"Username retrieved from session: {username}")

    return username

# Asynchronous save functions
async def save_metadata():
    """Save file metadata to disk asynchronously"""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _save_metadata_sync)

def _save_metadata_sync():
    """Synchronous helper to save metadata"""
    try:
        with open(METADATA_FILE, 'w') as f:
            json.dump(file_metadata, f, indent=4)
        logger.info("Metadata saved successfully")
    except Exception as e:
        logger.error(f"Error saving metadata: {e}")

async def save_users():
    """Save users to disk asynchronously"""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _save_users_sync)

def _save_users_sync():
    """Synchronous helper to save users"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
        logger.info("Users saved successfully")
    except Exception as e:
        logger.error(f"Error saving users: {e}")

# Request Handlers
async def login_handler(request):
    """Handle user login with optimizations"""
    try:
        if not request.headers.get('Content-Type', '').startswith('application/json'):
            logger.warning("Invalid Content-Type for login request")
            return web.json_response({'message': 'Invalid request format'}, status=400)

        data = await request.json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            logger.warning(f"Missing credentials in login attempt: username={username}")
            return web.json_response({'message': 'Missing username or password'}, status=400)

        if username in users and users[username].get('password') == password:
            session_id = create_session(username)
            response = web.json_response({'message': 'Login successful'})
            response.set_cookie('session_id', session_id, httponly=True)
            logger.info(f"Login successful for user {username}. Setting session ID: {session_id}")
            return response
        else:
            logger.warning(f"Failed login attempt for user: {username} - Invalid credentials")
            return web.json_response({'message': 'Invalid credentials'}, status=401)

    except json.JSONDecodeError:
        logger.error("Invalid JSON in login request")
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
    """Handle password change requests"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    try:
        data = await request.json()
        old_password = data.get('oldPassword')
        new_password = data.get('newPassword')

        async with users_lock:
            if users[username]['password'] == old_password:
                users[username]['password'] = new_password
                await save_users()
                logger.info(f"Password changed successfully for user: {username}")
                return web.json_response({'message': 'Password changed successfully'})
            else:
                logger.warning(f"Incorrect old password for user: {username}")
                return web.json_response({'message': 'Incorrect old password'}, status=400)

    except Exception as e:
        logger.error(f"Error in change_password_handler: {e}")
        return web.json_response({'message': 'Internal server error'}, status=500)

async def file_list_handler(request):
    """Return a list of files accessible to the user with uploader info"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    role = users[username]['role']
    files = []

    loop = asyncio.get_running_loop()
    file_names = await loop.run_in_executor(None, os.listdir, UPLOAD_DIR)

    for filename in file_names:
        filepath = os.path.join(UPLOAD_DIR, filename)
        is_file = await loop.run_in_executor(None, os.path.isfile, filepath)
        if is_file:
            size = await loop.run_in_executor(None, os.path.getsize, filepath)
            uploader = file_metadata.get(filename, {}).get('uploader', 'admin')
            status = file_metadata.get(filename, {}).get('status', 'pending')
            mime_type, _ = mimetypes.guess_type(filename)
            is_viewable = mime_type and (
                mime_type.startswith('text/') or
                mime_type == 'application/pdf' or
                mime_type.startswith('image/') or
                mime_type == 'application/json' or
                mime_type == 'text/html'
            )

            if role == 'admin' or uploader == username or uploader == 'admin':
                files.append({
                    'name': filename,
                    'size': size,
                    'url': f'/shared/{filename}',
                    'uploader': uploader,
                    'status': status,
                    'isViewable': is_viewable
                })

    logger.info(f"File list requested by user: {username}, found {len(files)} accessible files")
    return web.json_response({'role': role, 'files': files})

async def file_download_handler(request):
    """Serve a file if the user has permission"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    filename = unquote(request.match_info['filename'])
    filepath = os.path.join(UPLOAD_DIR, filename)

    if not await asyncio.to_thread(os.path.exists, filepath):
        logger.warning(f"File not found: {filename}")
        return web.json_response({'message': 'File not found'}, status=404)

    role = users[username]['role']
    uploader = file_metadata.get(filename, {}).get('uploader', 'admin')
    
    if role != 'admin' and uploader != username and uploader != 'admin':
        logger.warning(f"Permission denied for user: {username} to access file: {filename}")
        return web.json_response({'message': 'Permission denied'}, status=403)

    mime_type, _ = mimetypes.guess_type(filename)
    
    logger.info(f"File download: {filename} by user: {username}")
    return web.FileResponse(filepath, headers={
        'Content-Type': mime_type or 'application/octet-stream'
    })

async def file_upload_handler(request):
    """Handle file uploads and update metadata"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    reader = await request.multipart()
    
    updates = {}
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
                updates[filename] = {'uploader': username, 'status': 'pending'}
                file_count += 1
            except Exception as e:
                logger.error(f"Error uploading file {filename}: {e}")
                if os.path.exists(filepath):
                    os.remove(filepath)
    
    if updates:
        async with metadata_lock:
            file_metadata.update(updates)
            await save_metadata()
    
    logger.info(f"User {username} uploaded {file_count} files")
    return web.json_response({'message': f'Successfully uploaded {file_count} files'})

async def download_all_handler(request):
    """Allow admins to download a ZIP of all files"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    role = users[username]['role']
    if role != 'admin':
        logger.warning(f"Admin access required: {username} attempted to download all files")
        return web.json_response({'message': 'Admin access required'}, status=403)

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
    """Allow admins to download a list of all unique uploaders and their count"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    role = users[username]['role']
    if role != 'admin':
        logger.warning(f"Admin access required: {username} attempted to download uploaders list")
        return web.json_response({'message': 'Admin access required'}, status=403)

    unique_uploaders = sorted(set(data['uploader'] for data in file_metadata.values()))
    total_uploaders = len(unique_uploaders)

    content = f"Total Uploaders: {total_uploaders}\n\nUploaders:\n"
    for filename, data in file_metadata.items():
        content += f"- {data['uploader']} (File: {filename}, Status: {data['status']})\n"
    content_bytes = content.encode('utf-8')

    logger.info(f"Admin {username} downloaded uploaders list")
    return web.Response(
        body=content_bytes,
        headers={
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename="uploaders.txt"',
            'Content-Length': str(len(content_bytes))
        }
    )

async def update_status_handler(request):
    """Handle updating the completion status of a file"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)

    if users[username]['role'] != 'admin':
        logger.warning(f"Admin access required: {username} attempted to update file status")
        return web.json_response({'message': 'Admin access required'}, status=403)

    try:
        data = await request.json()
        filename = data.get('filename')
        status = data.get('status')

        if filename and status in ['pending', 'completed', 'rejected']:
            async with metadata_lock:
                if filename in file_metadata:
                    file_metadata[filename]['status'] = status
                    await save_metadata()
                    logger.info(f"Status updated for file: {filename} to {status}")
                    return web.json_response({'message': 'Status updated successfully'})
                else:
                    logger.warning(f"File not found: {filename}")
                    return web.json_response({'message': 'File not found'}, status=404)
        else:
            logger.warning(f"Invalid request to update status: {filename}, {status}")
            return web.json_response({'message': 'Invalid filename or status'}, status=400)

    except Exception as e:
        logger.error(f"Error in update_status_handler: {e}")
        return web.json_response({'message': 'Internal server error'}, status=500)

async def clear_files_handler(request):
    """Handle clearing all files and metadata (admin only)"""
    username = await check_auth(request)
    if not username:
        return web.json_response({'message': 'Not authenticated'}, status=401)
    
    role = users[username]['role']
    if role != 'admin':
        logger.warning(f"Admin access required: {username} attempted to clear files")
        return web.json_response({'message': 'Admin access required'}, status=403)
    
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, clear_upload_dir)
        
        async with metadata_lock:
            file_metadata.clear()
            await save_metadata()
        
        logger.info(f"Admin {username} cleared all files and metadata")
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
    
    # Routes
    app.add_routes([
        web.get('/', index_handler),
        web.get('/files', file_list_handler),
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