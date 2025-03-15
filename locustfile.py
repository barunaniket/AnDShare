import random
import json
import os
from locust import HttpUser, task, between, tag
from locust.exception import StopUser
import logging

# Configure logging for Locust
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load users from users.json
USERS_FILE = "users.json"  # Or use an absolute path if needed
try:
    with open(USERS_FILE, 'r') as f:
        USERS = json.load(f)
    logger.info(f"Loaded {len(USERS)} users from {USERS_FILE}")
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Error loading users from {USERS_FILE}: {e}")
    USERS = {}


# Generate a sample file for upload
def generate_sample_file(size_kb=10):  # You can adjust the file size
    """Generates a dummy file of a specified size in KB."""
    file_size_bytes = size_kb * 1024
    return os.urandom(file_size_bytes)  # Returns random bytes

SAMPLE_FILE_CONTENT = generate_sample_file()


class FileServerUser(HttpUser):
    wait_time = between(1, 5)  # Users wait between 1 to 5 seconds between tasks
    user_counter = 0  # Class-level counter to cycle through users

    def on_start(self):
        """On start, each user logs in and stores session cookies."""
        self.login()

    def login(self):
        """Login with a user, cycling through the list to avoid concurrency issues with the same user."""
        user_list = list(USERS.items())
        user_index = FileServerUser.user_counter % len(user_list)
        FileServerUser.user_counter += 1  # Increment the counter
        self.username, self.user_info = user_list[user_index]

        login_data = {
            "username": self.username,
            "password": self.user_info["password"]
        }
        with self.client.post("/login", json=login_data, catch_response=True) as response:
            if response.status_code == 200:
                self.client.cookies.update(response.cookies.get_dict())
                self.session_id = response.cookies.get('session_id')
                logger.info(f"User {self.username} logged in successfully with session ID: {self.session_id}")
            else:
                logger.error(f"Failed to login with user {self.username}: {response.text}")
                response.failure(f"Login failed: {response.text}")
                raise StopUser(f"Failed to login with user {self.username}") # Stop the user if login fails

    @task(3)  # Higher weight for common tasks
    def list_files(self):
        """List files accessible to the authenticated user."""
        with self.client.get("/files", catch_response=True) as response:
            if response.status_code == 200:
                files = response.json().get("files", [])
                logger.debug(f"{self.username} can access {len(files)} files") # Reduced verbosity
            elif response.status_code == 401:
                logger.warning(f"{self.username} - Not authenticated when listing files")
                response.failure("Not authenticated")
            else:
                logger.error(f"{self.username} - Unexpected status code when listing files: {response.status_code}")
                response.failure(f"Unexpected status code: {response.status_code}")

    @task(2)
    def upload_file(self):
        """Upload a small sample file."""
        file_name = f"upload_test_{self.username}.txt"  # Unique filename for each user
        files = {'file': (file_name, SAMPLE_FILE_CONTENT)}

        with self.client.post("/upload", files=files, catch_response=True) as response:
            if response.status_code == 200:
                logger.info(f"{self.username} uploaded {file_name} successfully")
            elif response.status_code == 401:
                logger.warning(f"{self.username} - Not authenticated during file upload")
                response.failure("Not authenticated")
            else:
                logger.error(f"{self.username} - Failed to upload file: {response.text}")
                response.failure(f"Failed to upload file: {response.text}")

    @task(2)
    def download_random_file(self):
        """Download a random file from the accessible list."""
        files_response = self.client.get("/files")
        if files_response.status_code != 200:
            logger.warning(f"{self.username} - Could not get file list for download")
            return

        files = files_response.json().get("files", [])
        if not files:
            logger.info(f"No files available for {self.username} to download")
            return

        file_to_download = random.choice(files)
        file_name = file_to_download['name']
        with self.client.get(f"/shared/{file_name}", catch_response=True) as response:
            if response.status_code == 200:
                logger.info(f"{self.username} downloaded {file_name}")
            elif response.status_code == 403:
                logger.warning(f"{self.username} - Permission denied for downloading {file_name}")
                response.failure("Permission denied")
            else:
                logger.error(f"{self.username} - Failed to download {file_name}: {response.status_code}")
                response.failure(f"Failed to download {file_name}: {response.status_code}")

    @task(1)
    @tag("admin_only")
    def admin_update_status(self):
        """Admin updates the status of a random file."""
        if self.user_info["role"] != "admin":
            return  # Only execute if the user is an admin

        files_response = self.client.get("/files")
        if files_response.status_code != 200:
            logger.warning("Admin could not get file list to update status.")
            return

        files = files_response.json().get("files", [])
        if not files:
            logger.info("No files available to update status.")
            return

        file_to_update = random.choice(files)
        status = random.choice(['pending', 'completed', 'rejected'])
        update_data = {
            "filename": file_to_update['name'],
            "status": status
        }
        with self.client.post("/update_status", json=update_data, catch_response=True) as response:
            if response.status_code == 200:
                logger.info(f"Admin updated status of {file_to_update['name']} to {status}")
            else:
                logger.error(f"Admin failed to update status: {response.text}")
                response.failure(f"Failed to update status: {response.text}")

    @task(1)
    @tag("admin_only")
    def admin_download_all(self):
        """Admin downloads all files as a ZIP."""
        if self.user_info["role"] != "admin":
            return  # Only execute if the user is an admin

        with self.client.get("/download_all", catch_response=True) as response:
            if response.status_code == 200:
                logger.info("Admin downloaded all files as ZIP")
            else:
                logger.error(f"Admin failed to download all files: {response.text}")
                response.failure(f"Failed to download all files: {response.text}")

    @task(1)
    @tag("admin_only")
    def admin_download_uploaders(self):
        """Admin downloads the list of uploaders."""
        if self.user_info["role"] != "admin":
            return  # Only execute if the user is an admin

        with self.client.get("/download_uploaders", catch_response=True) as response:
            if response.status_code == 200:
                logger.info("Admin downloaded uploaders list")
            else:
                logger.error(f"Admin failed to download uploaders list: {response.text}")
                response.failure(f"Failed to download uploaders list: {response.text}")

    @task(1)
    @tag("admin_only")
    def admin_clear_files(self):
        """Admin clears all files and metadata."""
        if self.user_info["role"] != "admin":
            return  # Only execute if the user is an admin

        with self.client.post("/clear_files", catch_response=True) as response:
            if response.status_code == 200:
                logger.info("Admin cleared all files and metadata")
            else:
                logger.error(f"Admin failed to clear files: {response.text}")
                response.failure(f"Failed to clear files: {response.text}")

    def on_stop(self):
        """Ensure proper logout when stopping."""
        if hasattr(self, 'session_id') and self.session_id:
            with self.client.post("/logout", catch_response=True) as response:
                if response.status_code == 200:
                    logger.info(f"{self.username} logged out successfully.")
                else:
                    logger.warning(f"Logout failed for {self.username}: {response.text}")