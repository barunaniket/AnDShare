// This will store authentication related JS functions

// Function to handle login form submission
async function handleLoginFormSubmit(event) {
    event.preventDefault();
    const loginForm = event.target;
    const username = loginForm.username.value;
    const password = loginForm.password.value;
    const errorMessage = document.getElementById('error-message');

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (response.ok) {
            // Add subtle animation before redirect
            const loginContainer = document.querySelector('.login-container');
            if (loginContainer) {
                loginContainer.style.transition = 'transform 0.5s, opacity 0.5s';
                loginContainer.style.transform = 'scale(0.95)';
                loginContainer.style.opacity = '0';
            }
            setTimeout(() => { window.location.href = '/'; }, 500);
        } else {
            if (errorMessage) errorMessage.textContent = data.message || 'Login failed.';
            if (loginForm) { // Add shake animation for error
                loginForm.classList.add('shake');
                setTimeout(() => loginForm.classList.remove('shake'), 500);
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        if (errorMessage) errorMessage.textContent = 'An error occurred during login.';
    }
}

// Function to handle password change
async function handleChangePasswordFormSubmit(event) {
    event.preventDefault();
    const changePasswordForm = event.target;
    const oldPassword = changePasswordForm.oldPassword.value;
    const newPassword = changePasswordForm.newPassword.value;
    const confirmPassword = changePasswordForm.confirmPassword.value;
    const changePasswordError = document.getElementById('changePasswordError');
    const changePasswordSuccess = document.getElementById('changePasswordSuccess');

    if (newPassword !== confirmPassword) {
        if (changePasswordError) changePasswordError.textContent = 'New passwords do not match.';
        if (changePasswordSuccess) changePasswordSuccess.textContent = '';
        return;
    }

    try {
        const response = await fetch('/change_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ oldPassword, newPassword })
        });
        const data = await response.json(); // Always parse JSON, even for errors
        if (response.ok) {
            if (changePasswordSuccess) changePasswordSuccess.textContent = data.message || 'Password changed successfully.';
            if (changePasswordError) changePasswordError.textContent = '';
            changePasswordForm.reset();
            // Optionally close modal after a delay
            // setTimeout(() => {
            //     const settingsModal = document.getElementById('settingsModal');
            //     if (settingsModal) settingsModal.style.display = 'none';
            //     if (changePasswordSuccess) changePasswordSuccess.textContent = '';
            // }, 3000);
        } else {
            if (changePasswordError) changePasswordError.textContent = data.message || 'Password change failed.';
            if (changePasswordSuccess) changePasswordSuccess.textContent = '';
        }
    } catch (error) {
        console.error('Password change error:', error);
        if (changePasswordError) changePasswordError.textContent = 'An error occurred.';
        if (changePasswordSuccess) changePasswordSuccess.textContent = '';
    }
}

// Function to handle logout
async function handleLogout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            credentials: 'include'
        });
        if (response.redirected) {
            window.location.href = response.url;
        } else {
            // Fallback or error message if redirect doesn't happen as expected
            console.error('Logout failed or did not redirect.');
            window.location.href = '/login.html'; // Force redirect
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Display error to user or redirect
        window.location.href = '/login.html'; // Force redirect on error
    }
}

// Function to check authentication status (used by index.html)
// This will determine if the user should be on index.html or redirected to login.
// It also fetches the user's role for UI adjustments.
async function checkUserAuthAndRole() {
    try {
        const response = await fetch('/files'); // Endpoint that requires auth and returns role
        if (response.status === 401) {
            window.location.href = '/login.html';
            return null; // Not authenticated
        }
        if (!response.ok) {
            // For other errors, redirect to login as a safe fallback
            console.error('Auth check failed with status:', response.status);
            window.location.href = '/login.html';
            return null;
        }
        const data = await response.json();
        return data.role; // Return role if authenticated
    } catch (error) {
        console.error('Error checking authentication:', error);
        window.location.href = '/login.html'; // Redirect on any error
        return null;
    }
}


// Event listener setup - to be called from HTML pages
function initializeAuthForms() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLoginFormSubmit);
    }

    const changePasswordForm = document.getElementById('changePasswordForm');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', handleChangePasswordFormSubmit);
    }

    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', handleLogout);
    }
}

// Expose functions to global scope if needed, or rely on DOMContentLoaded to call initializers
// For simplicity here, we'll call initializeAuthForms on DOMContentLoaded from HTML.
// Or, it can be called directly from script tags in HTML.
// Example: document.addEventListener('DOMContentLoaded', initializeAuthForms);
// For checkUserAuthAndRole, it's usually called directly when index.html loads.
