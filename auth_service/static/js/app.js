// Meme App - Frontend JavaScript

// ==================== GLOBALS ====================

// Pending user info for resend
let pendingUser = null;

// Pending username for resend verification (from failed login)
let pendingResendUsername = null;

// Session tokens
let accessToken = localStorage.getItem('accessToken');
let refreshToken = localStorage.getItem('refreshToken');

// Password reset token (from URL)
let resetToken = null;

// MFA token (temporary, for completing MFA login)
let mfaToken = null;
let mfaUsername = null;

// ==================== reCAPTCHA ====================

// Initialize reCAPTCHA when ready
function onRecaptchaLoad() {
    // Widgets are rendered automatically via class
}

// Get reCAPTCHA response from the currently visible form
function getRecaptchaResponse(formType) {
    let container;
    if (formType === 'login') {
        container = document.getElementById('login-recaptcha');
    } else if (formType === 'forgot') {
        container = document.getElementById('forgot-recaptcha');
    } else if (formType === 'resend') {
        container = document.getElementById('resend-recaptcha');
    } else {
        container = document.getElementById('register-recaptcha');
    }

    // Get the response from the widget in this container
    const response = grecaptcha.getResponse(
        grecaptcha.getWidgetId ?
            grecaptcha.getWidgetId(container) :
            Array.from(container.querySelectorAll('iframe')).length > 0 ? 0 : 1
    );

    // Try alternative method - just get any response
    if (!response) {
        try {
            // Get all responses
            const allResponses = document.querySelectorAll('textarea[name="g-recaptcha-response"]');
            for (const textarea of allResponses) {
                if (textarea.value) {
                    return textarea.value;
                }
            }
        } catch (e) {
            console.error('Error getting reCAPTCHA response:', e);
        }
    }

    return response || '';
}

// Reset reCAPTCHA for a form
function resetRecaptcha() {
    try {
        grecaptcha.reset();
    } catch (e) {
        // reCAPTCHA not loaded yet
    }
}

// ==================== VALIDATION FUNCTIONS ====================

function validateUsername(username) {
    if (!username) {
        return { valid: false, error: "Username is required" };
    }
    if (username.length < 3) {
        return { valid: false, error: "Username must be at least 3 characters" };
    }
    if (username.length > 30) {
        return { valid: false, error: "Username must not exceed 30 characters" };
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return { valid: false, error: "Only letters, numbers, and underscores allowed" };
    }
    return { valid: true, error: null };
}

function validatePassword(password) {
    if (!password) {
        return { valid: false, error: "Password is required" };
    }
    if (password.length < 15) {
        return { valid: false, error: "Password must be at least 15 characters" };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, error: "Must contain an uppercase letter" };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, error: "Must contain a lowercase letter" };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: "Must contain a digit" };
    }
    if (!/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\/~`]/.test(password)) {
        return { valid: false, error: "Must contain a special character" };
    }
    return { valid: true, error: null };
}

function validateEmail(email) {
    if (!email) {
        return { valid: false, error: "Email is required" };
    }
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailPattern.test(email)) {
        return { valid: false, error: "Invalid email format" };
    }
    if (email.length > 254) {
        return { valid: false, error: "Email is too long" };
    }
    return { valid: true, error: null };
}

// ==================== UI HELPERS ====================

function validateField(inputId, validatorFn) {
    const input = document.getElementById(inputId);
    const errorSpan = document.getElementById(inputId + "-error");
    const value = input.value.trim();

    const result = validatorFn(value);

    if (!result.valid && value.length > 0) {
        input.classList.add("error");
        errorSpan.textContent = result.error;
        errorSpan.classList.add("visible");
    } else {
        input.classList.remove("error");
        errorSpan.classList.remove("visible");
    }

    return result.valid;
}

function validateConfirmEmail() {
    const email = document.getElementById("reg-email").value.trim().toLowerCase();
    const confirmEmail = document.getElementById("reg-email-confirm").value.trim().toLowerCase();
    const confirmInput = document.getElementById("reg-email-confirm");
    const confirmError = document.getElementById("reg-email-confirm-error");

    if (confirmEmail.length > 0 && email !== confirmEmail) {
        confirmInput.classList.add("error");
        confirmError.textContent = "Emails do not match";
        confirmError.classList.add("visible");
        return false;
    } else {
        confirmInput.classList.remove("error");
        confirmError.classList.remove("visible");
        return confirmEmail.length > 0;
    }
}

function validateConfirmPassword() {
    const password = document.getElementById("reg-pass").value;
    const confirmPassword = document.getElementById("reg-pass-confirm").value;
    const confirmInput = document.getElementById("reg-pass-confirm");
    const confirmError = document.getElementById("reg-pass-confirm-error");

    if (confirmPassword.length > 0 && password !== confirmPassword) {
        confirmInput.classList.add("error");
        confirmError.textContent = "Passwords do not match";
        confirmError.classList.add("visible");
        return false;
    } else {
        confirmInput.classList.remove("error");
        confirmError.classList.remove("visible");
        return confirmPassword.length > 0;
    }
}

function validateAllFields() {
    const username = document.getElementById("reg-user").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const confirmEmail = document.getElementById("reg-email-confirm").value.trim();
    const password = document.getElementById("reg-pass").value;
    const confirmPassword = document.getElementById("reg-pass-confirm").value;

    const usernameResult = validateUsername(username);
    const emailResult = validateEmail(email);
    const passwordResult = validatePassword(password);

    // Show errors for all fields
    const userInput = document.getElementById("reg-user");
    const userError = document.getElementById("reg-user-error");
    if (!usernameResult.valid) {
        userInput.classList.add("error");
        userError.textContent = usernameResult.error;
        userError.classList.add("visible");
    }

    const emailInput = document.getElementById("reg-email");
    const emailError = document.getElementById("reg-email-error");
    if (!emailResult.valid) {
        emailInput.classList.add("error");
        emailError.textContent = emailResult.error;
        emailError.classList.add("visible");
    }

    const passInput = document.getElementById("reg-pass");
    const passError = document.getElementById("reg-pass-error");
    if (!passwordResult.valid) {
        passInput.classList.add("error");
        passError.textContent = passwordResult.error;
        passError.classList.add("visible");
    }

    // Validate confirm fields
    const emailsMatch = validateConfirmEmail();
    const passwordsMatch = validateConfirmPassword();

    // Check if confirm fields are empty
    const confirmEmailInput = document.getElementById("reg-email-confirm");
    const confirmEmailError = document.getElementById("reg-email-confirm-error");
    if (!confirmEmail) {
        confirmEmailInput.classList.add("error");
        confirmEmailError.textContent = "Please confirm your email";
        confirmEmailError.classList.add("visible");
    }

    const confirmPassInput = document.getElementById("reg-pass-confirm");
    const confirmPassError = document.getElementById("reg-pass-confirm-error");
    if (!confirmPassword) {
        confirmPassInput.classList.add("error");
        confirmPassError.textContent = "Please confirm your password";
        confirmPassError.classList.add("visible");
    }

    return usernameResult.valid && emailResult.valid && passwordResult.valid && emailsMatch && passwordsMatch;
}

function showMessage(msg, type) {
    const el = document.getElementById("message");
    el.innerHTML = msg;  // Using innerHTML to support clickable links
    el.className = type; // 'success', 'error', or 'warning'
    el.classList.remove("hidden");
}

// ==================== VERIFICATION HANDLERS ====================

// Handle resend verification email
async function handleResend() {
    if (!pendingUser) {
        showMessage("No pending verification. Please register again.", "error");
        return;
    }

    const btn = document.getElementById("resend-btn");
    btn.disabled = true;
    btn.textContent = "Sending...";

    try {
        const res = await fetch("/verify/resend", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(pendingUser)
        });

        const data = await res.json();

        if (res.ok) {
            showMessage("Verification email resent! Check your inbox.", "success");
            btn.textContent = "Email Sent ✓";
            // Re-enable after 2 minutes (rate limit)
            setTimeout(() => {
                btn.disabled = false;
                btn.textContent = "Resend Email";
            }, 120000);
        } else if (res.status === 429) {
            showMessage("Please wait 2 minutes before resending.", "warning");
            btn.disabled = false;
            btn.textContent = "Resend Email";
        } else {
            showMessage(data.error || "Failed to resend email", "error");
            btn.disabled = false;
            btn.textContent = "Resend Email";
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
        btn.disabled = false;
        btn.textContent = "Resend Email";
    }
}

// Go back to login from verification pending
function backToLogin() {
    document.getElementById("verification-pending").classList.add("hidden");
    document.getElementById("resend-verification-section").classList.add("hidden");
    document.getElementById("forgot-password-section").classList.add("hidden");
    document.getElementById("reset-email-sent").classList.add("hidden");
    document.getElementById("login-section").classList.remove("hidden");
    document.getElementById("message").classList.add("hidden");
    pendingUser = null;
    pendingResendUsername = null;
    resetRecaptcha();
}

// Show resend verification section
function showResendVerification() {
    // Hide all sections
    document.getElementById("login-section").classList.add("hidden");
    document.getElementById("register-section").classList.add("hidden");
    document.getElementById("verification-pending").classList.add("hidden");
    document.getElementById("forgot-password-section").classList.add("hidden");
    document.getElementById("message").classList.add("hidden");

    // Show resend verification section
    document.getElementById("resend-verification-section").classList.remove("hidden");

    // Pre-fill username if we have it from failed login
    if (pendingResendUsername) {
        document.getElementById("resend-username").value = pendingResendUsername;
    }

    // Focus on email field
    document.getElementById("resend-email").focus();

    // Reset reCAPTCHA
    resetRecaptcha();
}

// Handle resend verification form submission
async function handleResendVerification() {
    const username = document.getElementById("resend-username").value.trim();
    const email = document.getElementById("resend-email").value.trim().toLowerCase();

    // Validate inputs
    const usernameResult = validateUsername(username);
    if (!usernameResult.valid) {
        showMessage(usernameResult.error, "error");
        return;
    }

    const emailResult = validateEmail(email);
    if (!emailResult.valid) {
        showMessage(emailResult.error, "error");
        return;
    }

    // Get reCAPTCHA response
    const recaptchaToken = getRecaptchaResponse('resend');

    try {
        const res = await fetch("/auth/resend-verification", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                email,
                recaptcha_token: recaptchaToken
            }),
        });

        const data = await res.json();

        if (res.ok) {
            if (data.already_verified) {
                // Already verified - redirect to login
                showMessage("Your email is already verified! You can log in now.", "success");
                setTimeout(() => {
                    backToLogin();
                }, 2000);
            } else {
                // Show verification pending screen
                document.getElementById("pending-email").textContent = email;
                document.getElementById("resend-verification-section").classList.add("hidden");
                document.getElementById("verification-pending").classList.remove("hidden");

                // Store user info for potential resend from pending screen
                pendingUser = { username, email };

                showMessage(data.message || "Verification email sent! Check your inbox.", "success");
            }
        } else if (res.status === 429) {
            showMessage("Too many requests. Please wait a few minutes and try again.", "warning");
            resetRecaptcha();
        } else {
            showMessage(data.error || "Failed to resend verification email", "error");
            resetRecaptcha();
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
        resetRecaptcha();
    }
}

// ==================== API HANDLERS ====================

async function handleRegister() {
    // Client-side validation first
    if (!validateAllFields()) {
        showMessage("Please fix the errors above", "error");
        return;
    }

    // Get reCAPTCHA response
    const recaptchaToken = getRecaptchaResponse('register');

    const username = document.getElementById("reg-user").value.trim();
    const email = document.getElementById("reg-email").value.trim().toLowerCase();
    const password = document.getElementById("reg-pass").value;

    try {
        const res = await fetch("/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                email,
                password,
                recaptcha_token: recaptchaToken
            }),
        });

        const data = await res.json();

        if (res.ok) {
            // Store user info for resend
            pendingUser = {
                user_id: data.user_id,
                email: email,
                username: username
            };

            // Show verification pending section
            document.getElementById("pending-email").textContent = email;
            document.getElementById("register-section").classList.add("hidden");
            document.getElementById("verification-pending").classList.remove("hidden");
            showMessage("Account created! Please check your email.", "success");
        } else if (res.status === 429) {
            showMessage("Too many requests. Please wait a minute and try again.", "warning");
            resetRecaptcha();
        } else {
            // Handle validation errors from backend
            if (data.details && Array.isArray(data.details)) {
                showMessage(data.details.join(". "), "error");
            } else {
                showMessage(data.error || "Registration failed", "error");
            }
            resetRecaptcha();
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
        resetRecaptcha();
    }
}

async function handleLogin() {
    const username = document.getElementById("login-user").value.trim();
    const password = document.getElementById("login-pass").value;

    if (!username || !password) {
        showMessage("Please enter username and password", "error");
        return;
    }

    // Get reCAPTCHA response
    const recaptchaToken = getRecaptchaResponse('login');

    try {
        const res = await fetch("/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                password,
                recaptcha_token: recaptchaToken
            }),
        });

        const data = await res.json();

        if (res.ok) {
            // Check if MFA is required
            if (data.mfa_required) {
                // Store MFA token for verification
                mfaToken = data.mfa_token;
                mfaUsername = username;

                // Show MFA section
                document.getElementById("login-section").classList.add("hidden");
                document.getElementById("mfa-section").classList.remove("hidden");
                document.getElementById("mfa-code").focus();
                showMessage("Enter the 6-digit code from your authenticator app", "success");
                return;
            }

            // Normal login (no MFA)
            accessToken = data.access_token;
            refreshToken = data.refresh_token;
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', refreshToken);

            showMessage(`Welcome back, ${data.user}! Redirecting to dashboard...`, "success");

            // Redirect to dashboard after short delay
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else if (res.status === 429) {
            showMessage("Too many login attempts. Please wait a minute and try again.", "warning");
            resetRecaptcha();
        } else if (res.status === 403 && data.verification_required) {
            showMessage('Email not verified. <a href="#" onclick="showResendVerification(); return false;">Resend verification email</a>', "warning");
            // Pre-store username for resend form
            pendingResendUsername = username;
            resetRecaptcha();
        } else {
            showMessage(data.error || "Login failed", "error");
            resetRecaptcha();
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
        resetRecaptcha();
    }
}

// MFA Verification handler
async function handleMFAVerify() {
    const code = document.getElementById("mfa-code").value.trim();

    if (!code || code.length !== 6) {
        showMessage("Please enter a 6-digit code", "error");
        return;
    }

    if (!mfaToken) {
        showMessage("Session expired. Please login again.", "error");
        cancelMFA();
        return;
    }

    try {
        const res = await fetch("/auth/login/mfa", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                mfa_token: mfaToken,
                totp_code: code
            }),
        });

        const data = await res.json();

        if (res.ok) {
            // MFA verified - complete login
            accessToken = data.access_token;
            refreshToken = data.refresh_token;
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', refreshToken);

            // Clear MFA state
            mfaToken = null;
            mfaUsername = null;

            showMessage(`Welcome back, ${data.user}! Redirecting to dashboard...`, "success");

            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else if (res.status === 401) {
            showMessage(data.error || "Invalid code. Please try again.", "error");
            document.getElementById("mfa-code").value = "";
            document.getElementById("mfa-code").focus();
        } else {
            showMessage(data.error || "Verification failed", "error");
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
    }
}

// Cancel MFA and return to login
function cancelMFA() {
    mfaToken = null;
    mfaUsername = null;
    document.getElementById("mfa-section").classList.add("hidden");
    document.getElementById("login-section").classList.remove("hidden");
    document.getElementById("mfa-code").value = "";
    document.getElementById("login-pass").value = "";
    document.getElementById("message").classList.add("hidden");
}

function toggleView() {
    document.getElementById("login-section").classList.toggle("hidden");
    document.getElementById("register-section").classList.toggle("hidden");
    document.getElementById("message").classList.add("hidden");
    document.getElementById("token-display").classList.add("hidden");

    // Clear any error states
    document.querySelectorAll("input").forEach(input => {
        input.classList.remove("error");
        input.value = "";
    });
    document.querySelectorAll(".error-text").forEach(span => {
        span.classList.remove("visible");
    });

    // Reset reCAPTCHA
    resetRecaptcha();
}

// ==================== PASSWORD RESET HANDLERS ====================

function showForgotPassword() {
    // Hide all sections
    document.getElementById("login-section").classList.add("hidden");
    document.getElementById("register-section").classList.add("hidden");
    document.getElementById("verification-pending").classList.add("hidden");
    document.getElementById("message").classList.add("hidden");

    // Show forgot password section
    document.getElementById("forgot-password-section").classList.remove("hidden");

    // Reset reCAPTCHA
    resetRecaptcha();
}

function validateResetConfirmPassword() {
    const password = document.getElementById("reset-pass").value;
    const confirmPassword = document.getElementById("reset-pass-confirm").value;
    const confirmInput = document.getElementById("reset-pass-confirm");
    const confirmError = document.getElementById("reset-pass-confirm-error");

    if (confirmPassword.length > 0 && password !== confirmPassword) {
        confirmInput.classList.add("error");
        confirmError.textContent = "Passwords do not match";
        confirmError.classList.add("visible");
        return false;
    } else {
        confirmInput.classList.remove("error");
        confirmError.classList.remove("visible");
        return confirmPassword.length > 0;
    }
}

async function handleForgotPassword() {
    const email = document.getElementById("forgot-email").value.trim().toLowerCase();

    // Validate email
    const emailResult = validateEmail(email);
    if (!emailResult.valid) {
        showMessage(emailResult.error, "error");
        return;
    }

    // Get reCAPTCHA response
    const recaptchaToken = getRecaptchaResponse('forgot');

    try {
        const res = await fetch("/auth/forgot-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email,
                recaptcha_token: recaptchaToken
            }),
        });

        const data = await res.json();

        if (res.ok) {
            // Show success message section
            document.getElementById("forgot-password-section").classList.add("hidden");
            document.getElementById("reset-email-sent").classList.remove("hidden");
        } else if (res.status === 429) {
            showMessage("Too many requests. Please wait a few minutes and try again.", "warning");
            resetRecaptcha();
        } else {
            showMessage(data.error || "Request failed", "error");
            resetRecaptcha();
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
        resetRecaptcha();
    }
}

async function handleResetPassword() {
    const password = document.getElementById("reset-pass").value;
    const confirmPassword = document.getElementById("reset-pass-confirm").value;

    // Validate password
    const passwordResult = validatePassword(password);
    if (!passwordResult.valid) {
        showMessage(passwordResult.error, "error");
        return;
    }

    // Check passwords match
    if (password !== confirmPassword) {
        showMessage("Passwords do not match", "error");
        return;
    }

    if (!resetToken) {
        showMessage("Invalid or missing reset token. Please request a new password reset.", "error");
        return;
    }

    try {
        const res = await fetch("/auth/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                token: resetToken,
                password: password
            }),
        });

        const data = await res.json();

        if (res.ok) {
            showMessage("Password reset successful! Redirecting to login...", "success");

            // Clear the token from URL
            window.history.replaceState({}, document.title, window.location.pathname);

            // Redirect to login after delay
            setTimeout(() => {
                document.getElementById("reset-password-section").classList.add("hidden");
                document.getElementById("login-section").classList.remove("hidden");
            }, 2000);
        } else {
            showMessage(data.error || "Password reset failed", "error");
        }
    } catch (err) {
        showMessage("Network error. Please try again.", "error");
    }
}

// ==================== SESSION MANAGEMENT ====================

async function handleLogout() {
    try {
        await fetch("/auth/logout", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                refresh_token: refreshToken
            }),
        });
    } catch (err) {
        console.error("Logout request failed:", err);
    }

    // Clear tokens regardless of API response
    accessToken = null;
    refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');

    // Redirect to login
    window.location.href = '/';
}

async function refreshAccessToken() {
    if (!refreshToken) {
        return false;
    }

    try {
        const res = await fetch("/auth/refresh", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                refresh_token: refreshToken
            }),
        });

        if (res.ok) {
            const data = await res.json();
            accessToken = data.access_token;
            localStorage.setItem('accessToken', accessToken);
            return true;
        } else {
            // Refresh token invalid/expired - clear and redirect to login
            accessToken = null;
            refreshToken = null;
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            return false;
        }
    } catch (err) {
        console.error("Token refresh failed:", err);
        return false;
    }
}

// ==================== PAGE INITIALIZATION ====================

// Check for password reset token in URL on page load
document.addEventListener('DOMContentLoaded', function () {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (token) {
        // We have a reset token - show reset password form
        resetToken = token;
        document.getElementById("login-section").classList.add("hidden");
        document.getElementById("reset-password-section").classList.remove("hidden");
    }
});
