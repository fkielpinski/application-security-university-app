// Account Settings JavaScript

let accessToken = localStorage.getItem('accessToken');
let refreshToken = localStorage.getItem('refreshToken');

// Initialize
document.addEventListener('DOMContentLoaded', function () {
    checkAuth();
});

function checkAuth() {
    if (!accessToken) {
        showLoginPrompt();
        return;
    }

    try {
        const parts = accessToken.split('.');
        if (parts.length !== 3) throw new Error('Invalid token');

        const payload = JSON.parse(atob(parts[1]));

        if (payload.exp && payload.exp * 1000 < Date.now()) {
            refreshAccessToken().then(refreshed => {
                if (refreshed) {
                    loadSettings();
                } else {
                    showLoginPrompt();
                }
            });
            return;
        }

        loadSettings();
    } catch (e) {
        showLoginPrompt();
    }
}

function showLoginPrompt() {
    document.getElementById('greeting').textContent = 'Not logged in';
    document.getElementById('login-prompt').classList.remove('hidden');
    document.getElementById('settings-content').classList.add('hidden');
}

async function loadSettings() {
    const settingsContent = document.getElementById('settings-content');
    const loginPrompt = document.getElementById('login-prompt');

    loginPrompt.classList.add('hidden');
    settingsContent.classList.remove('hidden');

    // Load profile
    try {
        const res = await fetch('/account/profile', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });

        if (res.ok) {
            const data = await res.json();
            document.getElementById('greeting').textContent = data.username;
            document.getElementById('profile-username').textContent = data.username;
            document.getElementById('profile-email').textContent = data.email;
            updateMFAStatus(data.mfa_enabled);
        } else if (res.status === 401) {
            showLoginPrompt();
            return;
        }
    } catch (e) {
        showToast('Failed to load profile', 'error');
    }

    // Load sessions
    loadSessions();
}

function updateMFAStatus(enabled) {
    const badge = document.getElementById('mfa-badge');
    const enabledSection = document.getElementById('mfa-enabled');
    const disabledSection = document.getElementById('mfa-disabled');
    const setupSection = document.getElementById('mfa-setup');
    const disableForm = document.getElementById('mfa-disable-form');

    setupSection.classList.add('hidden');
    disableForm.classList.add('hidden');

    if (enabled) {
        badge.textContent = '✓ Enabled';
        badge.className = 'status-badge enabled';
        enabledSection.classList.remove('hidden');
        disabledSection.classList.add('hidden');
    } else {
        badge.textContent = 'Not Enabled';
        badge.className = 'status-badge disabled';
        enabledSection.classList.add('hidden');
        disabledSection.classList.remove('hidden');
    }
}

// MFA Functions
async function setupMFA() {
    try {
        const res = await fetch('/account/mfa/setup', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (res.ok) {
            const data = await res.json();

            // Show QR code
            document.getElementById('qr-code-container').innerHTML =
                `<img src="${data.qr_code}" alt="QR Code" />`;

            // Show secret
            document.getElementById('mfa-secret').textContent = data.secret;

            // Show backup codes
            if (data.backup_codes) {
                const codesContainer = document.getElementById('backup-codes');
                codesContainer.innerHTML = data.backup_codes
                    .map(code => `<code>${code}</code>`)
                    .join('');
                document.getElementById('backup-codes-container').classList.remove('hidden');
            }

            // Show setup section
            document.getElementById('mfa-disabled').classList.add('hidden');
            document.getElementById('mfa-setup').classList.remove('hidden');
        } else {
            showToast('Failed to setup MFA', 'error');
        }
    } catch (e) {
        showToast('Error setting up MFA', 'error');
    }
}

async function enableMFA() {
    const code = document.getElementById('totp-code').value.trim();

    if (!code || code.length !== 6) {
        showToast('Please enter a 6-digit code', 'error');
        return;
    }

    try {
        const res = await fetch('/account/mfa/enable', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ totp_code: code })
        });

        if (res.ok) {
            showToast('MFA enabled successfully!', 'success');
            updateMFAStatus(true);
        } else {
            const data = await res.json();
            showToast(data.error || 'Invalid code', 'error');
        }
    } catch (e) {
        showToast('Error enabling MFA', 'error');
    }
}

function showDisableMFA() {
    document.getElementById('mfa-enabled').classList.add('hidden');
    document.getElementById('mfa-disable-form').classList.remove('hidden');
}

function cancelDisableMFA() {
    document.getElementById('mfa-disable-form').classList.add('hidden');
    document.getElementById('mfa-enabled').classList.remove('hidden');
    document.getElementById('disable-totp-code').value = '';
}

async function disableMFA() {
    const code = document.getElementById('disable-totp-code').value.trim();

    if (!code || code.length !== 6) {
        showToast('Please enter a 6-digit code', 'error');
        return;
    }

    try {
        const res = await fetch('/account/mfa/disable', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ totp_code: code })
        });

        if (res.ok) {
            showToast('MFA disabled', 'success');
            updateMFAStatus(false);
        } else {
            const data = await res.json();
            showToast(data.error || 'Invalid code', 'error');
        }
    } catch (e) {
        showToast('Error disabling MFA', 'error');
    }
}

// Password Change
async function changePassword(event) {
    event.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (newPassword !== confirmPassword) {
        showToast('Passwords do not match', 'error');
        return;
    }

    try {
        const res = await fetch('/account/password', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        if (res.ok) {
            showToast('Password changed! Please log in again.', 'success');
            document.getElementById('password-form').reset();
            setTimeout(() => {
                localStorage.clear();
                window.location.href = '/';
            }, 2000);
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to change password', 'error');
        }
    } catch (e) {
        showToast('Error changing password', 'error');
    }
}

// Email Change
async function changeEmail(event) {
    event.preventDefault();

    const newEmail = document.getElementById('new-email').value;
    const password = document.getElementById('email-password').value;

    try {
        const res = await fetch('/account/email', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: newEmail,
                password: password
            })
        });

        if (res.ok) {
            showToast('Email updated successfully!', 'success');
            document.getElementById('email-form').reset();
            loadSettings(); // Refresh profile
        } else {
            const data = await res.json();
            showToast(data.error || 'Failed to update email', 'error');
        }
    } catch (e) {
        showToast('Error updating email', 'error');
    }
}

// Sessions
async function loadSessions() {
    try {
        const res = await fetch('/account/sessions', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });

        if (res.ok) {
            const data = await res.json();
            const list = document.getElementById('sessions-list');

            if (data.sessions.length === 0) {
                list.innerHTML = '<p class="muted">No active sessions</p>';
            } else {
                list.innerHTML = data.sessions.slice(0, 5).map(s => `
                    <div class="session-item">
                        <div class="session-info">
                            <div class="session-agent">${escapeHtml(s.user_agent.substring(0, 50) || 'Unknown device')}</div>
                            <div class="session-meta">${s.ip_address || 'Unknown IP'}</div>
                        </div>
                    </div>
                `).join('');
            }
        }
    } catch (e) {
        document.getElementById('sessions-list').innerHTML =
            '<p class="muted">Could not load sessions</p>';
    }
}

async function revokeSessions() {
    if (!confirm('This will log you out of all devices. Continue?')) return;

    try {
        const res = await fetch('/account/sessions', {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });

        if (res.ok) {
            showToast('All sessions revoked. Logging out...', 'success');
            setTimeout(() => {
                localStorage.clear();
                window.location.href = '/';
            }, 2000);
        } else {
            showToast('Failed to revoke sessions', 'error');
        }
    } catch (e) {
        showToast('Error revoking sessions', 'error');
    }
}

// Token Refresh
async function refreshAccessToken() {
    if (!refreshToken) return false;

    try {
        const res = await fetch('/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (res.ok) {
            const data = await res.json();
            accessToken = data.access_token;
            localStorage.setItem('accessToken', accessToken);
            return true;
        }
        return false;
    } catch (e) {
        return false;
    }
}

// Utilities
function showToast(message, type) {
    const toast = document.getElementById('message-toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');

    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
