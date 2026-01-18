/**
 * Meme Dashboard JavaScript
 * 
 * Security Features:
 * - XSS prevention: Uses textContent for user data, never innerHTML with unsanitized content
 * - Safe DOM manipulation: Creates elements properly
 * - Token handling: Secure storage and header attachment
 */

// Session state
let accessToken = localStorage.getItem('accessToken');
let refreshToken = localStorage.getItem('refreshToken');
let currentUser = null;
let currentOffset = 0;
let currentLimit = 20;
let currentSearchQuery = '';
let totalMemes = 0;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
    checkAuth();

    // Add enter key handler for search
    document.getElementById('search-input').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
});

/**
 * Parse JWT payload (without validation - validation happens server-side)
 */
function parseJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        return JSON.parse(atob(parts[1]));
    } catch (e) {
        return null;
    }
}

/**
 * Check authentication status and update UI accordingly
 */
function checkAuth() {
    if (!accessToken) {
        showGuestMode();
        loadMemes();
        return;
    }

    const payload = parseJWT(accessToken);
    if (!payload) {
        showGuestMode();
        loadMemes();
        return;
    }

    // Check token expiry
    if (payload.exp && payload.exp * 1000 < Date.now()) {
        // Token expired - try to refresh
        refreshAccessToken().then(success => {
            if (success) {
                const newPayload = parseJWT(accessToken);
                showAuthenticatedMode(newPayload);
            } else {
                showGuestMode();
            }
            loadMemes();
        });
        return;
    }

    showAuthenticatedMode(payload);
    loadMemes();
}

/**
 * Show guest mode UI
 */
function showGuestMode() {
    currentUser = null;
    document.getElementById('greeting').textContent = 'Guest';
    document.getElementById('login-prompt').classList.remove('hidden');
    document.getElementById('welcome-section').classList.add('hidden');
    document.getElementById('create-section').classList.add('hidden');
    document.getElementById('admin-panel').classList.add('hidden');
    document.getElementById('settings-link').classList.add('hidden');
    document.getElementById('logout-btn').classList.add('hidden');
    document.getElementById('role-badge').classList.add('hidden');
    document.getElementById('auth-status').textContent = 'Guest Mode';
}

/**
 * Show authenticated user UI
 */
function showAuthenticatedMode(payload) {
    currentUser = {
        user_id: payload.user_id,
        username: payload.username,
        role: payload.role || 'user'
    };

    document.getElementById('greeting').textContent = payload.username;
    document.getElementById('welcome-message').textContent = `Hello, ${escapeHtml(payload.username)}`;

    document.getElementById('login-prompt').classList.add('hidden');
    document.getElementById('welcome-section').classList.remove('hidden');
    document.getElementById('create-section').classList.remove('hidden');
    document.getElementById('settings-link').classList.remove('hidden');
    document.getElementById('logout-btn').classList.remove('hidden');

    // Show role badge
    const roleBadge = document.getElementById('role-badge');
    if (currentUser.role === 'admin') {
        roleBadge.textContent = 'Admin';
        roleBadge.className = 'role-badge admin';
        document.getElementById('admin-panel').classList.remove('hidden');
        document.getElementById('auth-status').textContent = 'Administrator';
    } else {
        roleBadge.textContent = 'User';
        roleBadge.className = 'role-badge user';
        document.getElementById('admin-panel').classList.add('hidden');
        document.getElementById('auth-status').textContent = 'Authenticated User';
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Make authenticated API request
 */
async function apiRequest(url, options = {}) {
    const headers = {
        ...options.headers
    };

    if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }

    if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, {
        ...options,
        headers
    });

    // Handle 401 - try token refresh
    if (response.status === 401 && refreshToken) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            headers['Authorization'] = `Bearer ${accessToken}`;
            return fetch(url, { ...options, headers });
        }
    }

    return response;
}

/**
 * Refresh access token
 */
async function refreshAccessToken() {
    if (!refreshToken) return false;

    try {
        const res = await fetch("/auth/refresh", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: refreshToken }),
        });

        if (res.ok) {
            const data = await res.json();
            accessToken = data.access_token;
            localStorage.setItem('accessToken', accessToken);
            return true;
        }

        // Refresh failed - clear tokens
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        accessToken = null;
        refreshToken = null;
        return false;
    } catch (err) {
        return false;
    }
}

/**
 * Load memes from API
 */
async function loadMemes() {
    const memeGrid = document.getElementById('meme-grid');
    memeGrid.innerHTML = '<div class="loading">Loading memes...</div>';

    try {
        let url = `/memes?offset=${currentOffset}&limit=${currentLimit}`;
        if (currentSearchQuery) {
            url = `/memes/search?q=${encodeURIComponent(currentSearchQuery)}&offset=${currentOffset}&limit=${currentLimit}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to load memes');
        }

        totalMemes = data.total || 0;
        document.getElementById('total-memes-count').textContent = `Total Memes: ${totalMemes}`;

        renderMemes(data.memes || []);
        updatePagination();
    } catch (err) {
        memeGrid.innerHTML = `<div class="error-message">Failed to load memes: ${escapeHtml(err.message)}</div>`;
    }
}

/**
 * Render memes to grid
 */
function renderMemes(memes) {
    const memeGrid = document.getElementById('meme-grid');

    if (memes.length === 0) {
        memeGrid.innerHTML = '<div class="no-content">No memes found. Be the first to create one!</div>';
        return;
    }

    memeGrid.innerHTML = '';

    memes.forEach(meme => {
        const card = document.createElement('div');
        card.className = 'meme-card';
        card.onclick = () => openMemeDetail(meme.id);

        // Image or placeholder
        const imageContainer = document.createElement('div');
        imageContainer.className = 'meme-image-container';

        if (meme.image_url) {
            const img = document.createElement('img');
            img.src = meme.image_url;
            img.alt = meme.title;
            img.className = 'meme-image';
            img.loading = 'lazy';
            imageContainer.appendChild(img);
        } else {
            imageContainer.innerHTML = '<div class="meme-placeholder">🎭</div>';
        }
        card.appendChild(imageContainer);

        // Info section
        const info = document.createElement('div');
        info.className = 'meme-info';

        const title = document.createElement('h3');
        title.className = 'meme-title';
        title.textContent = meme.title;
        info.appendChild(title);

        const meta = document.createElement('div');
        meta.className = 'meme-meta';

        const author = document.createElement('span');
        author.className = 'meme-author';
        author.textContent = `by ${meme.username}`;
        meta.appendChild(author);

        const stats = document.createElement('span');
        stats.className = 'meme-stats';
        stats.id = `meme-card-stats-${meme.id}`;
        stats.dataset.comments = meme.comment_count;
        stats.textContent = `${meme.avg_rating}/5 (${meme.rating_count}) | ${meme.comment_count} Comments`;
        meta.appendChild(stats);

        if (currentUser && (currentUser.user_id === meme.user_id || currentUser.role === 'admin')) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn-delete-meme';
            deleteBtn.textContent = 'DELETE';
            deleteBtn.title = 'Delete meme';
            deleteBtn.onclick = (e) => {
                e.stopPropagation();
                deleteMeme(meme.id);
            };
            meta.appendChild(deleteBtn);
        }

        info.appendChild(meta);
        card.appendChild(info);

        // (Removed appendChild to card)

        memeGrid.appendChild(card);
    });
}

/**
 * Open meme detail modal
 */
async function openMemeDetail(memeId) {
    const modal = document.getElementById('meme-modal');
    const modalBody = document.getElementById('modal-body');

    modalBody.innerHTML = '<div class="loading">Loading...</div>';
    modal.classList.remove('hidden');

    try {
        const response = await fetch(`/memes/${memeId}`);
        const meme = await response.json();

        if (!response.ok) {
            throw new Error(meme.error || 'Failed to load meme');
        }

        renderMemeDetail(meme);
    } catch (err) {
        modalBody.innerHTML = `<div class="error-message">${escapeHtml(err.message)}</div>`;
    }
}

/**
 * Render meme detail in modal
 */
function renderMemeDetail(meme) {
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = '';

    // Title
    const title = document.createElement('h2');
    title.textContent = meme.title;
    modalBody.appendChild(title);

    // Image
    if (meme.image_url) {
        const img = document.createElement('img');
        img.src = meme.image_url;
        img.alt = meme.title;
        img.className = 'meme-detail-image';
        modalBody.appendChild(img);
    }

    // Description
    if (meme.description) {
        const desc = document.createElement('p');
        desc.className = 'meme-description';
        desc.textContent = meme.description;
        modalBody.appendChild(desc);
    }

    // Meta info
    const meta = document.createElement('div');
    meta.className = 'meme-detail-meta';
    meta.innerHTML = `
        <span>Posted by <strong>${escapeHtml(meme.username)}</strong></span>
        <span id="meme-modal-rating-${meme.id}">RATING: ${meme.avg_rating}/5 (${meme.rating_count})</span>
    `;
    modalBody.appendChild(meta);

    // Rating section (authenticated users only)
    if (currentUser) {
        const ratingSection = document.createElement('div');
        ratingSection.className = 'rating-section';
        ratingSection.innerHTML = `
            <h4>RATE THIS MEME</h4>
            <div class="rating-buttons">
                ${[1, 2, 3, 4, 5].map(r =>
            `<button class="btn-rate" onclick="rateMeme(${meme.id}, ${r})">${r}</button>`
        ).join('')}
            </div>
            <div id="rating-result-${meme.id}" class="rating-result"></div>
        `;
        modalBody.appendChild(ratingSection);
    }

    // Comments section
    const commentsSection = document.createElement('div');
    commentsSection.className = 'comments-section';
    commentsSection.innerHTML = '<h4>COMMENTS</h4>';

    // Comment form (authenticated users only)
    if (currentUser) {
        const commentForm = document.createElement('form');
        commentForm.className = 'comment-form';
        commentForm.onsubmit = (e) => handleAddComment(e, meme.id);
        commentForm.innerHTML = `
            <textarea id="comment-input-${meme.id}" placeholder="Write a comment..." maxlength="1000" required></textarea>
            <button type="submit" class="btn btn-primary">POST COMMENT</button>
        `;
        commentsSection.appendChild(commentForm);
    }

    // Comments list
    const commentsList = document.createElement('div');
    commentsList.id = `comments-list-${meme.id}`;
    commentsList.className = 'comments-list';

    if (meme.comments && meme.comments.length > 0) {
        meme.comments.forEach(comment => {
            commentsList.appendChild(createCommentElement(meme.id, comment));
        });
    } else {
        commentsList.innerHTML = '<p class="no-comments">No comments yet. Be the first!</p>';
    }

    commentsSection.appendChild(commentsList);
    modalBody.appendChild(commentsSection);
}

/**
 * Create a comment element
 */
function createCommentElement(memeId, comment) {
    const div = document.createElement('div');
    div.className = 'comment';
    div.id = `comment-${comment.id}`;

    const header = document.createElement('div');
    header.className = 'comment-header';

    const author = document.createElement('strong');
    author.textContent = comment.username;
    header.appendChild(author);

    const date = document.createElement('span');
    date.className = 'comment-date';
    date.textContent = new Date(comment.created_at).toLocaleDateString();
    header.appendChild(date);

    // Delete button for owner/admin
    if (currentUser && (currentUser.user_id == comment.user_id || currentUser.role === 'admin')) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-delete-comment';
        deleteBtn.textContent = 'DELETE';
        deleteBtn.onclick = () => deleteComment(memeId, comment.id);
        header.appendChild(deleteBtn);
    }

    div.appendChild(header);

    const content = document.createElement('p');
    content.textContent = comment.content;
    div.appendChild(content);

    return div;
}

/**
 * Close modal
 */
function closeModal() {
    document.getElementById('meme-modal').classList.add('hidden');
}

// Close modal on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// Close modal on click outside (backdrop click)
document.getElementById('meme-modal').addEventListener('click', (e) => {
    if (e.target.id === 'meme-modal') {
        closeModal();
    }
});

/**
 * Handle create meme form submission
 */
async function handleCreateMeme(event) {
    event.preventDefault();

    const errorEl = document.getElementById('create-error');
    const successEl = document.getElementById('create-success');
    errorEl.classList.add('hidden');
    successEl.classList.add('hidden');

    const formData = new FormData();
    formData.append('title', document.getElementById('meme-title').value);
    formData.append('description', document.getElementById('meme-description').value);

    const imageFile = document.getElementById('meme-image').files[0];
    if (!imageFile) {
        errorEl.textContent = 'Image upload is required.';
        errorEl.classList.remove('hidden');
        return;
    }

    if (imageFile) {
        // Check file size client-side
        if (imageFile.size > 5 * 1024 * 1024) {
            errorEl.textContent = 'File too large. Maximum size is 5MB.';
            errorEl.classList.remove('hidden');
            return;
        }
        formData.append('image', imageFile);
    }

    try {
        const response = await apiRequest('/memes', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to create meme');
        }

        successEl.textContent = 'Meme created successfully!';
        successEl.classList.remove('hidden');

        // Reset form
        document.getElementById('create-meme-form').reset();

        // Reload memes
        currentOffset = 0;
        loadMemes();

    } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    }
}

/**
 * Handle adding a comment
 */
async function handleAddComment(event, memeId) {
    event.preventDefault();

    const input = document.getElementById(`comment-input-${memeId}`);
    const content = input.value.trim();

    if (!content) return;

    try {
        const response = await apiRequest(`/memes/${memeId}/comments`, {
            method: 'POST',
            body: JSON.stringify({ content })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to add comment');
        }

        // Add comment to list
        const commentsList = document.getElementById(`comments-list-${memeId}`);
        const noComments = commentsList.querySelector('.no-comments');
        if (noComments) noComments.remove();

        commentsList.appendChild(createCommentElement(memeId, data.comment));
        input.value = '';

    } catch (err) {
        alert('Failed to add comment: ' + err.message);
    }
}

/**
 * Rate a meme
 */
async function rateMeme(memeId, rating) {
    if (!currentUser) {
        alert('Please log in to rate memes');
        return;
    }

    try {
        const response = await apiRequest(`/memes/${memeId}/rate`, {
            method: 'POST',
            body: JSON.stringify({ rating })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to rate meme');
        }

        const resultEl = document.getElementById(`rating-result-${memeId}`);
        resultEl.textContent = `You rated: ${data.your_rating}/5`;
        resultEl.className = 'rating-result success';

        // Update modal header stats
        const ratingStatEl = document.getElementById(`meme-modal-rating-${memeId}`);
        if (ratingStatEl) {
            ratingStatEl.textContent = `RATING: ${data.avg_rating}/5 (${data.rating_count})`;
        }

        // Update grid card stats
        const cardStatEl = document.getElementById(`meme-card-stats-${memeId}`);
        if (cardStatEl) {
            const comments = cardStatEl.dataset.comments || 0;
            cardStatEl.textContent = `${data.avg_rating}/5 (${data.rating_count}) | ${comments} Comments`;
        }

    } catch (err) {
        alert('Failed to rate: ' + err.message);
    }
}

/**
 * Delete a meme
 */
async function deleteMeme(memeId) {
    if (!confirm('Are you sure you want to delete this meme?')) {
        return;
    }

    try {
        const response = await apiRequest(`/memes/${memeId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to delete meme');
        }

        closeModal();
        loadMemes();

    } catch (err) {
        alert('Failed to delete: ' + err.message);
    }
}

/**
 * Delete a comment
 */
async function deleteComment(memeId, commentId) {
    if (!confirm('Delete this comment?')) return;

    try {
        const response = await apiRequest(`/memes/${memeId}/comments/${commentId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to delete comment');
        }

        // Remove comment from DOM
        const commentEl = document.getElementById(`comment-${commentId}`);
        if (commentEl) commentEl.remove();

    } catch (err) {
        alert('Failed to delete comment: ' + err.message);
    }
}

/**
 * Perform search
 */
function performSearch() {
    const query = document.getElementById('search-input').value.trim();
    if (!query) return;

    currentSearchQuery = query;
    currentOffset = 0;

    document.getElementById('search-info').classList.remove('hidden');
    document.getElementById('search-query-display').textContent = `Searching: "${query}"`;

    loadMemes();
}

/**
 * Clear search
 */
function clearSearch() {
    currentSearchQuery = '';
    currentOffset = 0;
    document.getElementById('search-input').value = '';
    document.getElementById('search-info').classList.add('hidden');
    loadMemes();
}

/**
 * Update pagination buttons
 */
function updatePagination() {
    const pagination = document.getElementById('pagination');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');

    const totalPages = Math.ceil(totalMemes / currentLimit);
    const currentPage = Math.floor(currentOffset / currentLimit) + 1;

    if (totalMemes > currentLimit) {
        pagination.classList.remove('hidden');
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
        prevBtn.disabled = currentOffset === 0;
        nextBtn.disabled = currentOffset + currentLimit >= totalMemes;
    } else {
        pagination.classList.add('hidden');
    }
}

/**
 * Load page
 */
function loadPage(direction) {
    currentOffset += direction * currentLimit;
    if (currentOffset < 0) currentOffset = 0;
    loadMemes();
    window.scrollTo(0, 0);
}

/**
 * Handle logout
 */
async function handleLogout() {
    try {
        await fetch("/auth/logout", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${accessToken}`
            },
            body: JSON.stringify({ refresh_token: refreshToken }),
        });
    } catch (err) {
        // Continue with local cleanup
    }

    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    window.location.href = '/login';
}
