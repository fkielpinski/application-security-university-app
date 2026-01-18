-- Create databases
CREATE DATABASE auth_db;
CREATE DATABASE meme_db;
CREATE DATABASE verification_db;
CREATE DATABASE mfa_db;

-- Connect to auth_db and add role column support
\c auth_db;

-- Note: The users table is created by auth_service on startup.
-- This extension ensures role column exists for new installations.

-- Connect to meme_db and create tables
\c meme_db;

-- Memes/Posts table
CREATE TABLE IF NOT EXISTS memes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username VARCHAR(80) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    image_filename VARCHAR(255),
    image_mimetype VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    meme_id INTEGER NOT NULL REFERENCES memes(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL,
    username VARCHAR(80) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ratings table (prevents duplicate votes per user per meme)
CREATE TABLE IF NOT EXISTS ratings (
    id SERIAL PRIMARY KEY,
    meme_id INTEGER NOT NULL REFERENCES memes(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL,
    rating SMALLINT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(meme_id, user_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_memes_user_id ON memes(user_id);
CREATE INDEX IF NOT EXISTS idx_memes_created_at ON memes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_meme_id ON comments(meme_id);
CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id);
CREATE INDEX IF NOT EXISTS idx_ratings_meme_id ON ratings(meme_id);

-- Full-text search index for meme search
CREATE INDEX IF NOT EXISTS idx_memes_title_search ON memes USING gin(to_tsvector('english', title));
CREATE INDEX IF NOT EXISTS idx_memes_desc_search ON memes USING gin(to_tsvector('english', COALESCE(description, '')));
