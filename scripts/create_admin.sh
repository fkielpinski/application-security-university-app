#!/bin/bash
# ============================================================
# Admin User Creation Script
# 
# Creates an admin user for the Meme App.
# Run this after the containers are up and running.
#
# Usage:
#   ./scripts/create_admin.sh <username>
#   ./scripts/create_admin.sh admin
# ============================================================

set -e

if [ -z "$1" ]; then
    echo "Usage: ./scripts/create_admin.sh <username>"
    echo "Example: ./scripts/create_admin.sh admin"
    exit 1
fi

USERNAME=$1

echo "🔧 Promoting user '$USERNAME' to admin role..."

# Find the database container
DB_CONTAINER=$(docker ps -qf "name=db")

if [ -z "$DB_CONTAINER" ]; then
    echo "Error: Database container not found. Is the app running?"
    echo "   Run: docker compose up -d"
    exit 1
fi

# Check if user exists
USER_EXISTS=$(docker exec -i $DB_CONTAINER psql -U postgres -d auth_db -t -c "SELECT COUNT(*) FROM users WHERE username = '$USERNAME';" 2>/dev/null | tr -d ' ')

if [ "$USER_EXISTS" = "0" ]; then
    echo "Error: User '$USERNAME' not found in database."
    echo "   Please register the user first at http://localhost/login"
    exit 1
fi

# Promote to admin
docker exec -i $DB_CONTAINER psql -U postgres -d auth_db -c "UPDATE users SET role = 'admin' WHERE username = '$USERNAME';"

echo "User '$USERNAME' is now an administrator!"
echo ""
echo "Note: The user must log out and log back in for the new role to take effect."
echo "      (The role is embedded in the JWT token)"
