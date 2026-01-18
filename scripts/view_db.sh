#!/bin/bash
# Database Viewer Script for Meme App Security
# Displays authentication-related database records

set -e

DB_CONTAINER="meme-app-sec-university-db-1"

echo "=============================================="
echo "  🔐 Meme App Database Viewer"
echo "=============================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📋 AUTH_DB Tables:${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d auth_db -c "\dt"

echo ""
echo -e "${GREEN}👤 USERS${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d auth_db -c "SELECT id, username, email, LEFT(password_hash, 30) || '...' as password_hash_preview FROM users;"

echo ""
echo -e "${GREEN}🔑 REFRESH TOKENS${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d auth_db -c "SELECT id, user_id, LEFT(token_hash, 20) as token_hash_preview, revoked, created_at::date as created, expires_at::date as expires FROM refresh_tokens ORDER BY created_at DESC LIMIT 10;"

echo ""
echo -e "${GREEN}🚫 TOKEN BLACKLIST (Invalidated Access Tokens)${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d auth_db -c "SELECT id, jti, expires_at FROM token_blacklist ORDER BY id DESC LIMIT 10;"

echo ""
echo -e "${GREEN}🔄 PASSWORD RESET TOKENS${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d auth_db -c "SELECT id, user_id, email, used, created_at::date as created, expires_at as expires FROM password_reset_tokens ORDER BY id DESC LIMIT 5;"

echo ""
echo -e "${BLUE}📋 MFA_DB Tables:${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d mfa_db -c "\dt"

echo ""
echo -e "${GREEN}🔐 MFA SECRETS${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d mfa_db -c "SELECT user_id, LEFT(secret_encrypted, 25) || '...' as secret_preview, enabled, enabled_at::date as enabled_date, last_used_at FROM mfa_secrets;"

echo ""
echo -e "${GREEN}🔢 MFA BACKUP CODES${NC}"
echo "----------------------------------------------"
docker exec $DB_CONTAINER psql -U postgres -d mfa_db -c "SELECT user_id, COUNT(*) as total_codes, COUNT(*) FILTER (WHERE used = false) as unused_codes, COUNT(*) FILTER (WHERE used = true) as used_codes FROM mfa_backup_codes GROUP BY user_id;"

echo ""
echo "=============================================="
echo "  ✅ Database scan complete"
echo "=============================================="
