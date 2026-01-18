# Application Security University App

![Docker](https://img.shields.io/badge/deployment-docker--compose-orange.svg)
![Security](https://img.shields.io/badge/security-OWASP%20Hardened-blue.svg)

A security-focused microservices web application demonstrating robust authentication, authorization, and modern security practices.

---

## Quick Start

### Prerequisites
- Docker & Docker Compose

### Launch

```bash
# Configure environment (defaults are safe for local development)
cp .env.template .env

# Start all services
docker compose up -d --build
```

### Access

| Service              | URL                                      |
|----------------------|------------------------------------------|
| **Main Application** | [http://localhost](http://localhost)     |
| **Email Testing**    | [http://localhost:8025](http://localhost:8025) |

---

## Admin User Management

### Promoting a User to Administrator

After a user has registered through the web interface, you can promote them to admin using the included script:

```bash
./scripts/create_admin.sh <username>
```

**Example:**
```bash
./scripts/create_admin.sh john_doe
```

> **Note:** The user must log out and log back in after promotion for the new role to take effect (the role is embedded in the JWT token).

### How It Works

The script connects to the PostgreSQL database and updates the user's role:

```sql
UPDATE users SET role = 'admin' WHERE username = '<username>';
```

---

## Key Features

### User Experience
- **Gallery-Style Layout**: Masonry grid with dynamic animations
- **Interactive UI**: Real-time ratings, comments, and seamless interactions
- **Responsive Design**: Mobile-friendly interface

### Security
- **Defense in Depth**: Nginx gateway, service isolation, input sanitization
- **Secure Authentication**: JWT + Refresh Token system, scrypt hashing, MFA support
- **Email Verification**: Fail-closed verification flow
- **Protection**: Rate limiting, IDOR prevention, secure file handling

---

## Architecture

Decoupled Python (Flask) microservices:

| Service               | Purpose                          |
|-----------------------|----------------------------------|
| **Auth Service**      | Identity provider (Login/Register/Token) |
| **Meme Service**      | Content management (Posts/Comments/Rates) |
| **Verification Service** | Email lifecycle management    |
| **Account Service**   | User profile and settings        |
| **MFA Service**       | TOTP generation and validation   |

---

## Project Structure

```
├── auth_service/        # Authentication microservice
├── meme_service/        # Content management service
├── verification_service/ # Email verification
├── account_service/     # User account management
├── mfa_service/         # Multi-factor authentication
├── nginx/               # API gateway configuration
├── db/                  # Database initialization
├── scripts/             # Utility scripts
├── frontend/            # Static frontend files
├── compose.yaml         # Docker Compose config
└── .env.template        # Environment template
```

---

## License

MIT License
