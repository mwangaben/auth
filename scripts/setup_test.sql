-- This script creates the necessary tables for testing
-- Tables will be created automatically by GORM migrations

-- Drop tables if they exist
DROP TABLE IF EXISTS oauth_personal_access_tokens;
DROP TABLE IF EXISTS oauth_access_tokens;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS test_users;

-- Create tables (GORM will handle this, but keeping for reference)
CREATE TABLE IF NOT EXISTS test_users (
                                          id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    name VARCHAR(255),
    created_at DATETIME,
    updated_at DATETIME
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;