.PHONY: test test-cover test-verbose clean db-setup

# Database configuration for tests
DB_HOST ?= localhost
DB_PORT ?= 3306
DB_USER ?= root
DB_PASSWORD ?= root
DB_NAME ?= auth_test

# Run all tests
test:
	DB_HOST=$(DB_HOST) DB_PORT=$(DB_PORT) DB_USER=$(DB_USER) DB_PASSWORD=$(DB_PASSWORD) DB_NAME=$(DB_NAME) \
	go test -v ./tests

# Run tests with coverage
test-cover:
	DB_HOST=$(DB_HOST) DB_PORT=$(DB_PORT) DB_USER=$(DB_USER) DB_PASSWORD=$(DB_PASSWORD) DB_NAME=$(DB_NAME) \
	go test -v ./tests -coverprofile=coverage.out
	go tool cover -html=coverage.out

# Run tests with verbose output
test-verbose:
	DB_HOST=$(DB_HOST) DB_PORT=$(DB_PORT) DB_USER=$(DB_USER) DB_PASSWORD=$(DB_PASSWORD) DB_NAME=$(DB_NAME) \
	go test -v ./tests -v

# Clean test artifacts
clean:
	rm -f coverage.out
	go clean -testcache

# Setup test database
db-setup:
	mysql -h $(DB_HOST) -u $(DB_USER) -p$(DB_PASSWORD) -e "CREATE DATABASE IF NOT EXISTS $(DB_NAME);"
	mysql -h $(DB_HOST) -u $(DB_USER) -p$(DB_PASSWORD) $(DB_NAME) < scripts/setup_test_db.sql

# Run benchmarks
bench:
	DB_HOST=$(DB_HOST) DB_PORT=$(DB_PORT) DB_USER=$(DB_USER) DB_PASSWORD=$(DB_PASSWORD) DB_NAME=$(DB_NAME) \
	go test -v ./tests -bench=. -run=Benchmark

# Full test with setup
test-all: db-setup test