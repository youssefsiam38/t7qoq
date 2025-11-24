.PHONY: dev build test lint clean db-up db-down db-migrate dashboard-dev dashboard-build release-local

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=t7qoq

# Database parameters
DB_CONTAINER_NAME=t7qoq-postgres
DB_PORT=5432
DB_USER=t7qoq
DB_PASSWORD=t7qoq
DB_NAME=t7qoq

# Local development
dev:
	@echo "Starting development server with hot reload..."
	@which air > /dev/null || go install github.com/air-verse/air@latest
	air

build:
	$(GOBUILD) -v github.com/youssefsiam38/t7qoq github.com/youssefsiam38/t7qoq/internal/...

build-all: dashboard-build build
	@echo "Full build complete!"

test:
	$(GOTEST) -v -race -cover ./...

lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

clean:
	$(GOCMD) clean
	rm -f $(BINARY_NAME)

# Dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Database commands
db-up:
	@echo "Starting PostgreSQL container..."
	docker run -d \
		--name $(DB_CONTAINER_NAME) \
		-e POSTGRES_USER=$(DB_USER) \
		-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
		-e POSTGRES_DB=$(DB_NAME) \
		-p $(DB_PORT):5432 \
		postgres:16-alpine
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3
	@echo "PostgreSQL is running on port $(DB_PORT)"

db-down:
	@echo "Stopping PostgreSQL container..."
	docker stop $(DB_CONTAINER_NAME) || true
	docker rm $(DB_CONTAINER_NAME) || true

db-restart: db-down db-up

db-migrate:
	@echo "Running migrations..."
	$(GOCMD) run ./cmd/migrate/main.go

db-shell:
	docker exec -it $(DB_CONTAINER_NAME) psql -U $(DB_USER) -d $(DB_NAME)

# Dashboard (React Admin Panel)
dashboard-dev:
	@echo "Starting React development server..."
	cd dashboard && npm run dev

dashboard-install:
	@echo "Installing dashboard dependencies..."
	cd dashboard && npm install

dashboard-build:
	@echo "Building dashboard for production..."
	cd dashboard && npm run build

dashboard-clean:
	rm -rf dashboard/dist dashboard/node_modules

# Release
release-local:
	@echo "Testing GoReleaser locally..."
	@which goreleaser > /dev/null || go install github.com/goreleaser/goreleaser@latest
	goreleaser release --snapshot --clean

# Generate
generate:
	$(GOCMD) generate ./...

# All-in-one setup
setup: deps db-up dashboard-install
	@echo "Setup complete! Run 'make dev' to start development."

# Help
help:
	@echo "t7qoq - Enterprise Identity Infrastructure"
	@echo ""
	@echo "Usage:"
	@echo "  make dev              - Start development server with hot reload"
	@echo "  make build            - Build the binary"
	@echo "  make test             - Run tests"
	@echo "  make lint             - Run linter"
	@echo "  make deps             - Download dependencies"
	@echo ""
	@echo "Database:"
	@echo "  make db-up            - Start PostgreSQL container"
	@echo "  make db-down          - Stop PostgreSQL container"
	@echo "  make db-migrate       - Run database migrations"
	@echo "  make db-shell         - Open psql shell"
	@echo ""
	@echo "Dashboard:"
	@echo "  make dashboard-dev    - Start React dev server"
	@echo "  make dashboard-build  - Build React for embedding"
	@echo "  make dashboard-install- Install npm dependencies"
	@echo ""
	@echo "Release:"
	@echo "  make release-local    - Test GoReleaser locally"
