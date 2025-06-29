#!/bin/bash

# ==============================================
# IDEALPLOTS DOCKER SCRIPTS (MySQL Only)
# ==============================================

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Warning: .env file not found. Using default values."
fi

# Set defaults if not provided in .env
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-3306}
DB_NAME=${DB_NAME:-idealplots_local}
DB_USER=${DB_USER:-idealplots_user}
DB_PASSWORD=${DB_PASSWORD:-your_password}
DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD:-root_password}

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        print_status "Try: sudo systemctl start docker"
        exit 1
    fi
}

# Check if .env file exists
check_env() {
    if [ ! -f .env ]; then
        print_error ".env file not found!"
        print_status "Create a .env file with your database configuration"
        exit 1
    fi
}

# Setup project structure
setup() {
    print_header "Setting up IdealPlots MySQL Environment"
    
    # Create directories
    mkdir -p database/{migrations,backups}
    
    # Create MySQL config
    cat > database/my.cnf << 'EOF'
[mysqld]
# Performance settings for development
innodb_buffer_pool_size = 128M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
max_connections = 100

# Logging
log-error = /var/log/mysql/error.log
slow_query_log = 1
long_query_time = 2

[mysql]
default-character-set = utf8mb4

[client]
default-character-set = utf8mb4
EOF

    # Create .env template if it doesn't exist
    if [ ! -f .env ]; then
        cat > .env << 'EOF'
# ==============================================
# IDEALPLOTS BACKEND ENVIRONMENT
# ==============================================

# Node.js Backend
NODE_ENV=development
PORT=3001

# MySQL Database Configuration (Docker)
DB_HOST=localhost
DB_PORT=3306
DB_NAME=idealplots_local
DB_USER=idealplots_user
DB_PASSWORD=your_secure_password
DB_ROOT_PASSWORD=your_root_password

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000

# Security
JWT_SECRET=your_jwt_secret_here
BCRYPT_ROUNDS=12

# Development
DEBUG=true
EOF
        print_status ".env template created - please update with your actual values"
    fi

    print_status "Project structure created!"
    print_warning "Update your .env file with actual passwords before starting"
}

# Start MySQL container
start() {
    print_header "Starting IdealPlots MySQL Database"
    check_docker
    check_env
    
    print_status "Database: ${DB_NAME}"
    print_status "User: ${DB_USER}"
    print_status "Port: ${DB_PORT}"
    
    docker-compose up -d mysql
    
    if [ $? -ne 0 ]; then
        print_error "Failed to start MySQL container"
        print_status "Check docker-compose.yml and .env files"
        exit 1
    fi
    
    # Wait for MySQL to be ready
    print_status "Waiting for MySQL to be ready..."
    sleep 10
    
    local max_attempts=30
    local attempt=1
    
    until docker-compose exec mysql mysqladmin ping -h localhost --silent 2>/dev/null; do
        if [ $attempt -eq $max_attempts ]; then
            print_error "MySQL failed to start after ${max_attempts} attempts"
            print_status "Check logs with: docker-compose logs mysql"
            exit 1
        fi
        
        echo "Waiting for MySQL... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    print_status "MySQL is ready!"
    print_status "Database: mysql://${DB_HOST}:${DB_PORT}/${DB_NAME}"
    print_status "Connection: mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p ${DB_NAME}"
    print_status ""
    print_status "You can now run your Node.js backend with: npm run dev"
}

# Stop services
stop() {
    print_header "Stopping MySQL Database"
    docker-compose down
    print_status "MySQL stopped!"
}

# Restart services
restart() {
    print_header "Restarting MySQL Database"
    stop
    sleep 2
    start
}

# Database operations
migrate() {
    print_status "Running database migrations..."
    if [ -f "migrate.js" ]; then
        node migrate.js migrate
    else
        print_warning "migrate.js not found - migrations not available"
    fi
}

migration_create() {
    name="$1"
    if [ -z "$name" ]; then
        print_error "Please provide a migration name"
        print_status "Usage: $0 migration:create \"migration_name\""
        exit 1
    fi
    
    if [ -f "migrate.js" ]; then
        node migrate.js create "$name"
    else
        print_warning "migrate.js not found - creating simple migration file"
        timestamp=$(date +%Y%m%d%H%M%S)
        filename="database/migrations/${timestamp}_${name}.sql"
        mkdir -p database/migrations
        
        cat > "$filename" << EOF
-- Migration: ${name}
-- Created: $(date)

-- Add your SQL changes here
-- Example:
-- ALTER TABLE users ADD COLUMN new_field VARCHAR(255);

-- Remember to test this migration before applying to production
EOF
        print_status "Migration created: $filename"
    fi
}

migration_status() {
    if [ -f "migrate.js" ]; then
        node migrate.js status
    else
        print_warning "migrate.js not found - showing available migration files"
        if [ -d "database/migrations" ]; then
            ls -la database/migrations/
        else
            print_status "No migrations directory found"
        fi
    fi
}

# Backup database
backup() {
    check_env
    backup_name="backup_$(date +%Y%m%d_%H%M%S).sql"
    backup_path="database/backups/$backup_name"
    
    print_status "Creating database backup: $backup_name"
    
    # Create backups directory if it doesn't exist
    mkdir -p database/backups
    
    # Create backup using environment variables
    docker-compose exec mysql mysqldump \
        -u "${DB_USER}" \
        -p"${DB_PASSWORD}" \
        --routines \
        --triggers \
        --single-transaction \
        --add-drop-database \
        --create-options \
        "${DB_NAME}" > "$backup_path"
    
    if [ $? -eq 0 ]; then
        print_status "Backup created: $backup_path"
        print_status "Backup size: $(du -h "$backup_path" | cut -f1)"
    else
        print_error "Backup failed!"
        rm -f "$backup_path"
    fi
}

# Restore database from backup
restore() {
    backup_file="$1"
    if [ -z "$backup_file" ]; then
        print_error "Please provide a backup file"
        print_status "Available backups:"
        ls -la database/backups/ 2>/dev/null || print_status "No backups found"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    print_warning "This will replace all data in ${DB_NAME}!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Restore cancelled"
        exit 1
    fi
    
    print_status "Restoring database from: $backup_file"
    docker-compose exec -T mysql mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" < "$backup_file"
    
    if [ $? -eq 0 ]; then
        print_status "Database restored successfully!"
    else
        print_error "Restore failed!"
    fi
}

# MySQL shell access
mysql_shell() {
    check_env
    print_status "Opening MySQL shell for database: ${DB_NAME}"
    print_status "Type 'exit' to return to terminal"
    
    docker-compose exec mysql mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}"
}

# Root MySQL shell access
mysql_root() {
    check_env
    print_status "Opening MySQL shell as root"
    print_status "Type 'exit' to return to terminal"
    
    docker-compose exec mysql mysql -u root -p"${DB_ROOT_PASSWORD}"
}

# View MySQL logs
logs() {
    print_status "Showing MySQL logs (Ctrl+C to exit)"
    docker-compose logs -f mysql
}

# Show container stats
stats() {
    print_header "Container Statistics"
    docker-compose ps mysql
    echo ""
    docker stats --no-stream $(docker-compose ps -q mysql) 2>/dev/null || print_warning "Container not running"
}

# Clean up unused Docker resources
cleanup() {
    print_header "Docker Cleanup"
    print_warning "This will remove unused Docker images and volumes"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down
        docker system prune -f
        print_status "Cleanup completed"
    else
        print_status "Cleanup cancelled"
    fi
}

# Reset database (remove all data)
reset() {
    print_header "Database Reset"
    print_warning "This will DELETE ALL DATA and recreate the database!"
    read -p "Are you absolutely sure? (type 'yes'): " confirm
    
    if [ "$confirm" = "yes" ]; then
        print_status "Stopping containers..."
        docker-compose down
        
        print_status "Removing database volume..."
        docker volume rm $(basename $(pwd))_mysql_data 2>/dev/null || true
        
        print_status "Starting fresh database..."
        start
    else
        print_status "Reset cancelled"
    fi
}

# Status check
status() {
    print_header "IdealPlots MySQL Status"
    
    # Docker status
    if docker info > /dev/null 2>&1; then
        print_status "Docker: Running"
    else
        print_error "Docker: Not running"
        return 1
    fi
    
    # Container status
    echo ""
    echo "=== Container Status ==="
    docker-compose ps mysql
    
    # Database connectivity
    echo ""
    echo "=== Database Connectivity ==="
    if docker-compose exec mysql mysqladmin ping -h localhost --silent 2>/dev/null; then
        print_status "MySQL: Running and healthy"
        
        # Show database info
        echo ""
        echo "=== Database Information ==="
        print_status "Host: ${DB_HOST}:${DB_PORT}"
        print_status "Database: ${DB_NAME}"
        print_status "User: ${DB_USER}"
        
        # Table count
        table_count=$(docker-compose exec mysql mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" -e "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema='${DB_NAME}'" -s -N 2>/dev/null || echo "0")
        print_status "Tables: ${table_count}"
        
    else
        print_error "MySQL: Not responding"
    fi
}

# Show help
show_help() {
    echo -e "${BLUE}IdealPlots MySQL Docker Manager${NC}"
    echo ""
    echo "Usage: $0 {command} [options]"
    echo ""
    echo "Setup & Management:"
    echo "  setup                 - Create project structure and .env template"
    echo "  start                 - Start MySQL container"
    echo "  stop                  - Stop MySQL container"
    echo "  restart               - Restart MySQL container"
    echo "  status                - Show detailed status information"
    echo "  stats                 - Show container resource usage"
    echo "  logs                  - View MySQL logs (real-time)"
    echo ""
    echo "Database Access:"
    echo "  mysql                 - Open MySQL shell (as ${DB_USER})"
    echo "  mysql-root           - Open MySQL shell (as root)"
    echo ""
    echo "Backup & Restore:"
    echo "  backup                - Create database backup"
    echo "  restore <file>        - Restore from backup file"
    echo "  reset                 - Reset database (DELETE ALL DATA)"
    echo ""
    echo "Migrations:"
    echo "  migrate               - Run pending migrations"
    echo "  migration:create <n>  - Create new migration"
    echo "  migration:status      - Show migration status"
    echo ""
    echo "Maintenance:"
    echo "  cleanup               - Clean up unused Docker resources"
    echo ""
    echo "Examples:"
    echo "  $0 setup              # First time setup"
    echo "  $0 start              # Start MySQL"
    echo "  $0 backup             # Create backup"
    echo "  $0 mysql              # Open database shell"
    echo "  $0 migration:create \"add_user_preferences\""
    echo ""
    echo "Configuration:"
    echo "  Database: ${DB_NAME}"
    echo "  User: ${DB_USER}"
    echo "  Port: ${DB_PORT}"
    echo ""
}

# Main script execution
case "$1" in
    "setup")
        setup
        ;;
    "start")
        start
        ;;
    "stop")
        stop
        ;;
    "restart")
        restart
        ;;
    "migrate")
        migrate
        ;;
    "migration:create")
        migration_create "$2"
        ;;
    "migration:status")
        migration_status
        ;;
    "backup")
        backup
        ;;
    "restore")
        restore "$2"
        ;;
    "mysql")
        mysql_shell
        ;;
    "mysql-root")
        mysql_root
        ;;
    "logs")
        logs
        ;;
    "status")
        status
        ;;
    "stats")
        stats
        ;;
    "cleanup")
        cleanup
        ;;
    "reset")
        reset
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        show_help
        ;;
esac