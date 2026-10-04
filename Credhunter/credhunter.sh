#!/bin/bash

# CredHunter v1.0 - Advanced Credential Discovery Tool
# Designed for OSCP-style penetration testing
# Usage: ./credhunter.sh [directory] [options]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
MAX_DEPTH=10
MAX_FILE_SIZE=50M
OUTPUT_FILE=""
VERBOSE=false
QUIET=false
DETAILED=false
SEARCH_DIR="."

# Statistics
declare -A STATS
STATS[files_scanned]=0
STATS[matches_found]=0
STATS[sensitive_files]=0
STATS[total_findings]=0
STATS[critical_findings]=0

# Arrays to store critical findings
declare -a CRITICAL_FINDINGS
declare -a SENSITIVE_FILES_FOUND

# Progress tracking
PROGRESS_COUNTER=0
PROGRESS_TOTAL=0

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "  ██████╗██████╗ ███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ "
    echo " ██╔════╝██╔══██╗██╔════╝██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
    echo " ██║     ██████╔╝█████╗  ██║  ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
    echo " ██║     ██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
    echo " ╚██████╗██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
    echo "  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${WHITE}Advanced Credential Discovery Tool v1.0${NC}"
    echo -e "${YELLOW}Designed for OSCP-style penetration testing${NC}"
    echo ""
}

# Help function
show_help() {
    echo -e "${WHITE}Usage: $0 [directory] [options]${NC}"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo "  -d, --depth NUM      Maximum directory depth to search (default: 10)"
    echo "  -s, --size SIZE      Maximum file size to search (default: 50M)"
    echo "  -o, --output FILE    Save results to file"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -q, --quiet          Suppress banner and progress"
    echo "  --detailed           Show detailed analysis of all sensitive files"
    echo "  -h, --help           Show this help message"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  $0 /var/www                    # Search /var/www directory"
    echo "  $0 /home -d 5 -o results.txt   # Search /home with depth 5, save to file"
    echo "  $0 . -v --detailed             # Verbose search with detailed file analysis"
}

# Keyword patterns for credential hunting (general search)
declare -A PATTERNS=(
    ["passwords"]="password|passwd|pwd|pass"
    ["api_keys"]="api[_-]?key|apikey|api[_-]?secret|secret[_-]?key"
    ["tokens"]="token|jwt|bearer|oauth"
    ["database"]="db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password"
    ["connection_strings"]="connection[_-]?string|conn[_-]?string|database[_-]?url"
    ["private_keys"]="private[_-]?key|ssh[_-]?key|rsa[_-]?key|BEGIN.*PRIVATE.*KEY"
    ["certificates"]="certificate|cert|BEGIN.*CERTIFICATE"
    ["encryption"]="encrypt|decrypt|cipher|aes|des|rsa"
    ["authentication"]="auth|login|credential|username|user"
    ["cloud_keys"]="aws[_-]?key|azure[_-]?key|gcp[_-]?key|s3[_-]?key"
    ["smtp_credentials"]="smtp[_-]?password|mail[_-]?password|email[_-]?password"
    ["ftp_credentials"]="ftp[_-]?password|ftp[_-]?user"
    ["ldap_credentials"]="ldap[_-]?password|ldap[_-]?user|bind[_-]?password"
    ["hashes"]="hash|md5|sha1|sha256|sha512|bcrypt|ntlm"
)

# Critical patterns that should be highlighted
declare -A CRITICAL_PATTERNS=(
    ["passwords"]="(\\\$|\\$|\\w+\\[?['\"]?)password['\"]?\\]?\\s*[=:>]\\s*['\"]?[^'\";\\s]{3,}['\"]?|(\\\$|\\$|\\w+\\[?['\"]?)passwd['\"]?\\]?\\s*[=:>]\\s*['\"]?[^'\";\\s]{3,}['\"]?|(\\\$|\\$|\\w+\\[?['\"]?)pwd['\"]?\\]?\\s*[=:>]\\s*['\"]?[^'\";\\s]{3,}['\"]?|password\\s*[=:]\\s*['\"]?[^'\"\\s;]{3,}['\"]?|passwd\\s*[=:]\\s*['\"]?[^'\"\\s;]{3,}['\"]?|pwd\\s*[=:]\\s*['\"]?[^'\"\\s;]{3,}['\"]?|define\\s*\\(\\s*['\"]?\\w*password\\w*['\"]?\\s*,\\s*['\"]?[^'\"\\s;]{3,}['\"]?|['\"]password['\"]\s*=>\s*['\"]?[^'\"\\s;]{3,}['\"]?"
    ["api_keys"]="(\\\$|\\$|\\w+\\[?['\"]?)api[_-]?key['\"]?\\]?\\s*[=:>]\\s*['\"]?[a-zA-Z0-9]{10,}['\"]?|(\\\$|\\$|\\w+\\[?['\"]?)api[_-]?secret['\"]?\\]?\\s*[=:>]\\s*['\"]?[a-zA-Z0-9]{10,}['\"]?|define\\s*\\(\\s*['\"]?\\w*api[_-]?key\\w*['\"]?\\s*,\\s*['\"]?[a-zA-Z0-9]{10,}['\"]?|['\"]api[_-]?key['\"]\s*=>\s*['\"]?[a-zA-Z0-9]{10,}['\"]?"
    ["tokens"]="(\\\$|\\$|\\w+\\[?['\"]?)token['\"]?\\]?\\s*[=:>]\\s*['\"]?[a-zA-Z0-9]{20,}['\"]?|(\\\$|\\$|\\w+\\[?['\"]?)jwt['\"]?\\]?\\s*[=:>]\\s*['\"]?[a-zA-Z0-9._-]{20,}['\"]?|define\\s*\\(\\s*['\"]?\\w*token\\w*['\"]?\\s*,\\s*['\"]?[a-zA-Z0-9]{20,}['\"]?|['\"]token['\"]\s*=>\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
    ["database"]="(\\\$|\\$|\\w+\\[?['\"]?)db[_-]?password['\"]?\\]?\\s*[=:>]\\s*['\"]?[^'\"\\s;]{3,}['\"]?|(\\\$|\\$|\\w+\\[?['\"]?)database[_-]?password['\"]?\\]?\\s*[=:>]\\s*['\"]?[^'\"\\s;]{3,}['\"]?|define\\s*\\(\\s*['\"]?\\w*db[_-]?password\\w*['\"]?\\s*,\\s*['\"]?[^'\"\\s;]{3,}['\"]?|['\"]db[_-]?password['\"]\s*=>\s*['\"]?[^'\"\\s;]{3,}['\"]?"
    ["connection_strings"]="(\\\$|\\$|\\w+\\[?['\"]?)(database|db|dsn|url|uri|connection)['\"]?\\]?\\s*[=:>]\\s*['\"]?(jdbc|mysql|postgresql|mongodb|redis|sqlite|oracle|mssql|mariadb)://[^'\"\\s;]+['\"]?|(jdbc|mysql|postgresql|mongodb|redis|sqlite|oracle|mssql|mariadb)://[^\\s;'\"]+|mysql://[^\\s;'\"]+|postgresql://[^\\s;'\"]+|mongodb://[^\\s;'\"]+|redis://[^\\s;'\"]+|sqlite://[^\\s;'\"]+|oracle://[^\\s;'\"]+|mssql://[^\\s;'\"]+|mariadb://[^\\s;'\"]+|\\w+\\s*=\\s*['\"]?(mysql|postgresql|mongodb|redis|sqlite|oracle|mssql|mariadb)://[^'\"\\s;]+['\"]?"
    ["credentials_in_urls"]="://[^/\\s]*:[^@\\s]+@[^/\\s]+|://[a-zA-Z0-9._-]+:[^@\\s:]{3,}@"
    ["private_keys"]="-----BEGIN.*PRIVATE.*KEY-----"
    ["cloud_keys"]="AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|AIza[0-9A-Za-z_-]{35}"
    ["hashes"]="\\$[0-9a-f]{32,}|\\$[0-9]\\$[a-zA-Z0-9./]{22,}|[a-f0-9]{32}:[a-f0-9]{32,}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}"
)

# File extensions to search
FILE_EXTENSIONS=(
    "conf" "config" "cfg" "ini" "properties" "env" "envrc"
    "xml" "json" "yaml" "yml" "toml"
    "txt" "log" "bak" "backup" "old" "save" "tmp"
    "sh" "bash" "py" "php" "js" "pl" "rb" "go"
    "sql" "db" "sqlite" "mdb"
    "pem" "key" "crt" "cer" "p12" "pfx" "jks"
    "htaccess" "htpasswd" "web.config" "app.config"
    "settings" "local" "development" "production" "staging"
)

# Sensitive file patterns
SENSITIVE_FILES=(
    "passwd" "shadow" "group" "sudoers" "hosts" "fstab"
    "authorized_keys" "known_hosts" "id_rsa" "id_dsa" "id_ecdsa"
    "wp-config.php" "config.php" "database.php" "settings.php"
    "web.config" "app.config" "appsettings.json" "connectionstrings.config"
    ".env" ".envrc" ".env.local" ".env.production" ".env.development"
    "credentials" "secrets" "tokens" "keys" "passwords"
    "application.properties" "hibernate.cfg.xml" "spring.xml"
    "my.cnf" "mysql.conf" "postgresql.conf" "redis.conf"
    "nginx.conf" "apache.conf" "httpd.conf" "lighttpd.conf"
    "sshd_config" "ssh_config" "vsftpd.conf" "proftpd.conf"
    "smb.conf" "samba.conf" "krb5.conf" "ldap.conf"
    "Dockerfile" "docker-compose.yml" "docker-compose.yaml"
    "ansible.cfg" "inventory" "hosts.yml" "playbook.yml"
    "Vagrantfile" "Gemfile" "requirements.txt" "package.json"
    "gradle.properties" "build.gradle" "pom.xml" "build.xml"
    "tnsnames.ora" "sqlnet.ora" "listener.ora" "orapw*"
    "pgpass" "pgpass.conf" ".pgpass" "pg_hba.conf"
    "mongod.conf" "cassandra.yaml" "elasticsearch.yml"
    "rabbitmq.conf" "redis.conf" "memcached.conf"
    "jenkins.xml" "config.xml" "gitlab.rb" "gitlab.yml"
    "vault.conf" "consul.conf" "nomad.conf" "terraform.tfvars"
    "kubeconfig" "kube-config" "kubectl" "helm"
    "aws.conf" "azure.conf" "gcp.conf" "cloud.conf"
    "backup.sql" "dump.sql" "database.sql" "db.sql"
    "users.txt" "accounts.txt" "logins.txt" "creds.txt"
    "history" "bash_history" "zsh_history" "python_history"
    "viminfo" "lesshst" "mysql_history" "psql_history"
    "core" "crash" "debug" "error.log" "access.log"
    "mail.log" "auth.log" "secure.log" "messages.log"
    "install.log" "setup.log" "deploy.log" "backup.log"
    "*.bak" "*.backup" "*.old" "*.save" "*.tmp" "*.swp"
    "*.dist" "*.sample" "*.example" "*.template"
    "*.dpkg-old" "*.dpkg-new" "*.dpkg-dist" "*.rpm-new" "*.rpm-save"
)

# High-priority sensitive files that should be highlighted (TRULY critical only)
HIGH_PRIORITY_FILES=(
    "passwd" "shadow" "group" "sudoers" "authorized_keys" "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519"
    "wp-config.php" "config.php" "database.php" "settings.php" "web.config" "appsettings.json"
    ".env" ".envrc" ".env.local" ".env.production" ".env.development"
    "credentials" "secrets" "passwords" "my.cnf" "pgpass" ".pgpass"
    "backup.sql" "dump.sql" "database.sql" "users.txt" "logins.txt" "creds.txt"
    "bash_history" "zsh_history" "mysql_history" "psql_history" ".bash_history" ".zsh_history"
    "private.key" "keystore" "htpasswd" ".htpasswd"
)

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            [[ "$QUIET" == false ]] && echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            [[ "$QUIET" == false ]] && echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "DEBUG")
            [[ "$VERBOSE" == true ]] && echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
        "FOUND")
            echo -e "${PURPLE}[FOUND]${NC} $message"
            [[ -n "$OUTPUT_FILE" ]] && echo "[$timestamp] [FOUND] $message" >> "$OUTPUT_FILE"
            ;;
        "SENSITIVE")
            echo -e "${RED}[SENSITIVE]${NC} $message"
            [[ -n "$OUTPUT_FILE" ]] && echo "[$timestamp] [SENSITIVE] $message" >> "$OUTPUT_FILE"
            ;;
    esac
}

# Progress bar
show_progress() {
    if [[ "$QUIET" == false ]] && [[ $PROGRESS_TOTAL -gt 0 ]]; then
        local percent=$((PROGRESS_COUNTER * 100 / PROGRESS_TOTAL))
        local filled=$((percent / 2))
        local empty=$((50 - filled))
        
        printf "\r${CYAN}Progress: [%s%s] %d%% (%d/%d)${NC}" \
            "$(printf "%*s" $filled | tr ' ' '=')" \
            "$(printf "%*s" $empty | tr ' ' '-')" \
            $percent $PROGRESS_COUNTER $PROGRESS_TOTAL
    fi
}

# Check if file is binary
is_binary() {
    local file=$1
    file -b --mime-type "$file" | grep -q "^text/"
    return $?
}

# Extract context around match
extract_context() {
    local file=$1
    local line_num=$2
    local context_lines=2
    
    sed -n "$((line_num - context_lines)),$((line_num + context_lines))p" "$file" 2>/dev/null | \
    sed "${context_lines}s/^/>>> /" | \
    sed "s/^/    /"
}

# Check for sensitive file patterns
check_sensitive_file() {
    local file=$1
    local basename=$(basename "$file")
    local dirname=$(dirname "$file")
    local is_high_priority=false
    local is_sensitive=false
    
    # Check against high priority files first
    for pattern in "${HIGH_PRIORITY_FILES[@]}"; do
        if [[ "$basename" == $pattern ]] || [[ "$basename" == *"$pattern"* ]] || [[ "$basename" =~ $pattern ]]; then
            is_high_priority=true
            is_sensitive=true
            break
        fi
    done
    
    # If not high priority, check against all sensitive files
    if [[ "$is_sensitive" == false ]]; then
        for pattern in "${SENSITIVE_FILES[@]}"; do
            if [[ "$basename" == $pattern ]] || [[ "$basename" == *"$pattern"* ]] || [[ "$basename" =~ $pattern ]]; then
                is_sensitive=true
                break
            fi
        done
    fi
    
    # Add to findings if sensitive
    if [[ "$is_sensitive" == true ]]; then
        ((STATS[sensitive_files]++))
        
        if [[ "$is_high_priority" == true ]]; then
            SENSITIVE_FILES_FOUND+=("HIGH_PRIORITY|$file")
            log "SENSITIVE" "🔥 HIGH PRIORITY - Sensitive file found: $file"
        else
            SENSITIVE_FILES_FOUND+=("NORMAL|$file")
            log "SENSITIVE" "Sensitive file found: $file"
        fi
        
        if [[ "$VERBOSE" == true ]] && is_binary "$file"; then
            log "DEBUG" "  File size: $(stat -c%s "$file" 2>/dev/null || echo "unknown") bytes"
            log "DEBUG" "  Permissions: $(stat -c%A "$file" 2>/dev/null || echo "unknown")"
            log "DEBUG" "  Owner: $(stat -c%U:%G "$file" 2>/dev/null || echo "unknown")"
        fi
        return 0
    fi
    return 1
}

# Search for patterns in file
search_file() {
    local file=$1
    local matches_in_file=0
    
    # Skip if file is too large
    if [[ -n "$MAX_FILE_SIZE" ]]; then
        local file_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        local max_bytes=$(numfmt --from=iec "$MAX_FILE_SIZE" 2>/dev/null || echo "52428800")
        if [[ $file_size -gt $max_bytes ]]; then
            log "DEBUG" "Skipping large file: $file ($file_size bytes)"
            return 0
        fi
    fi
    
    # Check if it's a sensitive file first
    check_sensitive_file "$file"
    
    # Skip binary files for content search
    if ! is_binary "$file"; then
        log "DEBUG" "Skipping binary file: $file"
        ((STATS[files_scanned]++))
        return 0
    fi
    
    # Skip obviously non-credential files unless in detailed mode
    if [[ "$DETAILED" == false ]]; then
        local basename=$(basename "$file")
        local file_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        
        # Skip large minified/compiled files
        if [[ $file_size -gt 100000 ]]; then
            if [[ "$basename" == *.min.js ]] || [[ "$basename" == *.min.css ]] || \
               [[ "$file" == *"/translations/"* ]] || [[ "$file" == *"/vendor/"* ]] || \
               [[ "$file" == *"/node_modules/"* ]] || [[ "$file" == *"/build/"* ]] || \
               [[ "$file" == *"/dist/"* ]] || [[ "$file" == *"/lib/"* ]]; then
                log "DEBUG" "Skipping large non-credential file: $file ($file_size bytes)"
                ((STATS[files_scanned]++))
                return 0
            fi
        fi
    fi
    
    # Search for critical patterns first - ENHANCED VERSION
    for category in "${!CRITICAL_PATTERNS[@]}"; do
        local pattern="${CRITICAL_PATTERNS[$category]}"
        local matches
        
        # Use grep with line numbers and case-insensitive search
        matches=$(grep -inE "$pattern" "$file" 2>/dev/null)
        
        if [[ -n "$matches" ]]; then
            ((matches_in_file++))
            ((STATS[critical_findings]++))
            
            # Store critical findings - CAPTURE THE FULL LINE
            while IFS= read -r line; do
                local line_num=$(echo "$line" | cut -d: -f1)
                local match_line=$(echo "$line" | cut -d: -f2-)
                
                # Get the FULL line from the file for better context
                local full_line=$(sed -n "${line_num}p" "$file" 2>/dev/null)
                
                # Store the full line instead of just the match
                if [[ -n "$full_line" ]]; then
                    CRITICAL_FINDINGS+=("$category|$file|$line_num|$full_line")
                else
                    CRITICAL_FINDINGS+=("$category|$file|$line_num|$match_line")
                fi
                
                # Enhanced logging for database connections
                if [[ "$category" == "connection_strings" ]] || [[ "$category" == "database" ]]; then
                    if [[ "$full_line" == *"mysql://"* ]] || [[ "$full_line" == *"postgresql://"* ]] || [[ "$full_line" == *"mongodb://"* ]]; then
                        log "FOUND" "🚨 DATABASE CONNECTION STRING found in: $file:$line_num"
                        echo -e "  ${RED}FULL LINE: $full_line${NC}"
                    fi
                fi
                
            done <<< "$matches"
            
            log "FOUND" "🚨 CRITICAL [$category] matches in: $file"
            
            # Display matches with full context for important findings
            while IFS= read -r line; do
                local line_num=$(echo "$line" | cut -d: -f1)
                local match_line=$(echo "$line" | cut -d: -f2-)
                local full_line=$(sed -n "${line_num}p" "$file" 2>/dev/null)
                
                echo -e "  ${RED}Line $line_num:${NC} $match_line"
                
                # Show full line if different and contains more info
                if [[ -n "$full_line" ]] && [[ "$full_line" != "$match_line" ]] && [[ ${#full_line} -gt ${#match_line} ]]; then
                    echo -e "  ${GREEN}Full Line:${NC} $full_line"
                fi
                
                if [[ "$VERBOSE" == true ]]; then
                    echo -e "${BLUE}  Context:${NC}"
                    extract_context "$file" "$line_num"
                    echo ""
                fi
            done <<< "$matches"
            
            ((STATS[matches_found]++))
        fi
    done
    
    # Search for general patterns (non-critical) only if DETAILED mode or critical patterns found
    if [[ "$DETAILED" == true ]] || [[ $matches_in_file -gt 0 ]]; then
        for category in "${!PATTERNS[@]}"; do
            local pattern="${PATTERNS[$category]}"
            local matches
            
            # Skip if we already found critical matches in this category
            local has_critical=false
            for critical_category in "${!CRITICAL_PATTERNS[@]}"; do
                if [[ "$category" == "$critical_category" ]]; then
                    has_critical=true
                    break
                fi
            done
            
            if [[ "$has_critical" == true ]]; then
                continue
            fi
            
            # Use grep with line numbers and case-insensitive search
            matches=$(grep -inE "$pattern" "$file" 2>/dev/null)
            
            if [[ -n "$matches" ]]; then
                # Filter out false positives unless in detailed mode
                if [[ "$DETAILED" == false ]]; then
                    local filtered_matches=""
                    while IFS= read -r line; do
                        local match_line=$(echo "$line" | cut -d: -f2-)
                        
                        # Skip obvious false positives
                        if [[ "$match_line" =~ (dictionary|Object\.assign|translation|function|const|var|let) ]] || \
                           [[ "$match_line" =~ (\.min\.|minified|compressed) ]] || \
                           [[ ${#match_line} -gt 200 ]]; then
                            continue
                        fi
                        
                        if [[ -n "$filtered_matches" ]]; then
                            filtered_matches="$filtered_matches"$'\n'"$line"
                        else
                            filtered_matches="$line"
                        fi
                    done <<< "$matches"
                    matches="$filtered_matches"
                fi
                
                if [[ -n "$matches" ]]; then
                    ((matches_in_file++))
                    log "FOUND" "[$category] matches in: $file"
                    
                    # Display matches with context
                    while IFS= read -r line; do
                        local line_num=$(echo "$line" | cut -d: -f1)
                        local match_line=$(echo "$line" | cut -d: -f2-)
                        
                        echo -e "  ${YELLOW}Line $line_num:${NC} $match_line"
                        
                        if [[ "$VERBOSE" == true ]]; then
                            echo -e "${BLUE}  Context:${NC}"
                            extract_context "$file" "$line_num"
                            echo ""
                        fi
                    done <<< "$matches"
                    
                    ((STATS[matches_found]++))
                fi
            fi
        done
    fi
    
    ((STATS[files_scanned]++))
    ((STATS[total_findings] += matches_in_file))
    
    return $matches_in_file
}

# Build file list
build_file_list() {
    local search_path=$1
    local file_list=()
    
    log "INFO" "Building file list from: $search_path"
    
    # Build find command
    local find_cmd="find \"$search_path\" -type f -maxdepth $MAX_DEPTH"
    
    # Add file extension filters
    local ext_filter=""
    for ext in "${FILE_EXTENSIONS[@]}"; do
        if [[ -z "$ext_filter" ]]; then
            ext_filter="-name \"*.$ext\""
        else
            ext_filter="$ext_filter -o -name \"*.$ext\""
        fi
    done
    
    # Add sensitive file filters
    for pattern in "${SENSITIVE_FILES[@]}"; do
        ext_filter="$ext_filter -o -name \"$pattern\""
    done
    
    # Execute find command
    local find_result
    find_result=$(eval "$find_cmd \\( $ext_filter \\) -readable 2>/dev/null")
    
    # Convert to array
    while IFS= read -r file; do
        [[ -n "$file" ]] && file_list+=("$file")
    done <<< "$find_result"
    
    PROGRESS_TOTAL=${#file_list[@]}
    log "INFO" "Found ${#file_list[@]} files to search"
    
    printf '%s\n' "${file_list[@]}"
}

# Print critical findings section
# Simple enhanced print_critical_findings function - just better display, no complex regex
# Simple fix: Just add content preview to sensitive files
print_critical_findings() {
    if [[ ${#CRITICAL_FINDINGS[@]} -eq 0 ]] && [[ ${#SENSITIVE_FILES_FOUND[@]} -eq 0 ]]; then
        return 0
    fi
    
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                                            🚨 CRITICAL FINDINGS 🚨                                            ║${NC}"
    echo -e "${RED}║                                   HIGH PRIORITY CREDENTIALS & SENSITIVE FILES                                 ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Display high priority sensitive files WITH CONTENT
    local high_priority_count=0
    local normal_sensitive_count=0
    
    if [[ ${#SENSITIVE_FILES_FOUND[@]} -gt 0 ]]; then
        echo -e "${WHITE}🔥 HIGH PRIORITY SENSITIVE FILES:${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        for finding in "${SENSITIVE_FILES_FOUND[@]}"; do
            IFS='|' read -r priority filepath <<< "$finding"
            if [[ "$priority" == "HIGH_PRIORITY" ]]; then
                ((high_priority_count++))
                echo -e "${RED}  🔥 $filepath${NC}"
                
                # Show file details
                if [[ -r "$filepath" ]]; then
                    local file_size=$(stat -c%s "$filepath" 2>/dev/null || echo "unknown")
                    local file_perms=$(stat -c%A "$filepath" 2>/dev/null || echo "unknown")
                    local file_owner=$(stat -c%U:%G "$filepath" 2>/dev/null || echo "unknown")
                    echo -e "${CYAN}     📊 Size: $file_size bytes | Permissions: $file_perms | Owner: $file_owner${NC}"
                    
                    # SHOW FILE CONTENT - This is the key addition
                    echo -e "${YELLOW}     📄 FILE CONTENT:${NC}"
                    if [[ $file_size -lt 50000 ]]; then  # Only show content for files under 50KB
                        # Look for interesting lines first
                        local interesting_content=$(grep -iE "(password|passwd|pwd|database|mysql|postgresql|mongodb|connection|secret|key|token|api|auth|login|user|root|admin)" "$filepath" 2>/dev/null | head -20)
                        
                        if [[ -n "$interesting_content" ]]; then
                            echo -e "${GREEN}     🔍 INTERESTING LINES FOUND:${NC}"
                            echo "$interesting_content" | nl -ba | while read line_num content; do
                                echo -e "${PURPLE}       Line $line_num: ${WHITE}$content${NC}"
                                
                                # Highlight database connections specifically
                                if [[ "$content" =~ mysql://|postgresql://|mongodb://|sqlite:// ]]; then
                                    echo -e "${RED}       ⚠️  DATABASE CONNECTION STRING DETECTED!${NC}"
                                fi
                            done
                            echo ""
                        else
                            # If no interesting lines, show first 10 lines of file
                            echo -e "${CYAN}     📄 First 10 lines of file:${NC}"
                            head -10 "$filepath" 2>/dev/null | nl -ba | while read line_num content; do
                                echo -e "${CYAN}       $line_num: $content${NC}"
                            done
                            echo ""
                        fi
                    else
                        echo -e "${YELLOW}       File too large, showing first 5 lines:${NC}"
                        head -5 "$filepath" 2>/dev/null | nl -ba | while read line_num content; do
                            echo -e "${CYAN}       $line_num: $content${NC}"
                        done
                        echo ""
                    fi
                fi
            fi
        done
        
        if [[ $high_priority_count -eq 0 ]]; then
            echo -e "${GREEN}     ✓ No high priority sensitive files found${NC}"
        fi
        echo ""
    fi
    
    # Enhanced critical credential findings display
    if [[ ${#CRITICAL_FINDINGS[@]} -gt 0 ]]; then
        echo -e "${WHITE}🚨 CRITICAL CREDENTIAL DISCOVERIES:${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        declare -A grouped_findings
        
        # Group findings by category
        for finding in "${CRITICAL_FINDINGS[@]}"; do
            IFS='|' read -r category filepath line_num match_line <<< "$finding"
            if [[ -z "${grouped_findings[$category]}" ]]; then
                grouped_findings[$category]="$filepath:$line_num:$match_line"
            else
                grouped_findings[$category]="${grouped_findings[$category]}###$filepath:$line_num:$match_line"
            fi
        done
        
        # Display findings by category
        for category in "${!grouped_findings[@]}"; do
            echo -e "${RED}  🔑 ${category^^} CREDENTIALS:${NC}"
            
            IFS='###' read -ra findings_array <<< "${grouped_findings[$category]}"
            for item in "${findings_array[@]}"; do
                IFS=':' read -r filepath line_num match_line <<< "$item"
                echo -e "${YELLOW}     📁 File: ${WHITE}$filepath${NC}"
                echo -e "${CYAN}     📍 Line $line_num: ${GREEN}$match_line${NC}"
                
                # Get the full line for better context
                local full_context=""
                if [[ -r "$filepath" ]]; then
                    full_context=$(sed -n "${line_num}p" "$filepath" 2>/dev/null)
                    if [[ -n "$full_context" ]]; then
                        echo -e "${PURPLE}     📄 Full Line: ${WHITE}$full_context${NC}"
                    fi
                fi
                
                # Show context (±3 lines)
                echo -e "${BLUE}     📄 Context:${NC}"
                if [[ -r "$filepath" ]]; then
                    local context_start=$((line_num - 3))
                    local context_end=$((line_num + 3))
                    [[ $context_start -lt 1 ]] && context_start=1
                    
                    sed -n "${context_start},${context_end}p" "$filepath" 2>/dev/null | nl -ba -v$context_start | while read line_number content; do
                        if [[ $line_number -eq $line_num ]]; then
                            echo -e "${GREEN}        ➤ ${line_number}: ${content}${NC}"
                        else
                            echo -e "${CYAN}          ${line_number}: ${content}${NC}"
                        fi
                    done
                else
                    echo -e "${RED}        ✗ Cannot read file${NC}"
                fi
                
                echo -e "${CYAN}     ────────────────────────────────────────${NC}"
                echo ""
            done
        done
        echo ""
    else
        echo -e "${WHITE}🚨 CRITICAL CREDENTIAL DISCOVERIES:${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}     ✓ No critical credentials found${NC}"
        echo ""
    fi
    
    # Display other sensitive files (lower priority) - only if DETAILED flag is set
    if [[ "$DETAILED" == true ]] && [[ ${#SENSITIVE_FILES_FOUND[@]} -gt 0 ]]; then
        echo -e "${WHITE}📋 OTHER SENSITIVE FILES:${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        for finding in "${SENSITIVE_FILES_FOUND[@]}"; do
            IFS='|' read -r priority filepath <<< "$finding"
            if [[ "$priority" == "NORMAL" ]]; then
                ((normal_sensitive_count++))
                echo -e "${YELLOW}  📄 $filepath${NC}"
                
                # Show basic info and content preview for normal sensitive files too
                if [[ -r "$filepath" ]]; then
                    local file_size=$(stat -c%s "$filepath" 2>/dev/null || echo "unknown")
                    echo -e "${CYAN}     📊 Size: $file_size bytes${NC}"
                    
                    # Quick content scan for interesting patterns
                    if [[ $file_size -lt 10240 ]]; then
                        local interesting_lines=$(grep -iE "(password|key|secret|token|user|login|database|mysql|postgresql)" "$filepath" 2>/dev/null | head -5)
                        if [[ -n "$interesting_lines" ]]; then
                            echo -e "${YELLOW}     🔍 Interesting content found:${NC}"
                            echo "$interesting_lines" | sed 's/^/       │ /'
                        fi
                    fi
                fi
            fi
        done
        
        if [[ $normal_sensitive_count -eq 0 ]]; then
            echo -e "${GREEN}     ✓ No additional sensitive files found${NC}"
        fi
        echo ""
    fi
    
    # Summary of critical findings
    echo -e "${WHITE}📊 CRITICAL FINDINGS SUMMARY:${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  🔥 High Priority Files: $high_priority_count${NC}"
    echo -e "${PURPLE}  🚨 Critical Credentials: ${#CRITICAL_FINDINGS[@]}${NC}"
    if [[ "$DETAILED" == true ]]; then
        echo -e "${YELLOW}  📋 Other Sensitive Files: $normal_sensitive_count${NC}"
    fi
    
    # Risk assessment
    local risk_level="LOW"
    local risk_color="${GREEN}"
    if [[ ${#CRITICAL_FINDINGS[@]} -gt 0 ]] || [[ $high_priority_count -gt 0 ]]; then
        risk_level="HIGH"
        risk_color="${RED}"
    elif [[ ${STATS[sensitive_files]} -gt 0 ]]; then
        risk_level="MEDIUM"
        risk_color="${YELLOW}"
    fi
    
    echo -e "${risk_color}  ⚠️  Overall Risk Level: $risk_level${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Save critical findings to output file
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "" >> "$OUTPUT_FILE"
        echo "CRITICAL FINDINGS WITH CONTENT" >> "$OUTPUT_FILE"
        echo "==============================" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        
        echo "HIGH PRIORITY SENSITIVE FILES:" >> "$OUTPUT_FILE"
        for finding in "${SENSITIVE_FILES_FOUND[@]}"; do
            IFS='|' read -r priority filepath <<< "$finding"
            if [[ "$priority" == "HIGH_PRIORITY" ]]; then
                echo "  HIGH PRIORITY: $filepath" >> "$OUTPUT_FILE"
                if [[ -r "$filepath" ]]; then
                    local file_size=$(stat -c%s "$filepath" 2>/dev/null || echo "unknown")
                    echo "    Size: $file_size bytes" >> "$OUTPUT_FILE"
                    echo "    Content:" >> "$OUTPUT_FILE"
                    
                    # Add interesting content to file
                    local interesting_content=$(grep -iE "(password|database|mysql|secret|key|token)" "$filepath" 2>/dev/null | head -10)
                    if [[ -n "$interesting_content" ]]; then
                        echo "$interesting_content" | sed 's/^/      /' >> "$OUTPUT_FILE"
                    else
                        head -5 "$filepath" 2>/dev/null | sed 's/^/      /' >> "$OUTPUT_FILE"
                    fi
                    echo "" >> "$OUTPUT_FILE"
                fi
            fi
        done
        echo "" >> "$OUTPUT_FILE"
        
        echo "CRITICAL CREDENTIALS:" >> "$OUTPUT_FILE"
        for finding in "${CRITICAL_FINDINGS[@]}"; do
            IFS='|' read -r category filepath line_num match_line <<< "$finding"
            echo "  [$category] $filepath:$line_num - $match_line" >> "$OUTPUT_FILE"
            if [[ -r "$filepath" ]]; then
                local full_line=$(sed -n "${line_num}p" "$filepath" 2>/dev/null)
                echo "    Full line: $full_line" >> "$OUTPUT_FILE"
            fi
        done
        echo "" >> "$OUTPUT_FILE"
        
        echo "RISK ASSESSMENT: $risk_level" >> "$OUTPUT_FILE"
    fi
}

# Main search function
main_search() {
    local search_path=$1
    
    if [[ ! -d "$search_path" ]]; then
        log "ERROR" "Directory not found: $search_path"
        exit 1
    fi
    
    if [[ ! -r "$search_path" ]]; then
        log "ERROR" "Permission denied: $search_path"
        exit 1
    fi
    
    log "INFO" "Starting credential search in: $search_path"
    log "INFO" "Max depth: $MAX_DEPTH, Max file size: $MAX_FILE_SIZE"
    
    # Initialize output file
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "CredHunter Results - $(date)" > "$OUTPUT_FILE"
        echo "Search Directory: $search_path" >> "$OUTPUT_FILE"
        echo "=================================" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        log "INFO" "Output will be saved to: $OUTPUT_FILE"
    fi
    
    # Get file list
    local files
    files=$(build_file_list "$search_path")
    
    if [[ -z "$files" ]]; then
        log "WARN" "No files found to search"
        return 0
    fi
    
    # Process each file
    while IFS= read -r file; do
        [[ -n "$file" ]] && {
            ((PROGRESS_COUNTER++))
            show_progress
            search_file "$file"
        }
    done <<< "$files"
    
    # Clear progress bar
    [[ "$QUIET" == false ]] && echo ""
}

# Print summary
print_summary() {
    echo ""
    echo -e "${WHITE}=================================${NC}"
    echo -e "${WHITE}           SUMMARY${NC}"
    echo -e "${WHITE}=================================${NC}"
    echo -e "${GREEN}Files Scanned:${NC} ${STATS[files_scanned]}"
    echo -e "${YELLOW}Pattern Matches:${NC} ${STATS[matches_found]}"
    echo -e "${RED}Sensitive Files:${NC} ${STATS[sensitive_files]}"
    echo -e "${PURPLE}Critical Findings:${NC} ${STATS[critical_findings]}"
    echo -e "${CYAN}Total Findings:${NC} ${STATS[total_findings]}"
    echo -e "${WHITE}=================================${NC}"
    
    # Print critical findings section
    print_critical_findings
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "" >> "$OUTPUT_FILE"
        echo "SUMMARY" >> "$OUTPUT_FILE"
        echo "=======" >> "$OUTPUT_FILE"
        echo "Files Scanned: ${STATS[files_scanned]}" >> "$OUTPUT_FILE"
        echo "Pattern Matches: ${STATS[matches_found]}" >> "$OUTPUT_FILE"
        echo "Sensitive Files: ${STATS[sensitive_files]}" >> "$OUTPUT_FILE"
        echo "Critical Findings: ${STATS[critical_findings]}" >> "$OUTPUT_FILE"
        echo "Total Findings: ${STATS[total_findings]}" >> "$OUTPUT_FILE"
        
        log "INFO" "Results saved to: $OUTPUT_FILE"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--depth)
                MAX_DEPTH="$2"
                shift 2
                ;;
            -s|--size)
                MAX_FILE_SIZE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --detailed)
                DETAILED=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                SEARCH_DIR="$1"
                shift
                ;;
        esac
    done
}

# Cleanup function
cleanup() {
    echo ""
    log "INFO" "Search interrupted by user"
    print_summary
    exit 1
}

# Main execution
main() {
    # Set up signal handlers
    trap cleanup SIGINT SIGTERM
    
    # Parse arguments
    parse_args "$@"
    
    # Show banner
    [[ "$QUIET" == false ]] && print_banner
    
    # Validate search directory
    if [[ ! -d "$SEARCH_DIR" ]]; then
        log "ERROR" "Search directory does not exist: $SEARCH_DIR"
        exit 1
    fi
    
    # Check dependencies
    for cmd in find grep file stat; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR" "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Start search
    main_search "$SEARCH_DIR"
    
    # Print summary
    print_summary
    
    # Exit with appropriate code
    if [[ ${STATS[total_findings]} -gt 0 ]]; then
        log "INFO" "Search completed with findings!"
        exit 0
    else
        log "INFO" "Search completed with no findings."
        exit 0
    fi
}

# Run main function
main "$@"
