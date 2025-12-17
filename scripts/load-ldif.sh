#!/usr/bin/env bash

# Load LDIF files into running slapd
#
# Fixed mount points:
# - /ldif/config: Configuration LDIFs (applied to cn=config via ldapi:///)
# - /ldif/data: Data LDIFs (applied to database via admin bind)
#
# Files are processed in alphabetical order (use prefixes: 00-, 10-, ...)
#
# LDIF types (detected automatically):
# - "changetype: modify" -> ldapmodify
# - "changetype: add" or no changetype -> ldapadd
# - "changetype: delete" -> ldapmodify

set -euo pipefail

log_info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

: "${LDAP_PORT:=1389}"
: "${LDAP_ADMIN_DN:?LDAP_ADMIN_DN is required}"
: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required}"
: "${LDAP_BASE_DN:?LDAP_BASE_DN is required}"

# Detect if LDIF file is a modify operation
is_modify_ldif() {
    local file="${1}"
    grep -q "^changetype: \(modify\|delete\)" "${file}" 2>/dev/null
}

# Process a single LDIF file
process_ldif() {
    local file="${1}"
    local type="${2}"  # "config" or "data"
    local filename
    filename=$(basename "${file}")

    log_info "Processing ${type} LDIF: ${filename}"

    # Create a temporary file with variable substitution
    local temp_ldif
    temp_ldif=$(mktemp)
    trap "rm -f ${temp_ldif}" RETURN

    # Extract first DC component from base DN (e.g., dc=foobar,dc=svc,dc=local -> foobar)
    local first_dc
    first_dc=$(echo "${LDAP_BASE_DN}" | sed 's/dc=\([^,]*\).*/\1/')

    # Substitute placeholders with actual values
    sed -e "s|@BASE_DN@|${LDAP_BASE_DN}|g" \
        -e "s|@ORGANISATION@|${LDAP_ORGANISATION}|g" \
        -e "s|@FIRST_DC@|${first_dc}|g" \
        "${file}" > "${temp_ldif}"

    if [ "${type}" = "config" ]; then
        # Config LDIFs use ldapi:// with EXTERNAL auth
        if is_modify_ldif "${temp_ldif}"; then
            if ! ldapmodify -Y EXTERNAL -H ldapi:/// -f "${temp_ldif}" 2>&1; then
                log_error "Failed to apply config LDIF: ${filename}"
                return 1
            fi
        else
            # For config additions (like loading modules)
            if ! ldapadd -Y EXTERNAL -H ldapi:/// -f "${temp_ldif}" 2>&1; then
                # Try modify if add fails (might already exist)
                if ! ldapmodify -Y EXTERNAL -H ldapi:/// -f "${temp_ldif}" 2>&1; then
                    log_error "Failed to apply config LDIF: ${filename}"
                    return 1
                fi
            fi
        fi
    else
        # Data LDIFs use admin bind
        if is_modify_ldif "${temp_ldif}"; then
            if ! ldapmodify -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
                    -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
                    -f "${temp_ldif}" 2>&1; then
                log_error "Failed to apply data LDIF: ${filename}"
                return 1
            fi
        else
            if ! ldapadd -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
                    -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
                    -f "${temp_ldif}" 2>&1; then
                log_error "Failed to apply data LDIF: ${filename}"
                return 1
            fi
        fi
    fi

    log_info "Successfully applied: ${filename}"
    return 0
}

# Process all LDIF files in a directory
process_directory() {
    local dir="${1}"
    local type="${2}"
    local count=0
    local failed=0

    if ! [ -d "${dir}" ]; then
        log_warn "Directory not found: ${dir}"
        return 0
    fi

    # Find LDIF files sorted alphabetically
    while IFS= read -r -d '' file; do
        if process_ldif "${file}" "${type}"; then
            ((count++))
        else
            ((failed++))
            # Continue processing other files even if one fails
            log_warn "Continuing despite failure..."
        fi
    done < <(find "${dir}" -maxdepth 1 -name "*.ldif" -type f -print0 | sort -z)

    log_info "Processed ${count} ${type} LDIF file(s) (${failed} failed)"

    if [ $failed -gt 0 ]; then
        return 1
    fi
    return 0
}

# Main execution
log_info "=========================================="
log_info "Loading LDIF files"
log_info "=========================================="

# Step 1: Process configuration LDIFs
log_info "--- Configuration LDIFs (/ldif/config) ---"
config_result=0
process_directory "/ldif/config" "config" || config_result=$?

# Step 2: Process data LDIFs
log_info "--- Data LDIFs (/ldif/data) ---"
data_result=0
process_directory "/ldif/data" "data" || data_result=$?

# Summary
log_info "=========================================="
log_info "LDIF loading complete"
if [ $config_result -ne 0 ] || [ $data_result -ne 0 ]; then
    log_warn "Some LDIF files failed to load - check logs above"
fi
log_info "=========================================="

# Verify basic directory structure
log_info "Verifying directory contents..."
if ldapsearch -x -H "ldap://127.0.0.1:${LDAP_PORT}" \
        -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" \
        -b "${LDAP_BASE_DN}" "(objectClass=*)" dn 2>/dev/null | grep -q "dn:"; then
    log_info "Directory verification successful"
else
    log_warn "Directory appears empty or base DN not found"
    log_warn "Ensure your data LDIFs create the base DN entry"
fi

exit 0
