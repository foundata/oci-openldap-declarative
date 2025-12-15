#!/usr/bin/env bash

# Initialize slapd configuration from scratch
# This script runs before slapd starts and sets up the basic configuration

set -euo pipefail

log_info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

# Ensure required variables are set
: "${LDAP_DOMAIN:?LDAP_DOMAIN is required}"
: "${LDAP_ORGANISATION:?LDAP_ORGANISATION is required}"
: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required}"
: "${LDAP_BASE_DN:?LDAP_BASE_DN is required}"

# Directories
SLAPD_CONF_DIR="/etc/ldap/slapd.d"
LDAP_DATA_PATH="/var/lib/ldap"

# Clean any existing configuration (fresh start each time)
rm -rf "${SLAPD_CONF_DIR:?}"/*
rm -rf "${LDAP_DATA_PATH:?}"/*

log_info "Generating password hash..."
ADMIN_PASSWORD_HASH=$(slappasswd -s "${LDAP_ADMIN_PASSWORD}")

log_info "Creating initial slapd configuration..."

# Create temporary LDIF for initial configuration. Modern OpenLDAP (2.3+) uses
# a LDAP-based configuration stored in cn=config rather than the old slapd.conf
# file. This LDIF creates that configuration tree.
#
# This is a minimal working configuration derived from:
# - Debian's default slapd setup - What dpkg-reconfigure slapd creates
#   You can see what Debian creates by default: On a fresh Debian system after
#   installing slapd: sudo slapcat -n0  # Dumps cn=config database
# - OpenLDAP Administrator's Guide - https://www.openldap.org/doc/admin26/
# - man slapd-config - The definitive reference for cn=config
# - man slapd-mdb - MDB backend specifics
INIT_LDIF=$(mktemp)
trap "rm -f ${INIT_LDIF}" EXIT

cat > "${INIT_LDIF}" << LDIF_EOF
# Global configuration
dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /var/run/slapd/slapd.args
olcPidFile: /var/run/slapd/slapd.pid
olcLogLevel: stats

# Schema configuration
dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

# Include core schemas
include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif
include: file:///etc/ldap/schema/nis.ldif

# Frontend database (special)
dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcSizeLimit: 500

# Config database
dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=admin,cn=config
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break

# MDB backend module
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb

# MDB database
dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: ${LDAP_DATA_PATH}
olcSuffix: ${LDAP_BASE_DN}
olcRootDN: ${LDAP_ADMIN_DN}
olcRootPW: ${ADMIN_PASSWORD_HASH}
olcDbIndex: objectClass eq
olcDbIndex: cn,uid eq
olcDbIndex: uidNumber,gidNumber eq
olcDbIndex: member,memberUid eq
olcDbIndex: entryCSN eq
olcDbIndex: entryUUID eq
olcDbMaxSize: 1073741824
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by * read
olcAccess: {2}to * by * read
LDIF_EOF

log_info "Loading initial configuration with slapadd..."
slapadd -F "${SLAPD_CONF_DIR}" -n 0 -l "${INIT_LDIF}"

# Verify configuration
if ! [ -d "${SLAPD_CONF_DIR}/cn=config" ]; then
    log_error "slapd configuration directory not created"
    exit 1
fi

log_info "slapd configuration initialized successfully"
log_info "Base DN: ${LDAP_BASE_DN}"
log_info "Admin DN: ${LDAP_ADMIN_DN}"
