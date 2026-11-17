package com.cyberguard.incident.enums;

/**
 * Application roles used for role-based access control (RBAC).
 * Spring Security expects authorities prefixed with "ROLE_", which is
 * handled in {@link com.cyberguard.incident.security.UserPrincipal}.
 */
public enum Role {
    ADMIN,
    SECURITY_ANALYST,
    USER
}
