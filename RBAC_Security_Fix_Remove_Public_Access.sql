/*******************************************************************************
 * CRITICAL SECURITY FIX: Remove PUBLIC Access to ADMIN.RBAC
 * 
 * VULNERABILITY:
 * The initial config grants USAGE on ADMIN.RBAC to PUBLIC role, allowing
 * ANY user (including developers, end users) to execute sensitive RBAC
 * procedures like user management, role grants, and access control.
 * 
 * IMPACT:
 * - TEST_DEV_USER can execute ADMIN.RBAC.RBAC_CONFIGURE_USER
 * - Any user can execute ADMIN.RBAC.RBAC_GRANT_USER_ACCESS
 * - Developers can modify security configurations
 * 
 * FIX:
 * 1. Revoke PUBLIC access from ADMIN.RBAC
 * 2. Grant selective access only to appropriate roles
 * 3. Provide read-only procedures for end users via separate schema
 * 
 * EXECUTION:
 * USE ROLE SRS_SECURITY_ADMIN;
 * -- Run this script to remediate the vulnerability
 ******************************************************************************/

USE ROLE SRS_SECURITY_ADMIN;

-- =============================================================================
-- STEP 1: Revoke Dangerous PUBLIC Grants
-- =============================================================================

-- Revoke schema-level access
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE PUBLIC;
REVOKE USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.RBAC FROM ROLE PUBLIC;
REVOKE USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.RBAC FROM ROLE PUBLIC;

-- Also revoke from CLONES (developers should not create clones without approval)
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE PUBLIC;
REVOKE USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.CLONES FROM ROLE PUBLIC;
REVOKE USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.CLONES FROM ROLE PUBLIC;

-- Revoke database-level PUBLIC access
REVOKE USAGE ON DATABASE ADMIN FROM ROLE PUBLIC;

-- =============================================================================
-- STEP 2: Grant Selective Access to Appropriate Roles
-- =============================================================================

-- RBAC Schema: Only Security/User/System admins
GRANT USAGE ON SCHEMA ADMIN.RBAC TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON SCHEMA ADMIN.RBAC TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON SCHEMA ADMIN.RBAC TO ROLE SRS_SYSTEM_ADMIN;

GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_SYSTEM_ADMIN;

GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.RBAC TO ROLE SRS_SYSTEM_ADMIN;

-- CLONES Schema: Only DBADMIN and above can create clones
GRANT USAGE ON SCHEMA ADMIN.CLONES TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.CLONES TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ADMIN.CLONES TO ROLE SRS_SYSTEM_ADMIN;

-- =============================================================================
-- STEP 3: Grant Database-Level Access to System Roles
-- =============================================================================

GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_USER_ADMIN;
GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON DATABASE ADMIN TO ROLE SRS_DEVOPS;

-- =============================================================================
-- STEP 4: Create Read-Only Helper Procedures for End Users (Optional)
-- =============================================================================

-- If end users need to view their own access, create a PUBLIC-facing schema
-- with limited, safe procedures:
-- 
-- CREATE SCHEMA IF NOT EXISTS ADMIN.PUBLIC_HELP;
-- 
-- CREATE OR REPLACE SECURE PROCEDURE ADMIN.PUBLIC_HELP.MY_ACCESS()
-- RETURNS VARIANT
-- LANGUAGE SQL
-- EXECUTE AS CALLER
-- AS
-- $$
-- BEGIN
--     RETURN OBJECT_CONSTRUCT(
--         'user', CURRENT_USER(),
--         'current_role', CURRENT_ROLE(),
--         'available_roles', (SELECT ARRAY_AGG(ROLE) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE GRANTEE_NAME = CURRENT_USER())
--     );
-- END;
-- $$;
-- 
-- GRANT USAGE ON SCHEMA ADMIN.PUBLIC_HELP TO ROLE PUBLIC;
-- GRANT USAGE ON ALL PROCEDURES IN SCHEMA ADMIN.PUBLIC_HELP TO ROLE PUBLIC;

-- =============================================================================
-- STEP 5: Remove Environment-Specific Grants to Functional Roles
-- =============================================================================

-- Revoke ADMIN database access from END_USER roles (if exists)
REVOKE USAGE ON DATABASE ADMIN FROM ROLE SRF_DEV_END_USER;
REVOKE USAGE ON DATABASE ADMIN FROM ROLE SRF_TST_END_USER;
REVOKE USAGE ON DATABASE ADMIN FROM ROLE SRF_UAT_END_USER;
REVOKE USAGE ON DATABASE ADMIN FROM ROLE SRF_PPE_END_USER;
REVOKE USAGE ON DATABASE ADMIN FROM ROLE SRF_PRD_END_USER;

-- Revoke RBAC schema access from END_USER roles (if exists)
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE SRF_DEV_END_USER;
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE SRF_TST_END_USER;
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE SRF_UAT_END_USER;
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE SRF_PPE_END_USER;
REVOKE USAGE ON SCHEMA ADMIN.RBAC FROM ROLE SRF_PRD_END_USER;

-- Revoke CLONES schema access from DEVELOPER roles (if exists)
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE SRF_DEV_DEVELOPER;
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE SRF_TST_DEVELOPER;
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE SRF_UAT_DEVELOPER;
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE SRF_PPE_DEVELOPER;
REVOKE USAGE ON SCHEMA ADMIN.CLONES FROM ROLE SRF_PRD_DEVELOPER;

-- =============================================================================
-- STEP 6: Verify Fix
-- =============================================================================

-- Verify PUBLIC no longer has access
SHOW GRANTS TO ROLE PUBLIC;

-- Verify TEST_DEV_USER cannot execute RBAC procedures
-- Run as TEST_DEV_USER:
-- USE ROLE SRF_DEV_DEVELOPER;
-- CALL ADMIN.RBAC.RBAC_HELP();  -- Should fail with permission denied

SELECT 'SECURITY FIX APPLIED SUCCESSFULLY' AS STATUS;
