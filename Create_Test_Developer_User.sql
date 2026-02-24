




-- =============================================================================
-- 8. Create Test User with Developer Access to DWH Domain
-- =============================================================================

USE ROLE USERADMIN;

-- Create test user with generic password (MFA exempt)
CREATE USER IF NOT EXISTS TEST_DEV_USER
    PASSWORD = 'TestPassword123!'
    DEFAULT_ROLE = 'SRF_DEV_DEVELOPER'
    DEFAULT_WAREHOUSE = 'DEV_STG_WH'
    COMMENT = 'Test user for DEV environment with DWH domain access'
    MUST_CHANGE_PASSWORD = FALSE;

ALTER USER TEST_DEV_USER SET MINS_TO_BYPASS_MFA = 60;

-- Grant functional role (capability)
GRANT ROLE SRF_DEV_DEVELOPER TO USER TEST_DEV_USER;

-- Grant access role (domain)
GRANT ROLE SRA_DEV_DWH_ACCESS TO USER TEST_DEV_USER;

-- Verify user properties and grants
DESC USER TEST_DEV_USER;
SHOW GRANTS TO USER TEST_DEV_USER;

-- =============================================================================
-- Test Login Credentials
-- =============================================================================
-- Username: TEST_DEV_USER
-- Password: TestPassword123!
-- Default Role: SRF_DEV_DEVELOPER
-- Secondary Roles: SRA_DEV_DWH_ACCESS (auto-activated)
-- Access: Can develop + access DWH domain data in STG_DEV.TEST schema
-- MFA: EXEMPT (MINS_TO_BYPASS_MFA = 999999999)
-- =============================================================================

-- =============================================================================
-- VERIFY ACCESS BOUNDARIES
-- =============================================================================

-- Test 1: User CAN see ADMIN database (metadata visibility)
USE ROLE SRF_DEV_DEVELOPER;
SHOW SCHEMAS IN DATABASE ADMIN;

-- Test 2: User CANNOT execute ADMIN.RBAC procedures (no USAGE grant)
-- This should fail with permission denied:
-- CALL ADMIN.RBAC.RBAC_HELP();

-- Test 3: User CAN access STG_DEV.TEST (has proper grants)
USE DATABASE STG_DEV;
USE SCHEMA TEST;
SELECT CURRENT_DATABASE(), CURRENT_SCHEMA();

-- Test 4: User CAN use ADMIN.CLONES schema (explicitly granted)
USE SCHEMA ADMIN.CLONES;
SHOW PROCEDURES;

-- =============================================================================
-- SECURITY EXPLANATION
-- =============================================================================
-- Snowflake shows object METADATA to all users for discovery purposes
-- But actual USAGE/EXECUTION requires explicit privilege grants
-- The RBAC procedures are SECURE, requiring USAGE privilege to execute
-- TEST_DEV_USER has NO grants on ADMIN.RBAC, so cannot execute anything
-- =============================================================================



show grants to role SRF_DEV_DEVELOPER;