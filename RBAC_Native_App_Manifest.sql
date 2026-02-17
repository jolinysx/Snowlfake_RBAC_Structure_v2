/*******************************************************************************
 * RBAC NATIVE APPLICATION: Manifest and Setup Scripts
 * 
 * Purpose: Package the RBAC framework as a Snowflake Native Application for
 *          secure distribution to customers/clients
 * 
 * NATIVE APP BENEFITS:
 *   ✓ Code is completely hidden from consumers
 *   ✓ IP protection - consumers cannot view procedure definitions
 *   ✓ Version control and updates
 *   ✓ Can be distributed via Private Listings in Marketplace
 *   ✓ Consumer sees only the interface, not implementation
 *   ✓ Secure data sharing patterns
 * 
 * DIRECTORY STRUCTURE FOR NATIVE APP:
 *   rbac_native_app/
 *   ├── manifest.yml              -- App manifest (this file generates it)
 *   ├── setup_script.sql          -- Installation script
 *   ├── readme.md                 -- Consumer documentation
 *   └── scripts/
 *       ├── RBAC_SP_Initial_Config.sql
 *       ├── RBAC_SP_Identity_Integration.sql
 *       ├── RBAC_SP_Multi_Account.sql
 *       ├── RBAC_SP_External_Integration.sql
 *       ├── RBAC_SP_Create_Warehouse.sql
 *       ├── RBAC_SP_Create_Schema.sql
 *       ├── RBAC_SP_Access_Role.sql
 *       ├── RBAC_SP_Service_Role.sql
 *       ├── RBAC_SP_User_Management.sql
 *       ├── RBAC_SP_Audit_Roles.sql
 *       ├── RBAC_SP_Monitor_Config.sql
 *       └── RBAC_SP_Rectify_Config.sql
 ******************************************************************************/

-- =============================================================================
-- SECTION 1: CREATE APPLICATION PACKAGE (Provider Account)
-- =============================================================================

/*
 * Run these commands in the PROVIDER account (your account) to create
 * the application package that will be distributed to consumers.
 */

-- Step 1: Create a database for the application package
CREATE DATABASE IF NOT EXISTS RBAC_APP_PACKAGE_DB;
USE DATABASE RBAC_APP_PACKAGE_DB;

-- Step 2: Create a schema for application code
CREATE SCHEMA IF NOT EXISTS RBAC_CODE;
USE SCHEMA RBAC_CODE;

-- Step 3: Create internal stage for application files
CREATE OR REPLACE STAGE RBAC_APP_STAGE
    DIRECTORY = (ENABLE = TRUE)
    COMMENT = 'Stage for RBAC Native App files';

-- Step 4: Upload manifest.yml (create this file locally first)
-- PUT file://path/to/manifest.yml @RBAC_APP_STAGE AUTO_COMPRESS = FALSE;

-- Step 5: Upload setup script
-- PUT file://path/to/setup_script.sql @RBAC_APP_STAGE/scripts/ AUTO_COMPRESS = FALSE;

-- =============================================================================
-- SECTION 2: MANIFEST.YML CONTENT
-- =============================================================================

/*
 * Create a file named 'manifest.yml' with the following content:
 * Save this to your local filesystem, then upload to stage.
 * 
 * --- BEGIN manifest.yml ---

manifest_version: 1

version:
  name: "RBAC Framework"
  label: "1.0.0"

artifacts:
  setup_script: scripts/setup_script.sql
  readme: readme.md
  
configuration:
  log_level: INFO
  trace_level: OFF
  
privileges:
  - CREATE DATABASE:
      description: "Required to create RBAC administrative database"
  - CREATE ROLE:
      description: "Required to create RBAC roles (SRS, SRF, SRA, SRW, SRD)"
  - CREATE USER:
      description: "Required to create service accounts"
  - CREATE WAREHOUSE:
      description: "Required to create environment warehouses"
  - MANAGE GRANTS:
      description: "Required to manage role grants and privileges"
  - EXECUTE TASK:
      description: "Required for scheduled RBAC tasks"
  - CREATE SHARE:
      description: "Required for multi-account data sharing"
  - IMPORT SHARE:
      description: "Required for multi-account data sharing"

references:
  - snowflake_account:
      label: "Target Snowflake Account"
      description: "Account where RBAC will be implemented"
      privileges:
        - CREATE DATABASE
        - CREATE ROLE
        - MANAGE GRANTS

 * --- END manifest.yml ---
 */

-- =============================================================================
-- SECTION 3: SETUP_SCRIPT.SQL CONTENT
-- =============================================================================

/*
 * This is the main setup script that runs when the app is installed.
 * It creates all the RBAC procedures in the consumer's account.
 */

-- Create the setup script content
-- This will be saved as 'setup_script.sql' and uploaded to the stage

-- ============= BEGIN SETUP_SCRIPT.SQL =============

-- Create application schema for RBAC procedures
CREATE SCHEMA IF NOT EXISTS RBAC;
GRANT USAGE ON SCHEMA RBAC TO APPLICATION ROLE APP_PUBLIC;

-- Create version tracking table
CREATE TABLE IF NOT EXISTS RBAC.APP_VERSION (
    VERSION VARCHAR(20),
    INSTALLED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    INSTALLED_BY VARCHAR(255) DEFAULT CURRENT_USER()
);

INSERT INTO RBAC.APP_VERSION (VERSION) VALUES ('1.0.0');

-- =====================================================
-- RBAC PROCEDURES
-- All procedures are created with SECURE keyword
-- Consumers can execute but cannot view definitions
-- =====================================================

-- [Include all RBAC_SP_*.sql procedure definitions here]
-- The procedures will be included in the actual setup script

-- Grant execute on all procedures to the application role
-- This allows consumers to use the procedures

-- ============= END SETUP_SCRIPT.SQL =============

-- =============================================================================
-- SECTION 4: CREATE APPLICATION PACKAGE
-- =============================================================================

-- Create the application package
CREATE APPLICATION PACKAGE IF NOT EXISTS RBAC_FRAMEWORK_PACKAGE
    COMMENT = 'RBAC Framework - Role-Based Access Control for Snowflake';

-- Add the code stage to the package
ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    ADD VERSION v1_0 USING '@RBAC_APP_PACKAGE_DB.RBAC_CODE.RBAC_APP_STAGE';

-- Set the release directive
ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    SET DEFAULT RELEASE DIRECTIVE
    VERSION = v1_0
    PATCH = 0;

-- =============================================================================
-- SECTION 5: CREATE PRIVATE LISTING (Optional - for Marketplace distribution)
-- =============================================================================

/*
 * To distribute via Snowflake Marketplace as a Private Listing:
 * 
 * 1. Go to Provider Studio in Snowflake UI
 * 2. Create New Listing
 * 3. Select "Private" visibility
 * 4. Link to RBAC_FRAMEWORK_PACKAGE
 * 5. Add authorized consumer accounts
 * 6. Publish listing
 * 
 * Consumers will then see the app in their Marketplace under "Private" listings
 */

-- =============================================================================
-- SECTION 6: TESTING THE APPLICATION (Provider Side)
-- =============================================================================

-- Create a test installation in your own account
CREATE APPLICATION RBAC_FRAMEWORK_TEST
    FROM APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    USING VERSION v1_0;

-- Verify the application was installed correctly
SHOW APPLICATIONS LIKE 'RBAC_FRAMEWORK_TEST';

-- Test a procedure (should execute but definition should be hidden)
-- CALL RBAC_FRAMEWORK_TEST.RBAC.RBAC_INITIAL_CONFIG(NULL, TRUE);

-- Clean up test installation
-- DROP APPLICATION RBAC_FRAMEWORK_TEST;

-- =============================================================================
-- SECTION 7: CONSUMER INSTALLATION GUIDE
-- =============================================================================

/*
 * CONSUMER INSTALLATION STEPS:
 * 
 * 1. Accept the private listing in Snowflake Marketplace
 *    - Go to Data Products > Private Sharing
 *    - Find "RBAC Framework" listing
 *    - Click "Get"
 * 
 * 2. Install the application
 *    CREATE APPLICATION RBAC_FRAMEWORK
 *        FROM LISTING 'RBAC Framework'
 *        COMMENT = 'RBAC Framework installation';
 * 
 * 3. Grant required privileges
 *    GRANT CREATE DATABASE ON ACCOUNT TO APPLICATION RBAC_FRAMEWORK;
 *    GRANT CREATE ROLE ON ACCOUNT TO APPLICATION RBAC_FRAMEWORK;
 *    GRANT CREATE WAREHOUSE ON ACCOUNT TO APPLICATION RBAC_FRAMEWORK;
 *    GRANT MANAGE GRANTS ON ACCOUNT TO APPLICATION RBAC_FRAMEWORK;
 * 
 * 4. Initialize RBAC
 *    CALL RBAC_FRAMEWORK.RBAC.RBAC_INITIAL_CONFIG(NULL, FALSE);
 * 
 * 5. View available procedures
 *    SHOW PROCEDURES IN SCHEMA RBAC_FRAMEWORK.RBAC;
 *    -- Note: Definitions will show as "hidden" for SECURE procedures
 */

-- =============================================================================
-- SECTION 8: VERSION MANAGEMENT
-- =============================================================================

-- Add a new version (when you release updates)
/*
ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    ADD VERSION v1_1 USING '@RBAC_APP_PACKAGE_DB.RBAC_CODE.RBAC_APP_STAGE';

-- Update release directive to new version
ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    SET DEFAULT RELEASE DIRECTIVE
    VERSION = v1_1
    PATCH = 0;
*/

-- Add a patch to existing version
/*
ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE
    ADD PATCH FOR VERSION v1_0 USING '@RBAC_APP_PACKAGE_DB.RBAC_CODE.RBAC_APP_STAGE';
*/

-- =============================================================================
-- SECTION 9: PROCEDURE TO GENERATE SETUP SCRIPT
-- =============================================================================

/*
 * This procedure concatenates all RBAC procedure files into a single
 * setup_script.sql file for the Native App
 */

CREATE OR REPLACE SECURE PROCEDURE RBAC_GENERATE_NATIVE_APP_SETUP()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    RETURN 'To generate the Native App setup script:
    
1. Concatenate all RBAC_SP_*.sql files into setup_script.sql
2. Wrap with CREATE SCHEMA and GRANT statements
3. Upload to @RBAC_APP_STAGE/scripts/setup_script.sql
4. Create/update the application package version

Manual steps required as file concatenation needs external tools.

Files to include:
- RBAC_SP_Initial_Config.sql
- RBAC_SP_Identity_Integration.sql
- RBAC_SP_Multi_Account.sql
- RBAC_SP_External_Integration.sql
- RBAC_SP_Create_Warehouse.sql
- RBAC_SP_Create_Schema.sql
- RBAC_SP_Access_Role.sql
- RBAC_SP_Service_Role.sql
- RBAC_SP_User_Management.sql
- RBAC_SP_Audit_Roles.sql
- RBAC_SP_Monitor_Config.sql
- RBAC_SP_Rectify_Config.sql
';
END;
$$;

-- =============================================================================
-- SECTION 10: LICENSING AND TERMS (Template)
-- =============================================================================

/*
 * Include in readme.md for the Native App:
 * 
 * # RBAC Framework for Snowflake
 * 
 * ## Overview
 * Enterprise-grade Role-Based Access Control framework for Snowflake.
 * 
 * ## Features
 * - Environment-based access control (DEV, TST, UAT, PPE, PRD)
 * - Functional roles (SRF_*) for capabilities
 * - Access roles (SRA_*) for data segregation
 * - Service account management (SRW_*)
 * - SSO/SCIM integration support
 * - Multi-account architecture support
 * - External system integration (ServiceNow, Jira)
 * - Audit and compliance procedures
 * 
 * ## Getting Started
 * 1. Install the application
 * 2. Grant required privileges
 * 3. Run RBAC_INITIAL_CONFIG()
 * 4. Create warehouses and schemas
 * 5. Configure users and access
 * 
 * ## Support
 * Contact: [Your contact information]
 * 
 * ## License
 * Proprietary - All rights reserved
 * This software is licensed, not sold. Unauthorized copying,
 * reverse engineering, or distribution is prohibited.
 */

-- =============================================================================
-- QUICK REFERENCE: NATIVE APP COMMANDS
-- =============================================================================

/*
 * PROVIDER COMMANDS:
 * ------------------
 * -- Create package
 * CREATE APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE;
 * 
 * -- Add version
 * ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE ADD VERSION v1_0 USING '@stage';
 * 
 * -- Set release
 * ALTER APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE SET DEFAULT RELEASE DIRECTIVE VERSION = v1_0;
 * 
 * -- List packages
 * SHOW APPLICATION PACKAGES;
 * 
 * -- View versions
 * SHOW VERSIONS IN APPLICATION PACKAGE RBAC_FRAMEWORK_PACKAGE;
 * 
 * CONSUMER COMMANDS:
 * ------------------
 * -- Install from listing
 * CREATE APPLICATION RBAC_FRAMEWORK FROM LISTING 'listing_name';
 * 
 * -- Install from package (same org)
 * CREATE APPLICATION RBAC_FRAMEWORK FROM APPLICATION PACKAGE provider.RBAC_FRAMEWORK_PACKAGE;
 * 
 * -- View installed apps
 * SHOW APPLICATIONS;
 * 
 * -- Upgrade app
 * ALTER APPLICATION RBAC_FRAMEWORK UPGRADE;
 * 
 * -- Remove app
 * DROP APPLICATION RBAC_FRAMEWORK;
 */
