/*******************************************************************************
 # SNOWFLAKE RBAC FRAMEWORK
 * 
 * Enterprise Role-Based Access Control for Snowflake
 * 
 * ============================================================================
 * ADMIN DATABASE STRUCTURE
 * ============================================================================
 * 
 * All RBAC procedures are deployed to the ADMIN database with separate schemas:
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           ADMIN DATABASE                                    │
 * │                       Owner: SRS_SYSTEM_ADMIN                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.RBAC       │ Core RBAC procedures (setup, users, roles, audit)       │
 * │ ADMIN.DEVOPS     │ CI/CD pipelines, deployments, Git, releases             │
 * │ ADMIN.CLONES     │ Clone management, audit, compliance, monitoring         │
 * │ ADMIN.SECURITY   │ Security policies, alerts, exceptions, monitoring       │
 * │ ADMIN.GOVERNANCE │ Data governance (RLS, masking, classification, tags)    │
 * │ ADMIN.BACKUP     │ Backup management, policies, retention, restore         │
 * │ ADMIN.HADR       │ HA/DR, replication, failover, DR testing, RTO/RPO       │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 * ACCESS CONTROL MATRIX
 * ============================================================================
 * 
 * Detailed privileges by schema and role:
 * 
 * │ Schema     │ PUBLIC │ SRS_DEVOPS │ SRS_SECURITY │ SRF_*_DEV │ SRF_*_DBADMIN │
 * │────────────│────────│────────────│──────────────│───────────│───────────────│
 * │ RBAC       │ USAGE  │ USAGE      │ ALL          │ USAGE     │ USAGE         │
 * │ DEVOPS     │ -      │ ALL        │ USAGE        │ -         │ USAGE         │
 * │ CLONES     │ USAGE  │ USAGE      │ ALL          │ USAGE     │ USAGE         │
 * │ SECURITY   │ -      │ -          │ ALL          │ -         │ USAGE         │
 * │ GOVERNANCE │ -      │ -          │ ALL          │ -         │ USAGE         │
 * │ BACKUP     │ -      │ -          │ ALL          │ -         │ USAGE         │
 * │ HADR       │ -      │ -          │ ALL          │ -         │ USAGE (view)  │
 * 
 * Legend:
 *   ALL   = Full access (create, modify, delete, execute)
 *   USAGE = Execute procedures and read tables
 *   -     = No direct access
 * 
 * ============================================================================
 * DEPLOYMENT SEQUENCE (Correct Order)
 * ============================================================================
 * 
 * IMPORTANT: Different roles are required for different deployment steps!
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ ROLE REQUIREMENTS FOR DEPLOYMENT                                           │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │ ACCOUNTADMIN     │ Initial config (creates roles, database, schemas)       │
 * │ SRS_SYSTEM_ADMIN │ Deploy all procedure files (owns ADMIN database)        │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 * STEP 1: INITIAL SETUP (Run as ACCOUNTADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE ACCOUNTADMIN;
 *   
 *   -- First, deploy the Initial Config procedure
 *   -- Run the contents of RBAC_SP_Initial_Config.sql
 *   
 *   -- Then execute it to create all roles and schemas
 *   CALL RBAC_INITIAL_CONFIG(NULL, FALSE);
 *   -- Creates: SRS_* roles, SRF_* roles, ADMIN database, all 7 schemas, grants
 * 
 * STEP 2: DEPLOY TO ADMIN.RBAC (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.RBAC;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │   1   │ RBAC_SP_Help.sql                │ SRS_SYSTEM_ADMIN │
 *   │   2   │ RBAC_SP_Create_Warehouse.sql    │ SRS_SYSTEM_ADMIN │
 *   │   3   │ RBAC_SP_Create_Schema.sql       │ SRS_SYSTEM_ADMIN │
 *   │   4   │ RBAC_SP_Access_Role.sql         │ SRS_SYSTEM_ADMIN │
 *   │   5   │ RBAC_SP_Service_Role.sql        │ SRS_SYSTEM_ADMIN │
 *   │   6   │ RBAC_SP_User_Management.sql     │ SRS_SYSTEM_ADMIN │
 *   │   7   │ RBAC_SP_Audit_Roles.sql         │ SRS_SYSTEM_ADMIN │
 *   │   8   │ RBAC_SP_Monitor_Config.sql      │ SRS_SYSTEM_ADMIN │
 *   │   9   │ RBAC_SP_Rectify_Config.sql      │ SRS_SYSTEM_ADMIN │
 *   │  10   │ RBAC_SP_Identity_Integration.sql│ SRS_SYSTEM_ADMIN │
 *   │  11   │ RBAC_SP_External_Integration.sql│ SRS_SYSTEM_ADMIN │
 *   │  12   │ RBAC_SP_Multi_Account.sql       │ SRS_SYSTEM_ADMIN │
 *   │  13   │ RBAC_SP_Cost_Management.sql     │ SRS_SYSTEM_ADMIN │
 *   │  14   │ RBAC_SP_Validate_Deployment.sql │ SRS_SYSTEM_ADMIN │  ◄── Deploy LAST
 *   │  14   │ RBAC_SP_Validate_Deployment.sql │ SRS_SYSTEM_ADMIN │  ◄── Deploy LAST
 * 
 * STEP 3: DEPLOY TO ADMIN.DEVOPS (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.DEVOPS;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  14   │ RBAC_SP_DevOps.sql              │ SRS_SYSTEM_ADMIN │
 *   │  15   │ RBAC_SP_DevOps_Monitoring.sql   │ SRS_SYSTEM_ADMIN │
 * 
 * STEP 4: DEPLOY TO ADMIN.CLONES (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.CLONES;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  16   │ RBAC_SP_Clone_Management.sql    │ SRS_SYSTEM_ADMIN │
 *   │  17   │ RBAC_SP_Clone_Audit.sql         │ SRS_SYSTEM_ADMIN │
 *   │  18   │ RBAC_SP_Clone_Monitoring.sql    │ SRS_SYSTEM_ADMIN │
 * 
 * STEP 5: DEPLOY TO ADMIN.SECURITY (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.SECURITY;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  19   │ RBAC_SP_Security_Monitoring.sql │ SRS_SYSTEM_ADMIN │
 *   │  20   │ RBAC_SP_Policy_Management.sql   │ SRS_SYSTEM_ADMIN │
 * 
 * STEP 6: DEPLOY TO ADMIN.GOVERNANCE (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.GOVERNANCE;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  21   │ RBAC_SP_Data_Governance.sql     │ SRS_SYSTEM_ADMIN │
 *   │  22   │ RBAC_SP_Governance_Monitoring.sql│ SRS_SYSTEM_ADMIN │
 * 
 * STEP 7: DEPLOY TO ADMIN.BACKUP (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.BACKUP;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  23   │ RBAC_SP_Backup_Management.sql   │ SRS_SYSTEM_ADMIN │
 *   │  24   │ RBAC_SP_Backup_Monitoring.sql   │ SRS_SYSTEM_ADMIN │
 * 
 * STEP 8: DEPLOY TO ADMIN.HADR (Run as SRS_SYSTEM_ADMIN)
 * ─────────────────────────────────────────────────────────────────────────────
 *   USE ROLE SRS_SYSTEM_ADMIN;
 *   USE SCHEMA ADMIN.HADR;
 *   
 *   │ Order │ File                            │ Deploy Role      │
 *   │───────│─────────────────────────────────│──────────────────│
 *   │  25   │ RBAC_SP_HADR_Management.sql     │ SRS_SYSTEM_ADMIN │
 *   │  26   │ RBAC_SP_HADR_Monitoring.sql     │ SRS_SYSTEM_ADMIN │
 * 
 * OTHER FILES (Reference only - not deployed to schemas):
 * ─────────────────────────────────────────────────────────────────────────────
 *   │ File                            │ Purpose                                │
 *   │─────────────────────────────────│────────────────────────────────────────│
 *   │ RBAC_README.sql                 │ This file - framework documentation    │
 *   │ RBAC_Reference_Guide.sql        │ Comprehensive reference documentation  │
 *   │ RBAC_Native_App_Manifest.sql    │ Native App packaging for distribution  │
 * 
 * ============================================================================
 * GETTING STARTED
 * ============================================================================
 * 
 * After deploying procedures, run:
 * 
 *   -- STEP 1: Validate deployment
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT();    -- Full validation
 *   CALL ADMIN.RBAC.RBAC_DEPLOYMENT_STATUS();      -- Quick status table
 *   
 *   -- STEP 2: Get help
 *   CALL ADMIN.RBAC.RBAC_HELP();              -- List all documentation topics
 *   CALL ADMIN.RBAC.RBAC_HELP('SETUP');       -- Setup guide
 *   CALL ADMIN.RBAC.RBAC_HELP('QUICKSTART');  -- Quick reference
 *   CALL ADMIN.RBAC.RBAC_HELP('PROCEDURES');  -- Procedure reference
 * 
 * MODULAR VALIDATION (Validate specific sections):
 * 
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('RBAC');     -- Core RBAC only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('SECURITY'); -- Security only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('ROLES');    -- System roles only
 * 
 * ============================================================================
 * QUICK START EXAMPLES (Post-Deployment)
 * ============================================================================
 * 
 * Each example shows the REQUIRED ROLE for execution:
 * 
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ PROCEDURE EXECUTION ROLES                                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │ Procedure Type              │ Execution Role                               │
 * │─────────────────────────────│──────────────────────────────────────────────│
 * │ Create warehouse            │ SRF_<ENV>_DBADMIN                            │
 * │ Create schema/database      │ SRF_<ENV>_DBADMIN                            │
 * │ Create access role          │ SRS_SECURITY_ADMIN                           │
 * │ Link schema to access role  │ SRS_SECURITY_ADMIN                           │
 * │ Configure user              │ SRS_USER_ADMIN or SRS_SECURITY_ADMIN         │
 * │ Create service account      │ SRS_USER_ADMIN or SRS_SECURITY_ADMIN         │
 * │ Audit roles                 │ SRS_SECURITY_ADMIN                           │
 * │ Monitor/rectify config      │ SRF_<ENV>_DBADMIN or SRS_SECURITY_ADMIN      │
 * │ Clone management            │ SRF_<ENV>_DEVELOPER (within limits)          │
 * │ Clone admin (policies)      │ SRS_SECURITY_ADMIN                           │
 * │ Security monitoring         │ SRS_SECURITY_ADMIN                           │
 * │ Security policies           │ SRS_SECURITY_ADMIN (some need ACCOUNTADMIN)  │
 * │ Data governance             │ SRS_SECURITY_ADMIN                           │
 * │ Backup management           │ SRS_SECURITY_ADMIN or SRF_<ENV>_DBADMIN      │
 * │ HA/DR operations            │ SRS_SECURITY_ADMIN                           │
 * │ DevOps pipelines            │ SRS_DEVOPS                                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 * 
 * 1. CREATE WAREHOUSE
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRF_DEV_DBADMIN;  -- Environment-specific DBADMIN role
 *    CALL ADMIN.RBAC.RBAC_CREATE_WAREHOUSE('DEV', 'XSMALL', 60, NULL);
 * 
 * 2. CREATE SCHEMA
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRF_DEV_DBADMIN;  -- Environment-specific DBADMIN role
 *    CALL ADMIN.RBAC.RBAC_CREATE_SCHEMA('DEV', 'HR', 'EMPLOYEES', 'Employee data');
 * 
 * 3. CREATE ACCESS ROLE
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin creates access roles
 *    CALL ADMIN.RBAC.RBAC_CREATE_ACCESS_ROLE('DEV', 'HR', 'HR team access');
 * 
 * 4. LINK SCHEMA TO ACCESS ROLE
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin links schemas
 *    CALL ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE('DEV', 'HR', 'HR', 'EMPLOYEES', 'WRITE');
 * 
 * 5. CONFIGURE USER (SCIM-provisioned user)
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_USER_ADMIN;  -- User admin configures users
 *    CALL ADMIN.RBAC.RBAC_CONFIGURE_USER(
 *        'user@company.com',  -- Username (from SCIM)
 *        'DEV',               -- Environment
 *        'HR',                -- Domain (for access role)
 *        'DEVELOPER',         -- Capability level
 *        'DEV_WH',            -- Default warehouse
 *        NULL                 -- Additional access roles
 *    );
 * 
 * 6. CREATE SERVICE ACCOUNT
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_USER_ADMIN;  -- User admin creates service accounts
 *    CALL ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT(
 *        'SVC_POWERBI_HR',              -- Service account name
 *        'MIIBIjANBgkq...',             -- RSA public key
 *        'PRD',                         -- Environment
 *        'HR',                          -- Domain
 *        'ANALYST',                     -- Capability level
 *        'PRD_WH',                      -- Default warehouse
 *        'Power BI HR reporting',       -- Comment
 *        NULL                           -- Second RSA key (optional)
 *    );
 * 
 * 7. SETUP CLONE POLICIES
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin manages clone policies
 *    CALL ADMIN.CLONES.RBAC_SETUP_DEFAULT_CLONE_POLICIES();
 * 
 * 8. CREATE A CLONE (as developer)
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRF_DEV_DEVELOPER;  -- Developers can create clones within limits
 *    CALL ADMIN.CLONES.RBAC_CREATE_CLONE(
 *        'DEV',              -- Environment
 *        'HR_DEV',           -- Source database
 *        'EMPLOYEES',        -- Source schema
 *        'SCHEMA',           -- Clone type
 *        'Testing new feature'  -- Reason
 *    );
 * 
 * 9. RUN SECURITY SCAN
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin runs scans
 *    CALL ADMIN.SECURITY.RBAC_RUN_SECURITY_SCAN();
 * 
 * 10. SETUP DATA GOVERNANCE
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin manages governance
 *    -- Create standard masking policies
 *    CALL ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_MASKING_POLICIES('ADMIN', 'GOVERNANCE');
 *    -- Create standard governance tags
 *    CALL ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_GOVERNANCE_TAGS('ADMIN', 'GOVERNANCE');
 *    -- Auto-classify a table
 *    CALL ADMIN.GOVERNANCE.RBAC_AUTO_CLASSIFY_TABLE('HR_DEV', 'EMPLOYEES', 'PERSONAL_INFO');
 * 
 * 11. VIEW GOVERNANCE DASHBOARD (as DBADMIN)
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRF_PRD_DBADMIN;  -- DBAdmins can view governance dashboards
 *    CALL ADMIN.GOVERNANCE.RBAC_GOVERNANCE_MONITORING_DASHBOARD();
 * 
 * 12. SETUP BACKUP POLICY
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin manages backups
 *    CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP_POLICY(
 *        'DAILY_HR_BACKUP',  -- Policy name
 *        'HR_PRD',           -- Database
 *        'EMPLOYEES',        -- Schema (NULL = full database)
 *        NULL,               -- Table (NULL = full schema)
 *        'DAILY',            -- Frequency
 *        30,                 -- Retention days
 *        NULL,               -- Target database
 *        TRUE                -- Active
 *    );
 *    CALL ADMIN.BACKUP.RBAC_SETUP_BACKUP_SCHEDULE('DAILY_HR_BACKUP', 'ADMIN_WH');
 * 
 * 13. VIEW BACKUP DASHBOARD (as DBADMIN)
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRF_PRD_DBADMIN;  -- DBAdmins can view backup status
 *    CALL ADMIN.BACKUP.RBAC_BACKUP_MONITORING_DASHBOARD();
 * 
 * 14. SETUP HA/DR REPLICATION
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin manages HA/DR
 *    CALL ADMIN.HADR.RBAC_CREATE_REPLICATION_GROUP(
 *        'DR_PRIMARY_GROUP',           -- Group name
 *        'CROSS_ACCOUNT',              -- Type
 *        'DR_ACCOUNT_XYZ',             -- Target account
 *        'AWS_US_EAST_1',              -- Target region
 *        ARRAY_CONSTRUCT('HR_PRD', 'SALES_PRD'),  -- Databases
 *        60,                           -- RPO target (minutes)
 *        240,                          -- RTO target (minutes)
 *        'USING CRON 0 * * * * UTC'    -- Schedule
 *    );
 * 
 * 15. REGISTER DEVOPS PIPELINE
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_DEVOPS;  -- DevOps role manages pipelines
 *    CALL ADMIN.DEVOPS.RBAC_REGISTER_PIPELINE(
 *        'HR_ETL_PIPELINE',            -- Pipeline name
 *        'AZURE_DEVOPS',               -- Platform
 *        'https://dev.azure.com/...',  -- URL
 *        ARRAY_CONSTRUCT('DEV', 'TST', 'PRD'),  -- Environments
 *        'HR ETL deployment pipeline'  -- Description
 *    );
 * 
 * 16. AUDIT USER ROLE ASSIGNMENTS
 *    ─────────────────────────────────────────────────────────────────────────
 *    USE ROLE SRS_SECURITY_ADMIN;  -- Security admin audits roles
 *    CALL ADMIN.RBAC.RBAC_AUDIT_USER_ROLES(NULL, TRUE);  -- All environments
 *    CALL ADMIN.RBAC.RBAC_AUDIT_USER_ROLES('PRD', TRUE); -- PRD only
 * 
 * ============================================================================
 * HELP TOPICS
 * ============================================================================
 * 
 * CALL ADMIN.RBAC.RBAC_HELP('OVERVIEW');       -- Framework overview
 * CALL ADMIN.RBAC.RBAC_HELP('SETUP');          -- Initial setup guide
 * CALL ADMIN.RBAC.RBAC_HELP('QUICKSTART');     -- Quick reference commands
 * CALL ADMIN.RBAC.RBAC_HELP('ROLES');          -- Role naming conventions
 * CALL ADMIN.RBAC.RBAC_HELP('PROCEDURES');     -- Procedure reference
 * CALL ADMIN.RBAC.RBAC_HELP('SSO');            -- SSO/SCIM integration
 * CALL ADMIN.RBAC.RBAC_HELP('DEVOPS');         -- DevOps/CI/CD overview
 * CALL ADMIN.RBAC.RBAC_HELP('CLONES');         -- Clone management overview
 * CALL ADMIN.RBAC.RBAC_HELP('GOVERNANCE');     -- Data governance overview
 * CALL ADMIN.RBAC.RBAC_HELP('BACKUP');         -- Backup management overview
 * CALL ADMIN.RBAC.RBAC_HELP('HADR');           -- HA/DR overview
 * CALL ADMIN.RBAC.RBAC_HELP('COSTS');          -- Cost management overview
 * CALL ADMIN.RBAC.RBAC_HELP('MONITORING');     -- Monitoring dashboards
 * CALL ADMIN.RBAC.RBAC_HELP('EXAMPLE_SETUP');  -- Complete setup example
 * 
 * ============================================================================
 * PROCEDURE COUNT BY SCHEMA
 * ============================================================================
 * 
 * │ Schema     │ Files │ Procedures │ Tables │ Primary Functions              │
 * │────────────│───────│────────────│────────│─────────────────────────────────│
 * │ RBAC       │  13   │    ~55     │   4    │ Setup, Users, Roles, Costs     │
 * │ DEVOPS     │   2   │    ~25     │   5    │ Pipelines, Deploy, Rollback    │
 * │ CLONES     │   3   │    ~20     │   3    │ Create, Manage, Compliance     │
 * │ SECURITY   │   1   │    ~15     │   3    │ Alerts, Scans, Anomalies       │
 * │ GOVERNANCE │   2   │    ~25     │   3    │ RLS, Masking, Classification   │
 * │ BACKUP     │   2   │    ~20     │   5    │ Backup, Restore, Retention     │
 * │ HADR       │   2   │    ~20     │   6    │ Replication, Failover, DR Test │
 * │────────────│───────│────────────│────────│─────────────────────────────────│
 * │ TOTAL      │  25   │   ~180     │  29    │                                 │
 * 
 * ============================================================================
 * CODE PROTECTION
 * ============================================================================
 * 
 * All procedures use SECURE keyword:
 *   ✓ Users can execute but cannot view code
 *   ✓ GET_DDL() returns "Definition hidden"
 *   ✓ Maximum protection via Native App packaging
 * 
 * See: RBAC_Native_App_Manifest.sql for distribution options
 * 
 ******************************************************************************/

-- Deploy this file to display help
SELECT 'RBAC Framework deployed. Run CALL RBAC_HELP(); for documentation.' AS INFO;
