/*******************************************************************************
 * SNOWFLAKE RBAC FRAMEWORK - COMPREHENSIVE REFERENCE GUIDE
 * 
 * This file contains the complete documentation for the RBAC framework.
 * For interactive help, use: CALL ADMIN.RBAC.RBAC_HELP();
 * 
 * ============================================================================
 * TABLE OF CONTENTS
 * ============================================================================
 * 
 *   1. OVERVIEW
 *   2. ADMIN DATABASE STRUCTURE
 *   3. ROLE NAMING CONVENTIONS
 *   4. ROLE HIERARCHY
 *   5. DEPLOYMENT SEQUENCE
 *   6. PROCEDURE REFERENCE
 *   7. SSO/SCIM INTEGRATION
 *   8. MULTI-ACCOUNT ARCHITECTURE
 *   9. EXTERNAL INTEGRATIONS
 *  10. DEVOPS & CI/CD
 *  11. CLONE MANAGEMENT
 *  12. SECURITY MONITORING
 *  13. EXTENSIBILITY GUIDE
 *  14. CODE PROTECTION
 * 
 * ============================================================================
 * 1. OVERVIEW
 * ============================================================================
 * 
 * The RBAC framework provides:
 *   • Environment separation (DEV, TST, UAT, PPE, PRD)
 *   • Capability-based access via Functional Roles (SRF_*)
 *   • Data segregation via Access Roles (SRA_*)
 *   • Service account management via Wrapper Roles (SRW_*)
 *   • Schema-level access via Database Roles (SRD_*)
 *   • SSO/SCIM integration support
 *   • Multi-account architecture support
 *   • External system integration (ServiceNow, Jira)
 *   • Clone management with limits and compliance
 *   • Security monitoring and anomaly detection
 *   • DevOps pipeline integration
 *   • Audit and compliance tools
 * 
 * ============================================================================
 * 2. ADMIN DATABASE STRUCTURE
 * ============================================================================
 * 
 * All RBAC procedures are deployed to the ADMIN database:
 * 
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                         ADMIN DATABASE                                   │
 * │                     Owner: SRS_SYSTEM_ADMIN                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.RBAC                                                               │
 * │   Core RBAC procedures: Help, Config, Users, Roles, Audit               │
 * │   Access: PUBLIC (all users can execute help/config procedures)         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.DEVOPS                                                             │
 * │   DevOps procedures: Pipelines, Deployments, Git, Releases              │
 * │   Access: SRS_DEVOPS, SRF_*_TEAM_LEADER                                 │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.CLONES                                                             │
 * │   Clone procedures: Management, Audit, Compliance, Monitoring           │
 * │   Access: PUBLIC (developers can create clones within limits)           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.SECURITY                                                           │
 * │   Security procedures: Alerts, Exceptions, Anomaly Detection            │
 * │   Access: SRS_SECURITY_ADMIN, SRF_*_DBADMIN                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.GOVERNANCE                                                         │
 * │   Data Governance: RLS, Masking, Classification, Tagging                │
 * │   Access: SRS_SECURITY_ADMIN, SRF_*_DBADMIN                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.BACKUP                                                             │
 * │   Backup Management: Create, Restore, Policies, Retention               │
 * │   Access: SRS_SECURITY_ADMIN, SRF_*_DBADMIN                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ ADMIN.HADR                                                               │
 * │   HA/DR: Replication, Failover, DR Testing, RTO/RPO Monitoring          │
 * │   Access: SRS_SECURITY_ADMIN, SRF_*_DBADMIN (view only)                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 * 
 * SCHEMA TO FILE MAPPING:
 * 
 * ADMIN.RBAC:
 *   RBAC_SP_Help.sql, RBAC_SP_Initial_Config.sql, RBAC_SP_Identity_Integration.sql,
 *   RBAC_SP_Multi_Account.sql, RBAC_SP_External_Integration.sql,
 *   RBAC_SP_Create_Warehouse.sql, RBAC_SP_Create_Schema.sql,
 *   RBAC_SP_Access_Role.sql, RBAC_SP_Service_Role.sql, RBAC_SP_User_Management.sql,
 *   RBAC_SP_Audit_Roles.sql, RBAC_SP_Monitor_Config.sql, RBAC_SP_Rectify_Config.sql
 * 
 * ADMIN.DEVOPS:
 *   RBAC_SP_DevOps.sql, RBAC_SP_DevOps_Monitoring.sql
 * 
 * ADMIN.CLONES:
 *   RBAC_SP_Clone_Management.sql, RBAC_SP_Clone_Audit.sql, RBAC_SP_Clone_Monitoring.sql
 * 
 * ADMIN.SECURITY:
 *   RBAC_SP_Security_Monitoring.sql
 * 
 * ADMIN.GOVERNANCE:
 *   RBAC_SP_Data_Governance.sql, RBAC_SP_Governance_Monitoring.sql
 * 
 * ADMIN.BACKUP:
 *   RBAC_SP_Backup_Management.sql, RBAC_SP_Backup_Monitoring.sql
 * 
 * ADMIN.HADR:
 *   RBAC_SP_HADR_Management.sql, RBAC_SP_HADR_Monitoring.sql
 * 
 * ============================================================================
 * 3. ROLE NAMING CONVENTIONS
 * ============================================================================
 * 
 * | Prefix | Type            | Pattern                              | Example                    |
 * |--------|-----------------|--------------------------------------|----------------------------|
 * | SRS_   | System Role     | SRS_<FUNCTION>                       | SRS_SECURITY_ADMIN         |
 * | SRF_   | Functional Role | SRF_<ENV>_<CAPABILITY>                | SRF_DEV_DEVELOPER          |
 * | SRA_   | Access Role     | SRA_<ENV>_<DOMAIN>_ACCESS             | SRA_DEV_HR_ACCESS          |
 * | SRW_   | Wrapper Role    | SRW_<ENV>_<DOMAIN>_<CAPABILITY>       | SRW_PRD_SALES_ANALYST      |
 * | SRD_   | Database Role   | SRD_<DOMAIN>_<ENV>_<SCHEMA>_<RW>      | SRD_HR_DEV_EMPLOYEES_READ  |
 * 
 * ENVIRONMENTS: DEV, TST, UAT, PPE, PRD
 * 
 * CAPABILITY LEVELS (hierarchy - each inherits from previous):
 *   END_USER       → Basic read access
 *   ANALYST        → Query and analyze
 *   DEVELOPER      → Create objects, write (DEV only)
 *   TEAM_LEADER    → Manage team access
 *   DATA_SCIENTIST → ML and advanced analytics
 *   DBADMIN        → Full admin for environment
 * 
 * ============================================================================
 * 3. ROLE HIERARCHY
 * ============================================================================
 * 
 *                    ┌─────────────────────────────────────┐
 *                    │           ACCOUNTADMIN              │
 *                    └──────────────┬──────────────────────┘
 *                                   │
 *           ┌───────────────────────┼───────────────────────┐
 *           ▼                       ▼                       ▼
 *  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 *  │ SRS_ACCOUNT_    │    │ SRS_SECURITY_   │    │ SRS_SYSTEM_     │
 *  │ ADMIN           │    │ ADMIN           │    │ ADMIN           │
 *  └─────────────────┘    └────────┬────────┘    └────────┬────────┘
 *                                  │                      │
 *                    ┌─────────────┴──────────┐           │
 *                    ▼                        ▼           ▼
 *           ┌─────────────────┐      ┌─────────────────────────┐
 *           │ SRS_USER_ADMIN  │      │ SRF_*_DBADMIN           │
 *           └─────────────────┘      │ (per environment)       │
 *                                    └───────────┬─────────────┘
 *                                                │
 *                              ┌─────────────────┼─────────────────┐
 *                              ▼                 ▼                 ▼
 *                    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 *                    │SRF_*_DATA_   │   │SRF_*_TEAM_   │   │SRF_*_        │
 *                    │SCIENTIST     │   │LEADER        │   │DEVELOPER     │
 *                    └──────────────┘   └──────────────┘   └──────────────┘
 *                                                │
 *                                       ┌───────┴───────┐
 *                                       ▼               ▼
 *                              ┌──────────────┐ ┌──────────────┐
 *                              │SRF_*_ANALYST │ │SRF_*_END_USER│
 *                              └──────────────┘ └──────────────┘
 * 
 * ACCESS ROLE STRUCTURE:
 * 
 *   SRA_DEV_HR_ACCESS (Access Role)
 *        │
 *        ├──► SRD_HR_DEV_EMPLOYEES_READ   (Database Role)
 *        ├──► SRD_HR_DEV_EMPLOYEES_WRITE  (Database Role)
 *        └──► SRD_HR_DEV_PAYROLL_READ     (Database Role)
 * 
 * USER ASSIGNMENT:
 * 
 *   User: john.doe@company.com
 *        │
 *        ├──► SRF_DEV_DEVELOPER    (Functional - what they can do)
 *        │
 *        └──► SRA_DEV_HR_ACCESS    (Access - where they can do it)
 * 
 * ============================================================================
 * 4. DEPLOYMENT SEQUENCE
 * ============================================================================
 * 
 * STEP 1: Initial Configuration (ACCOUNTADMIN)
 *   CALL RBAC_INITIAL_CONFIG(NULL, FALSE);
 * 
 * STEP 2: Create Warehouses (SRF_*_DBADMIN)
 *   USE ROLE SRF_DEV_DBADMIN;
 *   CALL RBAC_CREATE_WAREHOUSE('DEV', 'XSMALL', 60, NULL);
 * 
 * STEP 3: Create Databases & Schemas (SRF_*_DBADMIN)
 *   CALL RBAC_CREATE_SCHEMA('DEV', 'HR', 'EMPLOYEES', 'Employee data');
 * 
 * STEP 4: Create Access Roles (SRS_SECURITY_ADMIN)
 *   USE ROLE SRS_SECURITY_ADMIN;
 *   CALL RBAC_CREATE_ACCESS_ROLE('DEV', 'HR', 'HR team access');
 * 
 * STEP 5: Link Schemas to Access Roles
 *   CALL RBAC_LINK_SCHEMA_TO_ACCESS_ROLE('DEV', 'HR', 'HR', 'EMPLOYEES', 'WRITE');
 * 
 * STEP 6: Configure Users
 *   CALL RBAC_CONFIGURE_USER('user@company.com', 'DEV', 'HR', 'DEVELOPER', 'DEV_WH', NULL);
 * 
 * ============================================================================
 * 5. PROCEDURE REFERENCE
 * ============================================================================
 * 
 * INITIAL SETUP:
 *   RBAC_INITIAL_CONFIG(environments, dry_run)
 *   RBAC_INITIAL_CONFIG_MULTI_ACCOUNT(account_type, purpose, environments, sub_domains, dry_run)
 * 
 * SSO/SCIM:
 *   RBAC_SETUP_SSO_OKTA(name, issuer, sso_url, cert)
 *   RBAC_SETUP_SSO_AZURE_AD(name, issuer, sso_url, cert)
 *   RBAC_SETUP_MODEL_A_BASIC_SCIM(idp_type, name, network_policy)
 *   RBAC_SETUP_MODEL_B_FULL_SCIM(idp_type, name, network_policy)
 *   RBAC_GENERATE_SCIM_TOKEN(integration_name)
 *   RBAC_LIST_SCIM_USERS_PENDING_CONFIG()
 * 
 * INFRASTRUCTURE:
 *   RBAC_CREATE_WAREHOUSE(env, size, auto_suspend, suffix)
 *   RBAC_CREATE_SCHEMA(env, database, schema, comment)
 * 
 * ACCESS MANAGEMENT:
 *   RBAC_CREATE_ACCESS_ROLE(env, domain, comment)
 *   RBAC_LINK_SCHEMA_TO_ACCESS_ROLE(env, domain, database, schema, access_level)
 *   RBAC_GRANT_USER_ACCESS(user, env, domain, capability)
 *   RBAC_REVOKE_USER_ACCESS(user, env, domain, revoke_functional)
 * 
 * SERVICE ACCOUNT MANAGEMENT:
 *   RBAC_CREATE_SERVICE_ROLE(env, domain, capability, comment)
 *   RBAC_ADD_ACCESS_TO_SERVICE_ROLE(env, service_domain, capability, additional_domain)
 *   RBAC_CREATE_SERVICE_ACCOUNT(name, rsa_key, env, domain, capability, warehouse, comment, rsa_key_2)
 *   RBAC_GRANT_SERVICE_ACCOUNT(service_account, env, domain, capability, set_default)
 *   RBAC_REVOKE_SERVICE_ACCOUNT(service_account, env, domain, capability)
 *   RBAC_ROTATE_SERVICE_KEY(account, new_key, key_slot)
 * 
 * USER MANAGEMENT:
 *   RBAC_CONFIGURE_USER(user, env, domain, capability, warehouse, additional_domains)
 *   RBAC_DISABLE_USER(user, reason)
 * 
 * AUDIT & MONITORING:
 *   RBAC_AUDIT_USER_ROLES(env, include_details)
 *   RBAC_GENERATE_REMEDIATION_SCRIPT(env)
 *   RBAC_GET_USER_ROLE_SUMMARY(user)
 *   RBAC_MONITOR_CONFIG(env, database, schema)
 *   RBAC_RECTIFY_CONFIG(env, database, schema, dry_run)
 * 
 * MULTI-ACCOUNT:
 *   RBAC_INITIAL_CONFIG_MULTI_ACCOUNT(account_type, account_purpose, environments, sub_domains, dry_run)
 *   RBAC_CREATE_ACCESS_ROLE_MULTI_ACCOUNT(account_type, environment, sub_domain, comment)
 *   RBAC_CREATE_OUTBOUND_SHARE(share_name, database, schemas, consumer_accounts, comment)
 *   RBAC_MOUNT_INBOUND_SHARE(share_identifier, local_db_name, access_role, comment)
 *   RBAC_CREATE_SHARED_DATA_ACCESS_ROLE(source_account, source_domain, environment, comment)
 *   RBAC_LIST_ACCOUNT_SHARES()
 *   RBAC_MULTI_ACCOUNT_SCIM_GUIDE(account_type, idp_type)
 *   RBAC_ORG_ACCOUNT_INVENTORY()
 * 
 * EXTERNAL INTEGRATION:
 *   RBAC_SETUP_SERVICENOW_ACCESS(instance, secret, username, password, integration)
 *   RBAC_SETUP_JIRA_ACCESS(url, secret, email, token, integration)
 *   RBAC_REQUEST_ACCESS(requestor, env, domain, capability, justification, system, project)
 *   RBAC_CHECK_AND_GRANT_APPROVED(ticket, system, requestor, env, domain, capability, warehouse)
 *   RBAC_CREATE_ACCESS_REVIEW_TICKETS(env, system, project, dry_run)
 *   RBAC_SERVICENOW_CREATE_ACCESS_REQUEST(...)
 *   RBAC_SERVICENOW_CHECK_TICKET_STATUS(ticket_number)
 *   RBAC_SERVICENOW_LOG_AUDIT_EVENT(event_type, user, role, performed_by, ticket, details)
 *   RBAC_JIRA_CREATE_ACCESS_REQUEST(...)
 *   RBAC_JIRA_CHECK_ISSUE_STATUS(issue_key)
 * 
 * HELP SYSTEM:
 *   RBAC_HELP(topic)
 *   RBAC_HELP_SETUP()
 *   RBAC_HELP_ROLES()
 *   RBAC_HELP_PROCEDURES()
 *   RBAC_HELP_QUICKSTART()
 *   RBAC_HELP_DEVOPS()
 * 
 * DEVOPS & CI/CD:
 *   DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT(pipeline, domain, rsa_key, environments, capability, comment)
 *   DEVOPS_SETUP_AZURE_DEVOPS(project, domain, rsa_key, environments)
 *   DEVOPS_SETUP_GITHUB_ACTIONS(repo, domain, rsa_key, environments)
 *   DEVOPS_SETUP_GITLAB(project, domain, rsa_key, environments)
 *   DEVOPS_SETUP_GIT_REPOSITORY(name, url, provider, secret, integration, branch)
 *   DEVOPS_CREATE_GIT_SECRET(secret_name, provider, username, token)
 *   DEVOPS_START_DEPLOYMENT(env, database, schema, type, pipeline, run_id, commit, branch, metadata)
 *   DEVOPS_LOG_DEPLOYMENT_OBJECT(deployment_id, object_type, object_name, operation, definition)
 *   DEVOPS_COMPLETE_DEPLOYMENT(deployment_id, status, error)
 *   DEVOPS_DEPLOY_FROM_GIT(repo, branch, file, env, database, schema)
 *   DEVOPS_PROMOTE_SCHEMA(source_env, target_env, database, schema, object_types, dry_run)
 *   DEVOPS_CLONE_SCHEMA(source_env, target_env, database, schema, include_data)
 *   DEVOPS_ROLLBACK_DEPLOYMENT(deployment_id, rollback_type, point_in_time)
 *   DEVOPS_GET_DEPLOYMENT_HISTORY(env, database, days_back, status)
 *   DEVOPS_GET_DEPLOYMENT_DETAILS(deployment_id)
 *   DEVOPS_GENERATE_DEPLOYMENT_REPORT(start_date, end_date)
 *   DEVOPS_TEST_CONNECTION()
 *   DEVOPS_LIST_PIPELINE_ACCOUNTS()
 * 
 * CLONE MANAGEMENT:
 *   RBAC_CREATE_CLONE(env, database, schema, clone_type, include_data, suffix)
 *   RBAC_LIST_USER_CLONES(env, username)
 *   RBAC_DELETE_CLONE(clone_identifier, force)
 *   RBAC_REPLACE_CLONE(env, database, schema, clone_type, include_data, replace_oldest, clone_to_replace)
 *   RBAC_GET_CLONE_LIMITS()
 *   RBAC_SET_CLONE_LIMIT(env, max_clones, expiry_days, allow_db, allow_schema)
 *   RBAC_LIST_ALL_CLONES(env, status)
 *   RBAC_CLEANUP_EXPIRED_CLONES(env, dry_run)
 *   RBAC_GET_CLONE_SUMMARY(env)
 * 
 * CLONE AUDIT & COMPLIANCE:
 *   RBAC_LOG_CLONE_OPERATION(operation, clone_id, name, type, env, db, schema, status, error, metadata)
 *   RBAC_LOG_CLONE_ACCESS(clone_id, name, access_type, query_id, rows)
 *   RBAC_CREATE_CLONE_POLICY(name, type, env, description, definition, severity)
 *   RBAC_SETUP_DEFAULT_CLONE_POLICIES()
 *   RBAC_LIST_CLONE_POLICIES(env, type, active_only)
 *   RBAC_SET_POLICY_STATUS(name, is_active)
 *   RBAC_DELETE_CLONE_POLICY(name)
 *   RBAC_CHECK_CLONE_POLICIES(clone_id, name, type, env, db, schema)
 *   RBAC_CHECK_CLONE_COMPLIANCE(env)
 *   RBAC_GET_CLONE_AUDIT_LOG(start, end, operation, user, env, limit)
 *   RBAC_GET_POLICY_VIOLATIONS(status, severity, start, end)
 *   RBAC_RESOLVE_POLICY_VIOLATION(violation_id, notes)
 *   RBAC_GENERATE_CLONE_AUDIT_REPORT(start, end)
 *   RBAC_GET_USER_CLONE_ACTIVITY(username, days_back)
 *   RBAC_PURGE_CLONE_AUDIT_RECORDS(retention_days, dry_run)
 * 
 * CLONE MONITORING:
 *   RBAC_CLONE_USAGE_DASHBOARD()
 *   RBAC_CLONE_STORAGE_DASHBOARD(cost_per_tb)
 *   RBAC_CLONE_COMPLIANCE_DASHBOARD()
 *   RBAC_CLONE_TRENDS_DASHBOARD(days_back)
 *   RBAC_CLONE_MONITORING_DASHBOARD()
 * 
 * SECURITY MONITORING:
 *   RBAC_ROLE_ASSIGNMENT_DASHBOARD()
 *   RBAC_ACCESS_ANOMALY_DASHBOARD(days_back)
 *   RBAC_CONFIG_MISALIGNMENT_DASHBOARD()
 *   RBAC_CREATE_SECURITY_EXCEPTION(type, user, role, env, reason, expires_days, ticket)
 *   RBAC_SECURITY_EXCEPTIONS_DASHBOARD()
 *   RBAC_CREATE_SECURITY_ALERT(type, severity, title, description, user, role, metadata)
 *   RBAC_SECURITY_ALERTS_DASHBOARD()
 *   RBAC_RESOLVE_SECURITY_ALERT(alert_id, action, notes)
 *   RBAC_SECURITY_MONITORING_DASHBOARD()
 *   RBAC_RUN_SECURITY_SCAN()
 * 
 * DEVOPS MONITORING:
 *   RBAC_PIPELINE_STATUS_DASHBOARD()
 *   RBAC_DEPLOYMENT_TRACKING_DASHBOARD(days_back)
 *   RBAC_LOG_RELEASE(version, name, env, database, schema, type, notes, commit, branch, tag)
 *   RBAC_RELEASE_MANAGEMENT_DASHBOARD()
 *   RBAC_GIT_INTEGRATION_DASHBOARD()
 *   RBAC_LOG_CHANGE(type, env, database, schema, object_type, object_name, description, deployment_id, release_id, is_breaking)
 *   RBAC_CHANGE_ANALYTICS_DASHBOARD(days_back)
 *   RBAC_DEPLOYMENT_FAILURE_DASHBOARD(days_back)
 *   RBAC_DEVOPS_MONITORING_DASHBOARD()
 * 
 * ============================================================================
 * 6. SSO/SCIM INTEGRATION
 * ============================================================================
 * 
 * TWO PROVISIONING MODELS:
 * 
 * MODEL A: SCIM + MANUAL RBAC
 *   - SCIM auto-creates users from IdP
 *   - Admin manually assigns roles via RBAC_CONFIGURE_USER
 *   - Best for: Smaller orgs, infrequent role changes
 * 
 *   Setup:
 *     CALL RBAC_SETUP_MODEL_A_BASIC_SCIM('OKTA', 'OKTA_SCIM', NULL);
 *     CALL RBAC_GENERATE_SCIM_TOKEN('OKTA_SCIM');
 *     -- Then: CALL RBAC_CONFIGURE_USER(...) for each user
 * 
 * MODEL B: FULL SCIM AUTOMATION
 *   - SCIM auto-creates users AND assigns roles
 *   - Role assignment via AD group membership
 *   - Best for: Larger orgs, frequent role changes
 * 
 *   Setup:
 *     CALL RBAC_SETUP_MODEL_B_FULL_SCIM('OKTA', 'OKTA_SCIM', NULL);
 *     CALL RBAC_GRANT_ALL_ROLES_TO_SCIM('OKTA', NULL);
 *     CALL RBAC_GENERATE_SCIM_TOKEN('OKTA_SCIM');
 * 
 *   AD Group Naming:
 *     SF_DEV_DEVELOPER     → SRF_DEV_DEVELOPER
 *     SF_DEV_HR_ACCESS     → SRA_DEV_HR_ACCESS
 * 
 * ============================================================================
 * 7. MULTI-ACCOUNT ARCHITECTURE
 * ============================================================================
 * 
 * SCENARIO 1: ENVIRONMENT-BASED ACCOUNTS
 *   Accounts: DEV, TST, UAT, PRD (each has all domains)
 *   Roles: SRF_DEVELOPER, SRA_HR_ACCESS (no env prefix)
 *   Setup: CALL RBAC_INITIAL_CONFIG_MULTI_ACCOUNT('ENVIRONMENT', 'DEV', ...);
 * 
 * SCENARIO 2: DEPARTMENT-BASED ACCOUNTS
 *   Accounts: HR, SALES, FINANCE (each has all environments)
 *   Roles: SRF_DEV_DEVELOPER, SRA_DEV_PAYROLL (no domain prefix)
 *   Setup: CALL RBAC_INITIAL_CONFIG_MULTI_ACCOUNT('DEPARTMENT', 'HR', ...);
 * 
 * SCENARIO 3: HYBRID
 *   Accounts: HR-DEV, HR-PRD, SALES-DEV, SALES-PRD
 *   Roles: SRF_DEVELOPER, SRA_PAYROLL (no prefixes)
 *   Setup: CALL RBAC_INITIAL_CONFIG_MULTI_ACCOUNT('HYBRID', 'HR_DEV', ...);
 * 
 * CROSS-ACCOUNT DATA SHARING:
 *   -- Source account
 *   CALL RBAC_CREATE_OUTBOUND_SHARE('HR_SHARE', 'HR_DB', 
 *        ARRAY_CONSTRUCT('EMPLOYEES'), ARRAY_CONSTRUCT('ORG.FINANCE_ACCT'), NULL);
 *   
 *   -- Consumer account
 *   CALL RBAC_CREATE_SHARED_DATA_ACCESS_ROLE('HR', 'HR_DATA', 'PRD', NULL);
 *   CALL RBAC_MOUNT_INBOUND_SHARE('ORG.HR_ACCT.HR_SHARE', 'HR_SHARED',
 *        'SRA_PRD_SHARED_HR_DATA_ACCESS', NULL);
 * 
 * ============================================================================
 * 8. EXTERNAL INTEGRATIONS
 * ============================================================================
 * 
 * SUPPORTED: ServiceNow, Jira, Generic REST APIs
 * 
 * WORKFLOW:
 *   1. User requests access → Ticket created
 *   2. Manager approves in external system
 *   3. Admin checks approval → Auto-grants access
 * 
 * SETUP (ServiceNow):
 *   CALL RBAC_SETUP_SERVICENOW_ACCESS('mycompany', 'SNOW_CREDS', 
 *        'api_user', 'api_password', 'SNOW_INT');
 *   GRANT USAGE ON INTEGRATION SNOW_INT TO ROLE SRS_SECURITY_ADMIN;
 * 
 * USAGE:
 *   -- Create request
 *   CALL RBAC_REQUEST_ACCESS('user@company.com', 'DEV', 'HR', 'DEVELOPER',
 *        'Business justification...', 'SERVICENOW', NULL);
 *   -- Returns: REQ0012345
 *   
 *   -- After approval, grant
 *   CALL RBAC_CHECK_AND_GRANT_APPROVED('REQ0012345', 'SERVICENOW',
 *        'user@company.com', 'DEV', 'HR', 'DEVELOPER', 'DEV_WH');
 * 
 * ============================================================================
 * 9. DEVOPS & CI/CD
 * ============================================================================
 * 
 * SUPPORTED PLATFORMS:
 *   • Azure DevOps
 *   • GitHub Actions
 *   • GitLab CI/CD
 *   • Any platform supporting Snowflake CLI
 * 
 * PIPELINE SETUP:
 *   -- Generate RSA key pair (outside Snowflake)
 *   openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
 *   openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
 *   
 *   -- Setup pipeline (choose one)
 *   CALL DEVOPS_SETUP_AZURE_DEVOPS('MyProject', 'HR', '<PUBLIC_KEY>', ARRAY_CONSTRUCT('DEV','TST','PRD'));
 *   CALL DEVOPS_SETUP_GITHUB_ACTIONS('my-repo', 'HR', '<PUBLIC_KEY>', ARRAY_CONSTRUCT('DEV','TST','PRD'));
 *   CALL DEVOPS_SETUP_GITLAB('my-project', 'HR', '<PUBLIC_KEY>', ARRAY_CONSTRUCT('DEV','TST','PRD'));
 * 
 * GIT INTEGRATION:
 *   CALL DEVOPS_CREATE_GIT_SECRET('GITHUB_CREDS', 'GITHUB', 'username', 'ghp_token');
 *   CALL DEVOPS_SETUP_GIT_REPOSITORY('MY_REPO', 'https://github.com/org/repo.git', 
 *        'GITHUB', 'GITHUB_CREDS', NULL, 'main');
 *   
 *   -- Execute SQL from Git
 *   EXECUTE IMMEDIATE FROM @MY_REPO/branches/main/deploy.sql;
 *   
 *   -- Or with tracking
 *   CALL DEVOPS_DEPLOY_FROM_GIT('MY_REPO', 'main', 'deploy.sql', 'DEV', 'HR', 'EMPLOYEES');
 * 
 * ENVIRONMENT PROMOTION:
 *   CALL DEVOPS_CLONE_SCHEMA('DEV', 'TST', 'HR', 'EMPLOYEES', FALSE);
 *   CALL DEVOPS_PROMOTE_SCHEMA('DEV', 'TST', 'HR', 'EMPLOYEES', NULL, TRUE);  -- dry run
 * 
 * DEPLOYMENT TRACKING:
 *   CALL DEVOPS_GET_DEPLOYMENT_HISTORY('DEV', NULL, 30, NULL);
 *   CALL DEVOPS_GET_DEPLOYMENT_DETAILS('<deployment_id>');
 *   CALL DEVOPS_GENERATE_DEPLOYMENT_REPORT('2024-01-01', '2024-12-31');
 * 
 * ROLLBACK:
 *   CALL DEVOPS_ROLLBACK_DEPLOYMENT('<deployment_id>', 'TIME_TRAVEL', NULL);
 * 
 * ============================================================================
 * 10. EXTENSIBILITY GUIDE
 * ============================================================================
 * 
 * WHERE TO UPDATE FOR NEW SNOWFLAKE FEATURES:
 * 
 * | Feature Type            | Primary File(s) to Update                      |
 * |-------------------------|------------------------------------------------|
 * | New object type         | RBAC_SP_Create_Schema.sql                      |
 * |                         | RBAC_SP_Monitor_Config.sql                     |
 * |                         | RBAC_SP_Rectify_Config.sql                     |
 * | New account privilege   | RBAC_SP_Initial_Config.sql                     |
 * |                         | RBAC_SP_Multi_Account.sql                      |
 * | New schema privilege    | RBAC_SP_Create_Schema.sql                      |
 * | New policy type         | RBAC_SP_Initial_Config.sql (APPLY privilege)   |
 * | New authentication      | RBAC_SP_Identity_Integration.sql               |
 * | New integration type    | RBAC_SP_Identity_Integration.sql               |
 * | New capability level    | RBAC_SP_Initial_Config.sql                     |
 * | New share/listing type  | RBAC_SP_Multi_Account.sql                      |
 * 
 * UPDATE PROCESS:
 *   1. Monitor Snowflake Release Notes
 *   2. Identify privilege requirements
 *   3. Update procedures
 *   4. Test with dry_run=TRUE
 *   5. Deploy and verify
 * 
 * ============================================================================
 * 11. CODE PROTECTION
 * ============================================================================
 * 
 * All procedures use SECURE keyword:
 *   CREATE OR REPLACE SECURE PROCEDURE ...
 * 
 * PROTECTION LEVELS:
 * 
 * | Method          | Protection | Who Can See Code                    |
 * |-----------------|------------|-------------------------------------|
 * | Direct Deploy   | Medium     | Owner, ACCOUNTADMIN only            |
 * | (SECURE procs)  |            |                                     |
 * | Native App      | High       | Nobody (completely hidden)          |
 * | (Marketplace)   |            |                                     |
 * 
 * For Native App packaging, see: RBAC_Native_App_Manifest.sql
 * 
 ******************************************************************************/

-- This file is for documentation reference only
SELECT 'RBAC Reference Guide - For interactive help, run: CALL RBAC_HELP();' AS INFO;
