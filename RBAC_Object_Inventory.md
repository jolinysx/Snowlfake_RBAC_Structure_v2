# RBAC Framework Object Inventory

## Summary

This inventory lists all CREATE statements across all files, with their proposed:
- **Owner Role** - The role that should execute the CREATE statement
- **Database.Schema** - The fully qualified location
- **Special Notes** - Any exceptions or clarifications needed

---

## LEGEND

| Symbol | Meaning |
|--------|---------|
| ✅ | Confirmed - standard pattern applies |
| ⚠️ | Requires ACCOUNTADMIN (account-level object) |
| ❓ | Needs confirmation |

---

## FILE 1: RBAC_SP_Initial_Config.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_INITIAL_CONFIG | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates account-level roles/objects |

**Note**: This is a bootstrap procedure - it creates the ADMIN database itself, so it must run as ACCOUNTADMIN before the database exists.

---

## FILE 2: RBAC_SP_Help.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_HELP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC.RBAC_HELP | Core help |
| PROCEDURE | RBAC_HELP_SETUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_ROLES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_QUICKSTART | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_PROCEDURES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_SSO | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_DEVOPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_CLONES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_GOVERNANCE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_BACKUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |
| PROCEDURE | RBAC_HELP_HADR | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Alias |

---

## FILE 3: RBAC_SP_Create_Warehouse.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CREATE_WAREHOUSE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Warehouse creation |

---

## FILE 4: RBAC_SP_Create_Schema.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CREATE_SCHEMA | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Schema/DB creation |

---

## FILE 5: RBAC_SP_Access_Role.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CREATE_ACCESS_ROLE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Creates SRA_* roles |
| PROCEDURE | RBAC_LINK_SCHEMA_TO_ACCESS_ROLE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Links schemas |
| PROCEDURE | RBAC_LIST_ACCESS_ROLES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists roles |
| PROCEDURE | RBAC_GRANT_ACCESS_ROLE_TO_USER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Grants to users |

---

## FILE 6: RBAC_SP_Service_Role.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CREATE_SERVICE_ROLE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Creates SRW_* roles |
| PROCEDURE | RBAC_CONFIGURE_SERVICE_ROLE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Config service role |
| PROCEDURE | RBAC_LIST_SERVICE_ROLES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists roles |

---

## FILE 7: RBAC_SP_User_Management.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CREATE_SERVICE_ACCOUNT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Creates service accounts |
| PROCEDURE | RBAC_CONFIGURE_USER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Configures SCIM users |
| PROCEDURE | RBAC_DISABLE_USER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Disables users |
| PROCEDURE | RBAC_LIST_USER_ACCESS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists user access |

---

## FILE 8: RBAC_SP_Audit_Roles.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_AUDIT_USER_ROLES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Audit role assignments |
| PROCEDURE | RBAC_AUDIT_ROLE_HIERARCHY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Audit hierarchy |
| PROCEDURE | RBAC_COMPLIANCE_REPORT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Compliance report |

---

## FILE 9: RBAC_SP_Monitor_Config.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_MONITOR_SCHEMA_CONFIG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Monitor config |
| PROCEDURE | RBAC_MONITOR_ROLE_CONFIG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Monitor roles |
| PROCEDURE | RBAC_CONFIGURATION_DRIFT_REPORT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Drift detection |

---

## FILE 10: RBAC_SP_Rectify_Config.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_RECTIFY_SCHEMA_CONFIG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Fix config |
| PROCEDURE | RBAC_RECTIFY_ROLE_CONFIG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Fix roles |
| PROCEDURE | RBAC_AUTO_RECTIFY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Auto-fix |

---

## FILE 11: RBAC_SP_Identity_Integration.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_SETUP_SCIM_PROVISIONER | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates SCIM integration |
| PROCEDURE | RBAC_SETUP_SAML_SSO | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates SAML integration |
| PROCEDURE | RBAC_SETUP_OKTA_SCIM | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Okta-specific |
| PROCEDURE | RBAC_SETUP_AZURE_AD_SCIM | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Azure AD-specific |

**Note**: These procedures create security integrations which require ACCOUNTADMIN. The procedures themselves could be owned by SRS_SYSTEM_ADMIN but must be executed with ACCOUNTADMIN privileges (EXECUTE AS CALLER).

---

## FILE 12: RBAC_SP_External_Integration.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_SETUP_SERVICENOW_INTEGRATION | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | ServiceNow |
| PROCEDURE | RBAC_SETUP_JIRA_INTEGRATION | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Jira |
| PROCEDURE | RBAC_SETUP_API_INTEGRATION | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates API integration |
| PROCEDURE | RBAC_SETUP_NOTIFICATION_INTEGRATION | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates notification int. |

---

## FILE 13: RBAC_SP_Multi_Account.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_INITIAL_CONFIG_MULTI_ACCOUNT | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Multi-account setup |
| PROCEDURE | RBAC_SETUP_DATA_SHARING | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates shares |
| PROCEDURE | RBAC_LIST_SHARED_DATABASES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists shares |

---

## FILE 14: RBAC_SP_Cost_Management.sql

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | RBAC_COST_CENTERS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Tracking table |
| TABLE | RBAC_WAREHOUSE_COST_MAPPING | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Tracking table |
| TABLE | RBAC_COST_ALERTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Tracking table |
| TABLE | RBAC_COST_SNAPSHOTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Tracking table |
| PROCEDURE | RBAC_CREATE_RESOURCE_MONITOR | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates resource monitors |
| PROCEDURE | RBAC_ASSIGN_RESOURCE_MONITOR | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Assigns monitors |
| PROCEDURE | RBAC_LIST_RESOURCE_MONITORS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists monitors |
| PROCEDURE | RBAC_CREATE_BUDGET | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.RBAC | Creates budgets |
| PROCEDURE | RBAC_LIST_BUDGETS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Lists budgets |
| PROCEDURE | RBAC_CREATE_COST_CENTER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Creates cost center |
| PROCEDURE | RBAC_TAG_WAREHOUSE_COST_CENTER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Tags warehouse |
| PROCEDURE | RBAC_COST_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Dashboard |
| PROCEDURE | RBAC_WAREHOUSE_COST_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Dashboard |
| PROCEDURE | RBAC_COST_ANOMALY_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Dashboard |
| PROCEDURE | RBAC_CHARGEBACK_REPORT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Report |
| PROCEDURE | RBAC_COST_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Dashboard |
| PROCEDURE | RBAC_CREATE_WAREHOUSE_WITH_MONITOR | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Enhanced WH creation |

---

## FILE 15: RBAC_SP_DevOps.sql (Schema: ADMIN.DEVOPS)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | DEVOPS_DEPLOYMENTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| TABLE | DEVOPS_DEPLOYMENT_OBJECTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| TABLE | DEVOPS_GIT_REPOSITORIES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| PROCEDURE | DEVOPS_CREATE_PIPELINE_SERVICE_ACCOUNT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Pipeline SA |
| PROCEDURE | DEVOPS_SETUP_AZURE_DEVOPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Azure setup |
| PROCEDURE | DEVOPS_SETUP_GITHUB_ACTIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | GitHub setup |
| PROCEDURE | DEVOPS_SETUP_GITLAB | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | GitLab setup |
| PROCEDURE | DEVOPS_START_DEPLOYMENT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Start deploy |
| PROCEDURE | DEVOPS_LOG_DEPLOYMENT_OBJECT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Log object |
| PROCEDURE | DEVOPS_COMPLETE_DEPLOYMENT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Complete deploy |
| PROCEDURE | DEVOPS_ROLLBACK_DEPLOYMENT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Rollback |
| PROCEDURE | DEVOPS_PROMOTE_TO_ENVIRONMENT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Promote |
| PROCEDURE | DEVOPS_REGISTER_GIT_REPOSITORY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Git repo |
| PROCEDURE | DEVOPS_SYNC_GIT_REPOSITORY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Git sync |

---

## FILE 16: RBAC_SP_DevOps_Monitoring.sql (Schema: ADMIN.DEVOPS)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | DEVOPS_PIPELINE_STATUS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| TABLE | DEVOPS_RELEASES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| TABLE | DEVOPS_CHANGE_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Tracking table |
| PROCEDURE | RBAC_PIPELINE_STATUS_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Dashboard |
| PROCEDURE | RBAC_DEPLOYMENT_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Dashboard |
| PROCEDURE | RBAC_RELEASE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Dashboard |
| PROCEDURE | DEVOPS_DEPLOYMENT_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.DEVOPS | Dashboard |

---

## FILE 17: RBAC_SP_Clone_Management.sql (Schema: ADMIN.CLONES)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | RBAC_CLONE_LIMITS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Config table |
| TABLE | RBAC_CLONE_REGISTRY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Tracking table |
| INDEX | IDX_CLONE_REGISTRY_USER | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Index |
| PROCEDURE | RBAC_GET_CLONE_LIMITS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | View limits |
| PROCEDURE | RBAC_SET_CLONE_LIMIT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Set limits |
| PROCEDURE | RBAC_CREATE_CLONE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Create clone |
| PROCEDURE | RBAC_LIST_USER_CLONES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | List clones |
| PROCEDURE | RBAC_DELETE_CLONE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Delete clone |
| PROCEDURE | RBAC_REPLACE_CLONE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Replace clone |
| PROCEDURE | RBAC_LIST_ALL_CLONES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Admin list |
| PROCEDURE | RBAC_CLEANUP_EXPIRED_CLONES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Cleanup |
| PROCEDURE | RBAC_SETUP_DEFAULT_CLONE_POLICIES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Setup defaults |

---

## FILE 18: RBAC_SP_Clone_Audit.sql (Schema: ADMIN.CLONES)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | RBAC_CLONE_AUDIT_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Audit table |
| TABLE | RBAC_CLONE_POLICIES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Policies table |
| TABLE | RBAC_CLONE_POLICY_VIOLATIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Violations |
| TABLE | RBAC_CLONE_ACCESS_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Access log |
| PROCEDURE | RBAC_LOG_CLONE_OPERATION | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Log operation |
| PROCEDURE | RBAC_CREATE_CLONE_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Create policy |
| PROCEDURE | RBAC_CHECK_CLONE_COMPLIANCE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Check compliance |
| PROCEDURE | RBAC_CLONE_AUDIT_REPORT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Audit report |
| PROCEDURE | RBAC_CLONE_COMPLIANCE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Dashboard |

---

## FILE 19: RBAC_SP_Clone_Monitoring.sql (Schema: ADMIN.CLONES)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_CLONE_USAGE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Dashboard |
| PROCEDURE | RBAC_CLONE_STORAGE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Dashboard |
| PROCEDURE | RBAC_CLONE_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.CLONES | Dashboard |

---

## FILE 20: RBAC_SP_Security_Monitoring.sql (Schema: ADMIN.SECURITY)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | RBAC_SECURITY_EXCEPTIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Exceptions |
| TABLE | RBAC_SECURITY_ALERTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Alerts |
| TABLE | RBAC_CONFIG_SNAPSHOTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Snapshots |
| PROCEDURE | RBAC_ROLE_ASSIGNMENT_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Dashboard |
| PROCEDURE | RBAC_ACCESS_ANOMALY_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Dashboard |
| PROCEDURE | RBAC_SECURITY_POSTURE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Dashboard |
| PROCEDURE | RBAC_CREATE_SECURITY_EXCEPTION | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Create exception |
| PROCEDURE | RBAC_RUN_SECURITY_SCAN | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Run scan |
| PROCEDURE | RBAC_SECURITY_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Dashboard |

---

## FILE 21: RBAC_SP_Data_Governance.sql (Schema: ADMIN.GOVERNANCE)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | GOVERNANCE_POLICY_REGISTRY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Registry |
| TABLE | GOVERNANCE_POLICY_APPLICATIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Applications |
| TABLE | GOVERNANCE_DATA_CLASSIFICATIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Classifications |
| TABLE | GOVERNANCE_TAGS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Tags |
| TABLE | GOVERNANCE_TAG_APPLICATIONS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Tag apps |
| TABLE | GOVERNANCE_AUDIT_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Audit log |
| PROCEDURE | RBAC_CREATE_ROW_ACCESS_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Create RLS |
| PROCEDURE | RBAC_APPLY_ROW_ACCESS_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Apply RLS |
| PROCEDURE | RBAC_CREATE_MASKING_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Create masking |
| PROCEDURE | RBAC_APPLY_MASKING_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Apply masking |
| PROCEDURE | RBAC_SETUP_STANDARD_MASKING_POLICIES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Standard masks |
| PROCEDURE | RBAC_CLASSIFY_COLUMN | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Classify |
| PROCEDURE | RBAC_AUTO_CLASSIFY_TABLE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Auto-classify |
| PROCEDURE | RBAC_CREATE_GOVERNANCE_TAG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Create tag |
| PROCEDURE | RBAC_APPLY_TAG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Apply tag |
| PROCEDURE | RBAC_SETUP_STANDARD_GOVERNANCE_TAGS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Standard tags |
| PROCEDURE | RBAC_APPLY_MASKING_TO_CLASSIFIED | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Bulk apply |

---

## FILE 22: RBAC_SP_Governance_Monitoring.sql (Schema: ADMIN.GOVERNANCE)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_POLICY_COVERAGE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Dashboard |
| PROCEDURE | RBAC_CLASSIFICATION_STATUS_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Dashboard |
| PROCEDURE | RBAC_GOVERNANCE_COMPLIANCE_SCORECARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Scorecard |
| PROCEDURE | RBAC_SENSITIVE_DATA_MAP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Data map |
| PROCEDURE | RBAC_SCAN_UNPROTECTED_DATA | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Scan |
| PROCEDURE | RBAC_GOVERNANCE_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.GOVERNANCE | Dashboard |

---

## FILE 23: RBAC_SP_Backup_Management.sql (Schema: ADMIN.BACKUP)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | BACKUP_POLICIES | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Policies |
| TABLE | BACKUP_CATALOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Catalog |
| TABLE | BACKUP_JOBS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Jobs |
| TABLE | BACKUP_RESTORE_HISTORY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | History |
| TABLE | BACKUP_AUDIT_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Audit log |
| PROCEDURE | RBAC_CREATE_BACKUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Create backup |
| PROCEDURE | RBAC_CREATE_BACKUP_POLICY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Create policy |
| PROCEDURE | RBAC_SETUP_BACKUP_SCHEDULE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Setup schedule |
| PROCEDURE | RBAC_TOGGLE_BACKUP_SCHEDULE | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Toggle schedule |
| PROCEDURE | RBAC_RESTORE_FROM_BACKUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Restore |
| PROCEDURE | RBAC_RESTORE_TIME_TRAVEL | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Time travel |
| PROCEDURE | RBAC_LIST_BACKUPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | List backups |
| PROCEDURE | RBAC_DELETE_BACKUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Delete backup |
| PROCEDURE | RBAC_CLEANUP_EXPIRED_BACKUPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Cleanup |
| PROCEDURE | RBAC_SETUP_RETENTION_CLEANUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Retention |
| PROCEDURE | RBAC_QUICK_BACKUP | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Quick backup |

---

## FILE 24: RBAC_SP_Backup_Monitoring.sql (Schema: ADMIN.BACKUP)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_BACKUP_STATUS_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Dashboard |
| PROCEDURE | RBAC_BACKUP_STORAGE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Dashboard |
| PROCEDURE | RBAC_BACKUP_COMPLIANCE_REPORT | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Report |
| PROCEDURE | RBAC_BACKUP_HEALTH_CHECK | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Health check |
| PROCEDURE | RBAC_TIME_TRAVEL_COVERAGE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Dashboard |
| PROCEDURE | RBAC_BACKUP_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.BACKUP | Dashboard |

---

## FILE 25: RBAC_SP_HADR_Management.sql (Schema: ADMIN.HADR)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | HADR_REPLICATION_GROUPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Groups |
| TABLE | HADR_FAILOVER_GROUPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Failover groups |
| TABLE | HADR_REPLICATION_HISTORY | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | History |
| TABLE | HADR_FAILOVER_EVENTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Events |
| TABLE | HADR_DR_TESTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | DR tests |
| TABLE | HADR_AUDIT_LOG | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Audit log |
| PROCEDURE | RBAC_CREATE_REPLICATION_GROUP | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.HADR | Creates replication |
| PROCEDURE | RBAC_SETUP_DATABASE_REPLICATION | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.HADR | DB replication |
| PROCEDURE | RBAC_REFRESH_REPLICATION | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Refresh |
| PROCEDURE | RBAC_INITIATE_FAILOVER | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.HADR | Failover |
| PROCEDURE | RBAC_INITIATE_FAILBACK | No qualifier | ⚠️ ACCOUNTADMIN | ADMIN.HADR | Failback |
| PROCEDURE | RBAC_SCHEDULE_DR_TEST | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Schedule test |
| PROCEDURE | RBAC_EXECUTE_DR_TEST | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Execute test |
| PROCEDURE | RBAC_LIST_DR_TESTS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | List tests |
| PROCEDURE | RBAC_CHECK_REPLICATION_STATUS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Check status |
| PROCEDURE | RBAC_GENERATE_DR_RUNBOOK | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Generate runbook |
| PROCEDURE | RBAC_LIST_FAILOVER_GROUPS | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | List groups |

---

## FILE 26: RBAC_SP_HADR_Monitoring.sql (Schema: ADMIN.HADR)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_REPLICATION_HEALTH_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Dashboard |
| PROCEDURE | RBAC_FAILOVER_READINESS_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Dashboard |
| PROCEDURE | RBAC_RTORPO_COMPLIANCE_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Dashboard |
| PROCEDURE | RBAC_DR_TEST_RESULTS_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Dashboard |
| PROCEDURE | RBAC_HADR_MONITORING_DASHBOARD | No qualifier | ✅ SRS_SYSTEM_ADMIN | ADMIN.HADR | Dashboard |

---

## SUMMARY BY SCHEMA

| Schema | Tables | Procedures | Index | Total |
|--------|--------|------------|-------|-------|
| ADMIN.RBAC | 4 | ~55 | 0 | ~59 |
| ADMIN.DEVOPS | 6 | ~15 | 0 | ~21 |
| ADMIN.CLONES | 5 | ~15 | 1 | ~21 |
| ADMIN.SECURITY | 8 | ~30 | 0 | ~38 |
| ADMIN.GOVERNANCE | 6 | ~20 | 0 | ~26 |
| ADMIN.BACKUP | 5 | ~20 | 0 | ~25 |
| ADMIN.HADR | 6 | ~20 | 0 | ~26 |
| **TOTAL** | **40** | **~175** | **1** | **~216** |

---

## FILE 23: RBAC_SP_Policy_Management.sql (NEW)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| TABLE | POLICY_REGISTRY | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Policy tracking |
| TABLE | POLICY_ASSIGNMENTS | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Assignment tracking |
| TABLE | POLICY_TEMPLATES | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Policy templates |
| TABLE | POLICY_AUDIT_LOG | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Audit trail |
| TABLE | POLICY_EXCEPTIONS | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Exception tracking |
| PROCEDURE | POLICY_CREATE_NETWORK_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Creates network policies |
| PROCEDURE | POLICY_MODIFY_NETWORK_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Modifies network policies |
| PROCEDURE | POLICY_ASSIGN_NETWORK_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Assigns to account/user |
| PROCEDURE | POLICY_CREATE_PASSWORD_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Creates password policies |
| PROCEDURE | POLICY_ASSIGN_PASSWORD_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Assigns to account/user |
| PROCEDURE | POLICY_CREATE_SESSION_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Creates session policies |
| PROCEDURE | POLICY_ASSIGN_SESSION_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Assigns to account/user |
| PROCEDURE | POLICY_CREATE_AUTHENTICATION_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Creates auth policies |
| PROCEDURE | POLICY_ASSIGN_AUTHENTICATION_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Assigns to account/user |
| PROCEDURE | POLICY_SETUP_TEMPLATES | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Creates standard templates |
| PROCEDURE | POLICY_CREATE_FROM_TEMPLATE | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Creates from template |
| PROCEDURE | POLICY_LIST_POLICIES | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Lists policies |
| PROCEDURE | POLICY_LIST_ASSIGNMENTS | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Lists assignments |
| PROCEDURE | POLICY_AUDIT_REPORT | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Audit reporting |
| PROCEDURE | POLICY_COMPLIANCE_DASHBOARD | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Compliance overview |
| PROCEDURE | POLICY_MONITORING_DASHBOARD | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Master dashboard |
| PROCEDURE | POLICY_CREATE_EXCEPTION | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Create exception request |
| PROCEDURE | POLICY_APPROVE_EXCEPTION | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.SECURITY | Approve exception |
| PROCEDURE | POLICY_DROP_POLICY | New | ⚠️ ACCOUNTADMIN | ADMIN.SECURITY | Drop policy |

---

## FILE 24: RBAC_SP_Validate_Deployment.sql (NEW)

| Object Type | Object Name | Current State | Proposed Role | Proposed Location | Notes |
|-------------|-------------|---------------|---------------|-------------------|-------|
| PROCEDURE | RBAC_GET_EXPECTED_OBJECTS | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Expected objects config |
| PROCEDURE | RBAC_VALIDATE_SECTION | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Validate single section |
| PROCEDURE | RBAC_VALIDATE_DEPLOYMENT | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Main validation (modular) |
| PROCEDURE | RBAC_DEPLOYMENT_STATUS | New | ✅ SRS_SYSTEM_ADMIN | ADMIN.RBAC | Quick status table |

**Note**: Deploy this file LAST after all other RBAC files. Supports modular validation:
- `CALL RBAC_VALIDATE_DEPLOYMENT()` - Validate all sections
- `CALL RBAC_VALIDATE_DEPLOYMENT('RBAC')` - Validate RBAC only
- `CALL RBAC_VALIDATE_DEPLOYMENT('ROLES')` - Validate roles only

---

## OBJECTS REQUIRING ACCOUNTADMIN

These objects require ACCOUNTADMIN due to their nature:

| File | Object | Reason |
|------|--------|--------|
| RBAC_SP_Initial_Config | RBAC_INITIAL_CONFIG | Creates account-level roles |
| RBAC_SP_Identity_Integration | RBAC_SETUP_SCIM_PROVISIONER | Creates security integrations |
| RBAC_SP_Identity_Integration | RBAC_SETUP_SAML_SSO | Creates security integrations |
| RBAC_SP_Identity_Integration | RBAC_SETUP_OKTA_SCIM | Creates security integrations |
| RBAC_SP_Identity_Integration | RBAC_SETUP_AZURE_AD_SCIM | Creates security integrations |
| RBAC_SP_External_Integration | RBAC_SETUP_API_INTEGRATION | Creates API integrations |
| RBAC_SP_External_Integration | RBAC_SETUP_NOTIFICATION_INTEGRATION | Creates notification integrations |
| RBAC_SP_Multi_Account | RBAC_INITIAL_CONFIG_MULTI_ACCOUNT | Creates account-level roles |
| RBAC_SP_Multi_Account | RBAC_SETUP_DATA_SHARING | Creates shares |
| RBAC_SP_Cost_Management | RBAC_CREATE_RESOURCE_MONITOR | Creates resource monitors |
| RBAC_SP_Cost_Management | RBAC_ASSIGN_RESOURCE_MONITOR | Modifies resource monitors |
| RBAC_SP_Cost_Management | RBAC_CREATE_BUDGET | Creates budgets |
| RBAC_SP_HADR_Management | RBAC_CREATE_REPLICATION_GROUP | Creates replication groups |
| RBAC_SP_HADR_Management | RBAC_SETUP_DATABASE_REPLICATION | Sets up replication |
| RBAC_SP_HADR_Management | RBAC_INITIATE_FAILOVER | Initiates failover |
| RBAC_SP_HADR_Management | RBAC_INITIATE_FAILBACK | Initiates failback |
| RBAC_SP_Policy_Management | POLICY_CREATE_NETWORK_POLICY | Creates network policies |
| RBAC_SP_Policy_Management | POLICY_MODIFY_NETWORK_POLICY | Modifies network policies |
| RBAC_SP_Policy_Management | POLICY_ASSIGN_NETWORK_POLICY | Assigns policies to account/user |
| RBAC_SP_Policy_Management | POLICY_CREATE_PASSWORD_POLICY | Creates password policies |
| RBAC_SP_Policy_Management | POLICY_ASSIGN_PASSWORD_POLICY | Assigns policies to account/user |
| RBAC_SP_Policy_Management | POLICY_CREATE_SESSION_POLICY | Creates session policies |
| RBAC_SP_Policy_Management | POLICY_ASSIGN_SESSION_POLICY | Assigns policies to account/user |
| RBAC_SP_Policy_Management | POLICY_CREATE_AUTHENTICATION_POLICY | Creates auth policies |
| RBAC_SP_Policy_Management | POLICY_ASSIGN_AUTHENTICATION_POLICY | Assigns policies to account/user |
| RBAC_SP_Policy_Management | POLICY_CREATE_FROM_TEMPLATE | Creates policies from templates |
| RBAC_SP_Policy_Management | POLICY_DROP_POLICY | Drops policies |

---

## QUESTIONS FOR CONFIRMATION

1. **Bootstrap Procedure**: `RBAC_INITIAL_CONFIG` must be deployed before the ADMIN database exists. Should this remain outside the standard pattern?

2. **ACCOUNTADMIN Procedures**: For procedures that require ACCOUNTADMIN to execute, should:
   - Option A: The procedure be owned by SRS_SYSTEM_ADMIN with EXECUTE AS CALLER (requires ACCOUNTADMIN to call)
   - Option B: The procedure be owned by ACCOUNTADMIN

3. **Tables vs Procedures**: Should tracking tables be created:
   - Option A: In the same file as their related procedures
   - Option B: In a separate schema setup file run before procedures

Please confirm the above and any adjustments needed before I proceed with updating all files.
