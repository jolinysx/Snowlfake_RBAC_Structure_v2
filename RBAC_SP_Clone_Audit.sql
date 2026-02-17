/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Audit & Compliance
 * 
 * Purpose: Track clone operations, enforce compliance policies, and provide
 *          audit reporting for clone management activities
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          CLONES
 *   Object Type:     TABLES (4), PROCEDURES (~8)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and CLONES schema must exist
 *     - RBAC_SP_Clone_Management.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * AUDIT CAPABILITIES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Full audit trail of all clone operations (create, delete, access)
 *   • Compliance policy definition and enforcement
 *   • Usage pattern analysis and reporting
 *   • Policy violation detection and alerting
 *   • Retention compliance tracking
 * 
 * COMPLIANCE POLICIES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Maximum clone age policies
 *   • Data classification restrictions
 *   • Environment-specific rules
 *   • User quota enforcement
 *   • Sensitive data clone restrictions
 * 
 * INTEGRATION:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Works alongside RBAC_SP_Clone_Management.sql to provide comprehensive
 *   clone governance and compliance monitoring.
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA CLONES;

-- #############################################################################
-- SECTION 1: AUDIT TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    OPERATION VARCHAR(50) NOT NULL,
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    CLONE_TYPE VARCHAR(20),
    ENVIRONMENT VARCHAR(10),
    SOURCE_DATABASE VARCHAR(255),
    SOURCE_SCHEMA VARCHAR(255),
    PERFORMED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    PERFORMED_BY_ROLE VARCHAR(255) DEFAULT CURRENT_ROLE(),
    SESSION_ID VARCHAR(100) DEFAULT CURRENT_SESSION(),
    CLIENT_IP VARCHAR(50),
    STATUS VARCHAR(20),
    ERROR_MESSAGE TEXT,
    METADATA VARIANT,
    POLICY_VIOLATIONS ARRAY
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_POLICIES (
    POLICY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_NAME VARCHAR(255) NOT NULL UNIQUE,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    ENVIRONMENT VARCHAR(10),
    DESCRIPTION TEXT,
    POLICY_DEFINITION VARIANT NOT NULL,
    SEVERITY VARCHAR(20) DEFAULT 'WARNING',
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(255),
    UPDATED_AT TIMESTAMP_NTZ
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_POLICY_VIOLATIONS (
    VIOLATION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    POLICY_ID VARCHAR(36) NOT NULL,
    POLICY_NAME VARCHAR(255),
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    VIOLATED_BY VARCHAR(255),
    VIOLATION_DETAILS VARIANT,
    SEVERITY VARCHAR(20),
    STATUS VARCHAR(20) DEFAULT 'OPEN',
    RESOLVED_BY VARCHAR(255),
    RESOLVED_AT TIMESTAMP_NTZ,
    RESOLUTION_NOTES TEXT,
    FOREIGN KEY (POLICY_ID) REFERENCES RBAC_CLONE_POLICIES(POLICY_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.CLONES.RBAC_CLONE_ACCESS_LOG (
    ACCESS_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    CLONE_ID VARCHAR(36),
    CLONE_NAME VARCHAR(500),
    ACCESSED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    ACCESS_TYPE VARCHAR(50),
    QUERY_ID VARCHAR(100),
    ROWS_ACCESSED INTEGER,
    SESSION_ID VARCHAR(100) DEFAULT CURRENT_SESSION()
);

-- Index for efficient querying
CREATE INDEX IF NOT EXISTS IDX_CLONE_AUDIT_TIMESTAMP 
ON RBAC_CLONE_AUDIT_LOG (TIMESTAMP DESC);

CREATE INDEX IF NOT EXISTS IDX_CLONE_AUDIT_USER 
ON RBAC_CLONE_AUDIT_LOG (PERFORMED_BY, TIMESTAMP DESC);

CREATE INDEX IF NOT EXISTS IDX_POLICY_VIOLATIONS_STATUS 
ON RBAC_CLONE_POLICY_VIOLATIONS (STATUS, TIMESTAMP DESC);

-- #############################################################################
-- SECTION 2: AUDIT LOGGING PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Clone Operation
 * 
 * Purpose: Records clone operations to the audit log
 *          Called internally by clone management procedures
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_OPERATION(
    P_OPERATION VARCHAR,
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_CLONE_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR,
    P_STATUS VARCHAR,
    P_ERROR_MESSAGE TEXT DEFAULT NULL,
    P_METADATA VARIANT DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_audit_id VARCHAR;
    v_policy_violations ARRAY := ARRAY_CONSTRUCT();
    v_violation VARIANT;
BEGIN
    v_audit_id := UUID_STRING();
    
    -- Check for policy violations if this is a CREATE operation
    IF P_OPERATION = 'CREATE' AND P_STATUS = 'SUCCESS' THEN
        CALL RBAC_CHECK_CLONE_POLICIES(
            P_CLONE_ID, P_CLONE_NAME, P_CLONE_TYPE, 
            P_ENVIRONMENT, P_SOURCE_DATABASE, P_SOURCE_SCHEMA
        ) INTO v_violation;
        
        IF v_violation:violations IS NOT NULL THEN
            v_policy_violations := v_violation:violations;
        END IF;
    END IF;
    
    -- Insert audit record
    INSERT INTO RBAC_CLONE_AUDIT_LOG (
        AUDIT_ID, OPERATION, CLONE_ID, CLONE_NAME, CLONE_TYPE,
        ENVIRONMENT, SOURCE_DATABASE, SOURCE_SCHEMA, STATUS,
        ERROR_MESSAGE, METADATA, POLICY_VIOLATIONS
    ) VALUES (
        v_audit_id, P_OPERATION, P_CLONE_ID, P_CLONE_NAME, P_CLONE_TYPE,
        P_ENVIRONMENT, P_SOURCE_DATABASE, P_SOURCE_SCHEMA, P_STATUS,
        P_ERROR_MESSAGE, P_METADATA, v_policy_violations
    );
    
    RETURN v_audit_id;

EXCEPTION
    WHEN OTHER THEN
        -- Don't fail the main operation if audit fails
        RETURN NULL;
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Clone Access
 * 
 * Purpose: Records when users access clone data
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_LOG_CLONE_ACCESS(
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_ACCESS_TYPE VARCHAR,
    P_QUERY_ID VARCHAR DEFAULT NULL,
    P_ROWS_ACCESSED INTEGER DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_access_id VARCHAR;
BEGIN
    v_access_id := UUID_STRING();
    
    INSERT INTO RBAC_CLONE_ACCESS_LOG (
        ACCESS_ID, CLONE_ID, CLONE_NAME, ACCESS_TYPE, QUERY_ID, ROWS_ACCESSED
    ) VALUES (
        v_access_id, P_CLONE_ID, P_CLONE_NAME, P_ACCESS_TYPE, P_QUERY_ID, P_ROWS_ACCESSED
    );
    
    RETURN v_access_id;

EXCEPTION
    WHEN OTHER THEN
        RETURN NULL;
END;
$$;

-- #############################################################################
-- SECTION 3: COMPLIANCE POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Clone Policy
 * 
 * Purpose: Creates a compliance policy for clone management
 * 
 * Policy Types:
 *   - MAX_AGE: Maximum age for clones
 *   - RESTRICTED_SOURCE: Sources that cannot be cloned
 *   - DATA_CLASSIFICATION: Restrict cloning based on data classification
 *   - USER_QUOTA: Additional quota restrictions
 *   - ENVIRONMENT_RESTRICTION: Environment-specific rules
 *   - TIME_RESTRICTION: Time-based restrictions
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE_POLICY(
    P_POLICY_NAME VARCHAR,
    P_POLICY_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_DESCRIPTION TEXT DEFAULT NULL,
    P_POLICY_DEFINITION VARIANT,
    P_SEVERITY VARCHAR DEFAULT 'WARNING'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy_id VARCHAR;
BEGIN
    -- Validate policy type
    IF P_POLICY_TYPE NOT IN ('MAX_AGE', 'RESTRICTED_SOURCE', 'DATA_CLASSIFICATION', 
                              'USER_QUOTA', 'ENVIRONMENT_RESTRICTION', 'TIME_RESTRICTION',
                              'SENSITIVE_DATA', 'APPROVAL_REQUIRED') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid policy type. Valid types: MAX_AGE, RESTRICTED_SOURCE, DATA_CLASSIFICATION, USER_QUOTA, ENVIRONMENT_RESTRICTION, TIME_RESTRICTION, SENSITIVE_DATA, APPROVAL_REQUIRED'
        );
    END IF;
    
    -- Validate severity
    IF P_SEVERITY NOT IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid severity. Valid values: INFO, WARNING, ERROR, CRITICAL'
        );
    END IF;
    
    v_policy_id := UUID_STRING();
    
    INSERT INTO RBAC_CLONE_POLICIES (
        POLICY_ID, POLICY_NAME, POLICY_TYPE, ENVIRONMENT,
        DESCRIPTION, POLICY_DEFINITION, SEVERITY
    ) VALUES (
        v_policy_id, P_POLICY_NAME, P_POLICY_TYPE, P_ENVIRONMENT,
        P_DESCRIPTION, P_POLICY_DEFINITION, P_SEVERITY
    );
    
    -- Log the policy creation
    CALL RBAC_LOG_CLONE_OPERATION(
        'POLICY_CREATE', v_policy_id, P_POLICY_NAME, 'POLICY',
        P_ENVIRONMENT, NULL, NULL, 'SUCCESS', NULL,
        OBJECT_CONSTRUCT('policy_type', P_POLICY_TYPE, 'severity', P_SEVERITY)
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_id', v_policy_id,
        'policy_name', P_POLICY_NAME,
        'policy_type', P_POLICY_TYPE,
        'message', 'Policy created successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Default Policies
 * 
 * Purpose: Creates a set of recommended default compliance policies
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SETUP_DEFAULT_CLONE_POLICIES()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policies_created ARRAY := ARRAY_CONSTRUCT();
    v_result VARIANT;
BEGIN
    -- Policy 1: Maximum clone age for PRD environment
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'PRD_MAX_CLONE_AGE_7_DAYS',
            'MAX_AGE',
            'PRD',
            'Production clones must not exceed 7 days to minimize data exposure risk',
            OBJECT_CONSTRUCT('max_age_days', 7, 'action', 'WARN_AND_LOG'),
            'WARNING'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 2: Maximum clone age for UAT
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'UAT_MAX_CLONE_AGE_14_DAYS',
            'MAX_AGE',
            'UAT',
            'UAT clones must not exceed 14 days',
            OBJECT_CONSTRUCT('max_age_days', 14, 'action', 'WARN_AND_LOG'),
            'WARNING'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 3: Restrict cloning of PII schemas
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'RESTRICT_PII_SCHEMA_CLONES',
            'SENSITIVE_DATA',
            NULL,
            'Schemas containing PII data require approval before cloning',
            OBJECT_CONSTRUCT(
                'restricted_schemas', ARRAY_CONSTRUCT('PII', 'SENSITIVE', 'CONFIDENTIAL', 'PHI', 'PCI'),
                'action', 'REQUIRE_APPROVAL',
                'approvers', ARRAY_CONSTRUCT('SRS_SECURITY_ADMIN', 'SRS_ACCOUNT_ADMIN')
            ),
            'CRITICAL'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 4: No PRD database clones
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'NO_PRD_DATABASE_CLONES',
            'ENVIRONMENT_RESTRICTION',
            'PRD',
            'Database-level clones are not permitted in production',
            OBJECT_CONSTRUCT('restricted_clone_types', ARRAY_CONSTRUCT('DATABASE'), 'action', 'BLOCK'),
            'ERROR'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 5: Business hours only for PRD
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'PRD_BUSINESS_HOURS_ONLY',
            'TIME_RESTRICTION',
            'PRD',
            'Production clones can only be created during business hours (8 AM - 6 PM)',
            OBJECT_CONSTRUCT(
                'allowed_hours_start', 8,
                'allowed_hours_end', 18,
                'allowed_days', ARRAY_CONSTRUCT('MON', 'TUE', 'WED', 'THU', 'FRI'),
                'timezone', 'America/New_York',
                'action', 'BLOCK'
            ),
            'ERROR'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 6: Maximum total clones per user across all environments
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'MAX_TOTAL_USER_CLONES_10',
            'USER_QUOTA',
            NULL,
            'Users cannot have more than 10 total active clones across all environments',
            OBJECT_CONSTRUCT('max_total_clones', 10, 'action', 'BLOCK'),
            'ERROR'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    -- Policy 7: Audit trail retention
    BEGIN
        CALL RBAC_CREATE_CLONE_POLICY(
            'AUDIT_RETENTION_365_DAYS',
            'DATA_CLASSIFICATION',
            NULL,
            'Clone audit records must be retained for 365 days for compliance',
            OBJECT_CONSTRUCT('retention_days', 365, 'applies_to', 'AUDIT_LOG'),
            'INFO'
        ) INTO v_result;
        IF v_result:status = 'SUCCESS' THEN
            v_policies_created := ARRAY_APPEND(v_policies_created, v_result:policy_name);
        END IF;
    EXCEPTION WHEN OTHER THEN NULL;
    END;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policies_created', v_policies_created,
        'count', ARRAY_SIZE(v_policies_created),
        'message', 'Default policies have been created'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Clone Policies
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_LIST_CLONE_POLICIES(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_POLICY_TYPE VARCHAR DEFAULT NULL,
    P_ACTIVE_ONLY BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    POLICY_ID VARCHAR,
    POLICY_NAME VARCHAR,
    POLICY_TYPE VARCHAR,
    ENVIRONMENT VARCHAR,
    SEVERITY VARCHAR,
    IS_ACTIVE BOOLEAN,
    DESCRIPTION TEXT,
    CREATED_AT TIMESTAMP_NTZ
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            POLICY_ID,
            POLICY_NAME,
            POLICY_TYPE,
            ENVIRONMENT,
            SEVERITY,
            IS_ACTIVE,
            DESCRIPTION,
            CREATED_AT
        FROM RBAC_CLONE_POLICIES
        WHERE (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT OR ENVIRONMENT IS NULL)
          AND (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
          AND (NOT P_ACTIVE_ONLY OR IS_ACTIVE = TRUE)
        ORDER BY SEVERITY DESC, POLICY_NAME
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Enable/Disable Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_SET_POLICY_STATUS(
    P_POLICY_NAME VARCHAR,
    P_IS_ACTIVE BOOLEAN
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    UPDATE RBAC_CLONE_POLICIES
    SET IS_ACTIVE = P_IS_ACTIVE,
        UPDATED_BY = CURRENT_USER(),
        UPDATED_AT = CURRENT_TIMESTAMP()
    WHERE POLICY_NAME = P_POLICY_NAME;
    
    IF (SELECT COUNT(*) FROM RBAC_CLONE_POLICIES WHERE POLICY_NAME = P_POLICY_NAME) = 0 THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Policy not found');
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'is_active', P_IS_ACTIVE,
        'message', 'Policy status updated'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Delete Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_DELETE_CLONE_POLICY(
    P_POLICY_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy_id VARCHAR;
BEGIN
    SELECT POLICY_ID INTO v_policy_id
    FROM RBAC_CLONE_POLICIES
    WHERE POLICY_NAME = P_POLICY_NAME;
    
    IF v_policy_id IS NULL THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Policy not found');
    END IF;
    
    DELETE FROM RBAC_CLONE_POLICIES WHERE POLICY_NAME = P_POLICY_NAME;
    
    -- Log deletion
    CALL RBAC_LOG_CLONE_OPERATION(
        'POLICY_DELETE', v_policy_id, P_POLICY_NAME, 'POLICY',
        NULL, NULL, NULL, 'SUCCESS', NULL, NULL
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'message', 'Policy deleted'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: POLICY ENFORCEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Clone Policies
 * 
 * Purpose: Evaluates all active policies against a clone operation
 *          Returns any violations found
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_CHECK_CLONE_POLICIES(
    P_CLONE_ID VARCHAR,
    P_CLONE_NAME VARCHAR,
    P_CLONE_TYPE VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_violations ARRAY := ARRAY_CONSTRUCT();
    v_current_user VARCHAR := CURRENT_USER();
    v_total_user_clones INTEGER;
    v_current_hour INTEGER;
    v_current_day VARCHAR;
    v_policy OBJECT;
    v_definition VARIANT;
    v_violation OBJECT;
    v_should_block BOOLEAN := FALSE;
BEGIN
    -- Get current time info
    v_current_hour := HOUR(CURRENT_TIMESTAMP());
    v_current_day := DAYNAME(CURRENT_DATE());
    
    -- Get total user clones
    SELECT COUNT(*) INTO v_total_user_clones
    FROM RBAC_CLONE_REGISTRY
    WHERE CREATED_BY = v_current_user AND STATUS = 'ACTIVE';
    
    -- Check each active policy
    FOR policy_rec IN (
        SELECT POLICY_ID, POLICY_NAME, POLICY_TYPE, ENVIRONMENT, POLICY_DEFINITION, SEVERITY
        FROM RBAC_CLONE_POLICIES
        WHERE IS_ACTIVE = TRUE
          AND (ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
    ) DO
        v_definition := policy_rec.POLICY_DEFINITION;
        v_violation := NULL;
        
        -- Check policy based on type
        CASE policy_rec.POLICY_TYPE
            
            -- Environment restriction
            WHEN 'ENVIRONMENT_RESTRICTION' THEN
                IF ARRAY_CONTAINS(P_CLONE_TYPE::VARIANT, v_definition:restricted_clone_types) THEN
                    v_violation := OBJECT_CONSTRUCT(
                        'policy_name', policy_rec.POLICY_NAME,
                        'policy_type', policy_rec.POLICY_TYPE,
                        'severity', policy_rec.SEVERITY,
                        'message', P_CLONE_TYPE || ' clones are not allowed in ' || P_ENVIRONMENT,
                        'action', v_definition:action
                    );
                    IF v_definition:action = 'BLOCK' THEN
                        v_should_block := TRUE;
                    END IF;
                END IF;
            
            -- User quota
            WHEN 'USER_QUOTA' THEN
                IF v_total_user_clones >= v_definition:max_total_clones::INTEGER THEN
                    v_violation := OBJECT_CONSTRUCT(
                        'policy_name', policy_rec.POLICY_NAME,
                        'policy_type', policy_rec.POLICY_TYPE,
                        'severity', policy_rec.SEVERITY,
                        'message', 'Total clone limit exceeded. You have ' || v_total_user_clones || ' clones (max: ' || v_definition:max_total_clones || ')',
                        'action', v_definition:action
                    );
                    IF v_definition:action = 'BLOCK' THEN
                        v_should_block := TRUE;
                    END IF;
                END IF;
            
            -- Time restriction
            WHEN 'TIME_RESTRICTION' THEN
                IF v_current_hour < v_definition:allowed_hours_start::INTEGER 
                   OR v_current_hour >= v_definition:allowed_hours_end::INTEGER
                   OR NOT ARRAY_CONTAINS(v_current_day::VARIANT, v_definition:allowed_days) THEN
                    v_violation := OBJECT_CONSTRUCT(
                        'policy_name', policy_rec.POLICY_NAME,
                        'policy_type', policy_rec.POLICY_TYPE,
                        'severity', policy_rec.SEVERITY,
                        'message', 'Clone creation not allowed at this time. Allowed: ' || 
                                   v_definition:allowed_hours_start || ':00 - ' || 
                                   v_definition:allowed_hours_end || ':00 on ' ||
                                   ARRAY_TO_STRING(v_definition:allowed_days, ', '),
                        'action', v_definition:action
                    );
                    IF v_definition:action = 'BLOCK' THEN
                        v_should_block := TRUE;
                    END IF;
                END IF;
            
            -- Sensitive data
            WHEN 'SENSITIVE_DATA' THEN
                IF P_SOURCE_SCHEMA IS NOT NULL THEN
                    FOR i IN 0 TO ARRAY_SIZE(v_definition:restricted_schemas) - 1 DO
                        IF CONTAINS(UPPER(P_SOURCE_SCHEMA), v_definition:restricted_schemas[i]::VARCHAR) THEN
                            v_violation := OBJECT_CONSTRUCT(
                                'policy_name', policy_rec.POLICY_NAME,
                                'policy_type', policy_rec.POLICY_TYPE,
                                'severity', policy_rec.SEVERITY,
                                'message', 'Schema contains sensitive data and requires approval',
                                'action', v_definition:action,
                                'approvers', v_definition:approvers
                            );
                            IF v_definition:action = 'BLOCK' OR v_definition:action = 'REQUIRE_APPROVAL' THEN
                                v_should_block := TRUE;
                            END IF;
                        END IF;
                    END FOR;
                END IF;
            
            ELSE
                NULL;
        END CASE;
        
        -- Record violation if found
        IF v_violation IS NOT NULL THEN
            v_violations := ARRAY_APPEND(v_violations, v_violation);
            
            -- Log the violation
            INSERT INTO RBAC_CLONE_POLICY_VIOLATIONS (
                POLICY_ID, POLICY_NAME, CLONE_ID, CLONE_NAME,
                VIOLATED_BY, VIOLATION_DETAILS, SEVERITY
            ) VALUES (
                policy_rec.POLICY_ID, policy_rec.POLICY_NAME, P_CLONE_ID, P_CLONE_NAME,
                v_current_user, v_violation, policy_rec.SEVERITY
            );
        END IF;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'has_violations', ARRAY_SIZE(v_violations) > 0,
        'should_block', v_should_block,
        'violations_count', ARRAY_SIZE(v_violations),
        'violations', v_violations
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('has_violations', FALSE, 'error', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Clone Compliance
 * 
 * Purpose: Checks all existing clones for policy compliance
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_COMPLIANCE(
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_violations ARRAY := ARRAY_CONSTRUCT();
    v_compliant_count INTEGER := 0;
    v_non_compliant_count INTEGER := 0;
    v_clone OBJECT;
    v_age_days INTEGER;
    v_max_age INTEGER;
BEGIN
    -- Check each active clone
    FOR clone_rec IN (
        SELECT 
            c.CLONE_ID, c.CLONE_NAME, c.CLONE_TYPE, c.ENVIRONMENT,
            c.SOURCE_DATABASE, c.SOURCE_SCHEMA, c.CREATED_BY, c.CREATED_AT,
            DATEDIFF(DAY, c.CREATED_AT, CURRENT_TIMESTAMP()) AS AGE_DAYS
        FROM RBAC_CLONE_REGISTRY c
        WHERE c.STATUS = 'ACTIVE'
          AND (P_ENVIRONMENT IS NULL OR c.ENVIRONMENT = P_ENVIRONMENT)
    ) DO
        v_age_days := clone_rec.AGE_DAYS;
        
        -- Check MAX_AGE policies
        FOR policy_rec IN (
            SELECT POLICY_NAME, POLICY_DEFINITION, SEVERITY
            FROM RBAC_CLONE_POLICIES
            WHERE IS_ACTIVE = TRUE
              AND POLICY_TYPE = 'MAX_AGE'
              AND (ENVIRONMENT IS NULL OR ENVIRONMENT = clone_rec.ENVIRONMENT)
        ) DO
            v_max_age := policy_rec.POLICY_DEFINITION:max_age_days::INTEGER;
            
            IF v_age_days > v_max_age THEN
                v_violations := ARRAY_APPEND(v_violations, OBJECT_CONSTRUCT(
                    'clone_name', clone_rec.CLONE_NAME,
                    'clone_owner', clone_rec.CREATED_BY,
                    'policy_name', policy_rec.POLICY_NAME,
                    'violation', 'Clone age (' || v_age_days || ' days) exceeds maximum (' || v_max_age || ' days)',
                    'severity', policy_rec.SEVERITY,
                    'environment', clone_rec.ENVIRONMENT
                ));
                v_non_compliant_count := v_non_compliant_count + 1;
            ELSE
                v_compliant_count := v_compliant_count + 1;
            END IF;
        END FOR;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'compliant_clones', v_compliant_count,
        'non_compliant_clones', v_non_compliant_count,
        'violations', v_violations,
        'scan_timestamp', CURRENT_TIMESTAMP()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: AUDIT REPORTING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Clone Audit Log
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_AUDIT_LOG(
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL,
    P_OPERATION VARCHAR DEFAULT NULL,
    P_USER VARCHAR DEFAULT NULL,
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_LIMIT INTEGER DEFAULT 1000
)
RETURNS TABLE (
    AUDIT_ID VARCHAR,
    TIMESTAMP TIMESTAMP_NTZ,
    OPERATION VARCHAR,
    CLONE_NAME VARCHAR,
    ENVIRONMENT VARCHAR,
    PERFORMED_BY VARCHAR,
    STATUS VARCHAR,
    POLICY_VIOLATIONS INTEGER
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_start TIMESTAMP_NTZ;
    v_end TIMESTAMP_NTZ;
    res RESULTSET;
BEGIN
    v_start := COALESCE(P_START_DATE::TIMESTAMP_NTZ, DATEADD(DAY, -30, CURRENT_TIMESTAMP()));
    v_end := COALESCE(P_END_DATE::TIMESTAMP_NTZ, CURRENT_TIMESTAMP());
    
    res := (
        SELECT 
            AUDIT_ID,
            TIMESTAMP,
            OPERATION,
            CLONE_NAME,
            ENVIRONMENT,
            PERFORMED_BY,
            STATUS,
            ARRAY_SIZE(COALESCE(POLICY_VIOLATIONS, ARRAY_CONSTRUCT())) AS POLICY_VIOLATIONS
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP BETWEEN v_start AND v_end
          AND (P_OPERATION IS NULL OR OPERATION = P_OPERATION)
          AND (P_USER IS NULL OR PERFORMED_BY = P_USER)
          AND (P_ENVIRONMENT IS NULL OR ENVIRONMENT = P_ENVIRONMENT)
        ORDER BY TIMESTAMP DESC
        LIMIT P_LIMIT
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get Policy Violations Report
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GET_POLICY_VIOLATIONS(
    P_STATUS VARCHAR DEFAULT 'OPEN',
    P_SEVERITY VARCHAR DEFAULT NULL,
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL
)
RETURNS TABLE (
    VIOLATION_ID VARCHAR,
    TIMESTAMP TIMESTAMP_NTZ,
    POLICY_NAME VARCHAR,
    CLONE_NAME VARCHAR,
    VIOLATED_BY VARCHAR,
    SEVERITY VARCHAR,
    STATUS VARCHAR,
    RESOLUTION_NOTES TEXT
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_start TIMESTAMP_NTZ;
    v_end TIMESTAMP_NTZ;
    res RESULTSET;
BEGIN
    v_start := COALESCE(P_START_DATE::TIMESTAMP_NTZ, DATEADD(DAY, -90, CURRENT_TIMESTAMP()));
    v_end := COALESCE(P_END_DATE::TIMESTAMP_NTZ, CURRENT_TIMESTAMP());
    
    res := (
        SELECT 
            VIOLATION_ID,
            TIMESTAMP,
            POLICY_NAME,
            CLONE_NAME,
            VIOLATED_BY,
            SEVERITY,
            STATUS,
            RESOLUTION_NOTES
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE TIMESTAMP BETWEEN v_start AND v_end
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
          AND (P_SEVERITY IS NULL OR SEVERITY = P_SEVERITY)
        ORDER BY 
            CASE SEVERITY WHEN 'CRITICAL' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'WARNING' THEN 3 ELSE 4 END,
            TIMESTAMP DESC
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Resolve Policy Violation
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_RESOLVE_POLICY_VIOLATION(
    P_VIOLATION_ID VARCHAR,
    P_RESOLUTION_NOTES TEXT
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    UPDATE RBAC_CLONE_POLICY_VIOLATIONS
    SET STATUS = 'RESOLVED',
        RESOLVED_BY = CURRENT_USER(),
        RESOLVED_AT = CURRENT_TIMESTAMP(),
        RESOLUTION_NOTES = P_RESOLUTION_NOTES
    WHERE VIOLATION_ID = P_VIOLATION_ID;
    
    IF (SELECT COUNT(*) FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE VIOLATION_ID = P_VIOLATION_ID) = 0 THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Violation not found');
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'violation_id', P_VIOLATION_ID,
        'resolved_by', CURRENT_USER(),
        'message', 'Violation marked as resolved'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate Clone Audit Report
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GENERATE_CLONE_AUDIT_REPORT(
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_start DATE;
    v_end DATE;
    v_summary VARIANT;
    v_by_operation VARIANT;
    v_by_user VARIANT;
    v_by_environment VARIANT;
    v_policy_violations VARIANT;
    v_top_clone_creators VARIANT;
BEGIN
    v_start := COALESCE(P_START_DATE, DATEADD(DAY, -30, CURRENT_DATE()));
    v_end := COALESCE(P_END_DATE, CURRENT_DATE());
    
    -- Summary statistics
    SELECT OBJECT_CONSTRUCT(
        'total_operations', COUNT(*),
        'successful', COUNT_IF(STATUS = 'SUCCESS'),
        'failed', COUNT_IF(STATUS != 'SUCCESS'),
        'creates', COUNT_IF(OPERATION = 'CREATE'),
        'deletes', COUNT_IF(OPERATION = 'DELETE'),
        'unique_users', COUNT(DISTINCT PERFORMED_BY)
    ) INTO v_summary
    FROM RBAC_CLONE_AUDIT_LOG
    WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end;
    
    -- By operation
    SELECT OBJECT_AGG(OPERATION, CNT) INTO v_by_operation
    FROM (
        SELECT OPERATION, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY OPERATION
    );
    
    -- By user (top 10)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('user', PERFORMED_BY, 'operations', CNT)) INTO v_by_user
    FROM (
        SELECT PERFORMED_BY, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY PERFORMED_BY
        ORDER BY CNT DESC
        LIMIT 10
    );
    
    -- By environment
    SELECT OBJECT_AGG(COALESCE(ENVIRONMENT, 'N/A'), CNT) INTO v_by_environment
    FROM (
        SELECT ENVIRONMENT, COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY ENVIRONMENT
    );
    
    -- Policy violations summary
    SELECT OBJECT_CONSTRUCT(
        'total_violations', COUNT(*),
        'open', COUNT_IF(STATUS = 'OPEN'),
        'resolved', COUNT_IF(STATUS = 'RESOLVED'),
        'critical', COUNT_IF(SEVERITY = 'CRITICAL'),
        'error', COUNT_IF(SEVERITY = 'ERROR'),
        'warning', COUNT_IF(SEVERITY = 'WARNING')
    ) INTO v_policy_violations
    FROM RBAC_CLONE_POLICY_VIOLATIONS
    WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end;
    
    RETURN OBJECT_CONSTRUCT(
        'report_period', OBJECT_CONSTRUCT('start', v_start, 'end', v_end),
        'summary', v_summary,
        'by_operation', v_by_operation,
        'top_users', v_by_user,
        'by_environment', v_by_environment,
        'policy_violations', v_policy_violations,
        'generated_at', CURRENT_TIMESTAMP(),
        'generated_by', CURRENT_USER()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Get User Clone Activity
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(
    P_USERNAME VARCHAR DEFAULT NULL,
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_user VARCHAR;
    v_activity VARIANT;
    v_current_clones ARRAY;
    v_recent_operations ARRAY;
    v_violations ARRAY;
BEGIN
    v_user := COALESCE(P_USERNAME, CURRENT_USER());
    
    -- Current active clones
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'clone_name', CLONE_NAME,
        'environment', ENVIRONMENT,
        'created_at', CREATED_AT,
        'age_days', DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP())
    )) INTO v_current_clones
    FROM RBAC_CLONE_REGISTRY
    WHERE CREATED_BY = v_user AND STATUS = 'ACTIVE';
    
    -- Recent operations
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'operation', OPERATION,
        'clone_name', CLONE_NAME,
        'timestamp', TIMESTAMP,
        'status', STATUS
    )) INTO v_recent_operations
    FROM RBAC_CLONE_AUDIT_LOG
    WHERE PERFORMED_BY = v_user
      AND TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
    ORDER BY TIMESTAMP DESC
    LIMIT 50;
    
    -- Policy violations
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_name', POLICY_NAME,
        'timestamp', TIMESTAMP,
        'severity', SEVERITY,
        'status', STATUS
    )) INTO v_violations
    FROM RBAC_CLONE_POLICY_VIOLATIONS
    WHERE VIOLATED_BY = v_user
      AND TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP());
    
    RETURN OBJECT_CONSTRUCT(
        'user', v_user,
        'active_clones', COALESCE(v_current_clones, ARRAY_CONSTRUCT()),
        'active_clone_count', ARRAY_SIZE(COALESCE(v_current_clones, ARRAY_CONSTRUCT())),
        'recent_operations', COALESCE(v_recent_operations, ARRAY_CONSTRUCT()),
        'policy_violations', COALESCE(v_violations, ARRAY_CONSTRUCT()),
        'days_analyzed', P_DAYS_BACK
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: MAINTENANCE & CLEANUP
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Purge Old Audit Records
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_PURGE_CLONE_AUDIT_RECORDS(
    P_RETENTION_DAYS INTEGER DEFAULT 365,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_cutoff_date TIMESTAMP_NTZ;
    v_audit_count INTEGER;
    v_violation_count INTEGER;
    v_access_count INTEGER;
BEGIN
    v_cutoff_date := DATEADD(DAY, -P_RETENTION_DAYS, CURRENT_TIMESTAMP());
    
    -- Count records to be purged
    SELECT COUNT(*) INTO v_audit_count
    FROM RBAC_CLONE_AUDIT_LOG
    WHERE TIMESTAMP < v_cutoff_date;
    
    SELECT COUNT(*) INTO v_violation_count
    FROM RBAC_CLONE_POLICY_VIOLATIONS
    WHERE TIMESTAMP < v_cutoff_date AND STATUS = 'RESOLVED';
    
    SELECT COUNT(*) INTO v_access_count
    FROM RBAC_CLONE_ACCESS_LOG
    WHERE TIMESTAMP < v_cutoff_date;
    
    IF NOT P_DRY_RUN THEN
        DELETE FROM RBAC_CLONE_AUDIT_LOG WHERE TIMESTAMP < v_cutoff_date;
        DELETE FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE TIMESTAMP < v_cutoff_date AND STATUS = 'RESOLVED';
        DELETE FROM RBAC_CLONE_ACCESS_LOG WHERE TIMESTAMP < v_cutoff_date;
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'retention_days', P_RETENTION_DAYS,
        'cutoff_date', v_cutoff_date,
        'records_affected', OBJECT_CONSTRUCT(
            'audit_log', v_audit_count,
            'violations', v_violation_count,
            'access_log', v_access_count,
            'total', v_audit_count + v_violation_count + v_access_count
        ),
        'message', IFF(P_DRY_RUN, 
            'Dry run complete. Set P_DRY_RUN=FALSE to purge records.',
            'Audit records older than ' || P_RETENTION_DAYS || ' days have been purged.'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 7: GRANT PERMISSIONS
-- #############################################################################

-- Audit logging (internal use)
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_LOG_CLONE_OPERATION(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT, VARIANT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_LOG_CLONE_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SYSTEM_ADMIN;

-- Policy management (admin only)
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CREATE_CLONE_POLICY(VARCHAR, VARCHAR, VARCHAR, TEXT, VARIANT, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_DEFAULT_CLONE_POLICIES() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_LIST_CLONE_POLICIES(VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_SET_POLICY_STATUS(VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_DELETE_CLONE_POLICY(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- Policy enforcement
GRANT USAGE ON PROCEDURE RBAC_CHECK_CLONE_POLICIES(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CHECK_CLONE_COMPLIANCE(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- Audit reporting
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_GET_CLONE_AUDIT_LOG(DATE, DATE, VARCHAR, VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GET_POLICY_VIOLATIONS(VARCHAR, VARCHAR, DATE, DATE) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_RESOLVE_POLICY_VIOLATION(VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GENERATE_CLONE_AUDIT_REPORT(DATE, DATE) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;

-- Allow users to see their own activity
GRANT USAGE ON PROCEDURE RBAC_GET_USER_CLONE_ACTIVITY(VARCHAR, INTEGER) TO ROLE PUBLIC;

-- Maintenance
GRANT USAGE ON PROCEDURE RBAC_PURGE_CLONE_AUDIT_RECORDS(INTEGER, BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
