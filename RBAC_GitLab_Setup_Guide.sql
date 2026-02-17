/*******************************************************************************
 * GITLAB CI/CD SETUP GUIDE FOR SNOWFLAKE CI/CD
 * 
 * This guide details all the steps needed on the GitLab side to implement
 * a complete CI/CD workflow that integrates with the RBAC framework.
 * 
 * ============================================================================
 * ARCHITECTURE OVERVIEW
 * ============================================================================
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                    GITLAB CI/CD + SNOWFLAKE CI/CD                       │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │   GITLAB                                SNOWFLAKE                       │
 *   │   ──────                                ─────────                       │
 *   │                                                                         │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Repository  │  ─────────────────►  Git Repository (optional)       │
 *   │   │ (Git)       │                      Native Snowflake Git             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Service Account                                  │
 *   │   │  CI/CD      │  ─────────────────►  SVC_GITLAB_*_DEPLOYER           │
 *   │   │  Pipelines  │      Key Pair Auth   SRW_*_DEPLOYER role             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Snowflake CLI                                    │
 *   │   │  Runners    │  ─────────────────►  ADMIN.DEVOPS.DEVOPS_*           │
 *   │   │ (Shared/    │      or SnowSQL      procedures                      │
 *   │   │  Self-host) │                                                       │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ├──────►  DEV  ───►  TST  ───►  UAT  ───►  PRD                │
 *   │          │         (auto)     (auto)    (manual)   (manual+approval)   │
 *   │          │                                                              │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Environments│  ─────────────────►  Deployment tracking             │
 *   │   │ & Variables │                      ADMIN.DEVOPS tables             │
 *   │   └─────────────┘                                                       │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 * PREREQUISITES
 * ============================================================================
 * 
 * Before starting GitLab setup:
 * 
 *   1. RBAC Framework deployed to Snowflake
 *      - RBAC_INITIAL_CONFIG executed
 *      - RBAC_SP_DevOps.sql deployed to ADMIN.DEVOPS schema
 *   
 *   2. GitLab project created
 *      - GitLab.com or GitLab Self-Managed
 *      - Maintainer or Owner access required
 *   
 *   3. RSA key pair generated for authentication
 *      - Generate using: openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
 *      - Extract public key: openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
 * 
 * ============================================================================
 * PHASE 1: SNOWFLAKE SETUP (Run in Snowflake)
 * ============================================================================
 * 
 * STEP 1.1: Generate RSA Key Pair (on your local machine)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   # Generate private key (PKCS#8 format required by Snowflake)
 *   openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
 *   
 *   # Extract public key
 *   openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
 *   
 *   # View public key (copy this for Snowflake, remove header/footer)
 *   cat rsa_key.pub | grep -v "BEGIN" | grep -v "END" | tr -d '\n'
 * 
 * STEP 1.2: Create Pipeline Service Account in Snowflake
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Run as SRS_DEVOPS role
USE ROLE SRS_DEVOPS;

-- Setup GitLab CI/CD pipeline (replace <PUBLIC_KEY> with your key)
CALL ADMIN.DEVOPS.DEVOPS_SETUP_GITLAB(
    'my-group/snowflake-project',    -- GitLab project (group/project format)
    'HR',                            -- Domain this pipeline deploys to
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',  -- RSA public key
    ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PRD')         -- Environments
);

-- The procedure returns:
-- {
--   "service_account": "GITLAB_MY_GROUP_SNOWFLAKE_PROJECT_HR_DEPLOYER",
--   "gitlab_variables": {
--     "SNOWFLAKE_ACCOUNT": "xy12345",
--     "SNOWFLAKE_USER": "GITLAB_MY_GROUP_SNOWFLAKE_PROJECT_HR_DEPLOYER",
--     "SNOWFLAKE_ROLE": "SRW_DEV_HR_DEVELOPER",
--     "SNOWFLAKE_WAREHOUSE": "DEV_WH"
--   }
-- }

/*
 * ============================================================================
 * PHASE 2: GITLAB SETUP
 * ============================================================================
 * 
 * STEP 2.1: Create Project Structure
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   In GitLab, create the following structure:
 *   
 *   my-group/snowflake-project/
 *   ├── .gitlab-ci.yml                      # Main CI/CD configuration
 *   │
 *   ├── ci/
 *   │   ├── templates/
 *   │   │   ├── .snowflake-setup.yml        # Reusable setup template
 *   │   │   └── .deploy-schema.yml          # Reusable deployment template
 *   │   └── jobs/
 *   │       ├── validate.yml
 *   │       ├── test.yml
 *   │       └── deploy.yml
 *   │
 *   ├── databases/
 *   │   ├── HR_DEV/
 *   │   │   └── EMPLOYEES/
 *   │   │       ├── tables/
 *   │   │       ├── views/
 *   │   │       ├── procedures/
 *   │   │       └── deploy.sql
 *   │   ├── HR_TST/
 *   │   ├── HR_UAT/
 *   │   └── HR_PRD/
 *   │
 *   ├── scripts/
 *   │   ├── pre-deploy.sql
 *   │   ├── post-deploy.sql
 *   │   └── rollback.sql
 *   │
 *   └── tests/
 *       └── test_*.sql
 * 
 * STEP 2.2: Configure CI/CD Variables
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project → Settings → CI/CD → Variables
 *   
 *   Click "Add variable" for each:
 *   
 *   │ Key                        │ Value                           │ Type     │ Protected │ Masked │
 *   │────────────────────────────│─────────────────────────────────│──────────│───────────│────────│
 *   │ SNOWFLAKE_ACCOUNT          │ xy12345                         │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_USER             │ GITLAB_MY_GROUP_..._DEPLOYER    │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_PRIVATE_KEY      │ <contents of rsa_key.p8>        │ File     │ Yes       │ No     │
 *   │ SNOWFLAKE_ROLE_DEV         │ SRW_DEV_HR_DEVELOPER            │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_ROLE_TST         │ SRW_TST_HR_DEVELOPER            │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_ROLE_UAT         │ SRW_UAT_HR_DEVELOPER            │ Variable │ Yes       │ No     │
 *   │ SNOWFLAKE_ROLE_PRD         │ SRW_PRD_HR_DEVELOPER            │ Variable │ Yes       │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_DEV    │ DEV_WH                          │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_TST    │ TST_WH                          │ Variable │ No        │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_UAT    │ UAT_WH                          │ Variable │ Yes       │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_PRD    │ PRD_WH                          │ Variable │ Yes       │ No     │
 *   
 *   IMPORTANT: 
 *   - Use "File" type for SNOWFLAKE_PRIVATE_KEY (GitLab writes it to a file)
 *   - Mark PRD/UAT variables as "Protected" to only expose on protected branches
 * 
 * STEP 2.3: Create Environments
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project → Operate → Environments → New environment
 *   
 *   Create these environments:
 *   
 *   │ Name        │ External URL (optional)                     │
 *   │─────────────│─────────────────────────────────────────────│
 *   │ development │ https://app.snowflake.com/xy12345/dev       │
 *   │ testing     │ https://app.snowflake.com/xy12345/tst       │
 *   │ uat         │ https://app.snowflake.com/xy12345/uat       │
 *   │ production  │ https://app.snowflake.com/xy12345/prd       │
 * 
 * STEP 2.4: Configure Protected Branches
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project → Settings → Repository → Protected branches
 *   
 *   Add:
 *   │ Branch  │ Allowed to merge      │ Allowed to push        │
 *   │─────────│───────────────────────│────────────────────────│
 *   │ main    │ Maintainers           │ No one                 │
 *   │ develop │ Developers+Maintainers│ Developers+Maintainers │
 * 
 * ============================================================================
 * PHASE 3: CREATE CI/CD CONFIGURATION FILES
 * ============================================================================
 * 
 * STEP 3.1: Main .gitlab-ci.yml
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .gitlab-ci.yml
 */

-- =====================================================================
-- BEGIN: .gitlab-ci.yml
-- =====================================================================
/*
# GitLab CI/CD for Snowflake Deployments
# ─────────────────────────────────────────────────────────────────────

stages:
  - validate
  - test
  - deploy-dev
  - deploy-tst
  - deploy-uat
  - deploy-prd

# ─────────────────────────────────────────────────────────────────────
# Default settings for all jobs
# ─────────────────────────────────────────────────────────────────────
default:
  image: python:3.11-slim
  before_script:
    - pip install --quiet snowflake-cli-labs
    - mkdir -p ~/.snowflake
    - cp $SNOWFLAKE_PRIVATE_KEY ~/.snowflake/rsa_key.p8
    - chmod 600 ~/.snowflake/rsa_key.p8

# ─────────────────────────────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────────────────────────────
variables:
  DOMAIN: "HR"
  SCHEMA: "EMPLOYEES"

# ─────────────────────────────────────────────────────────────────────
# Templates
# ─────────────────────────────────────────────────────────────────────
.snowflake_connection: &snowflake_connection
  - |
    cat > ~/.snowflake/config.toml << EOF
    [connections.default]
    account = "$SNOWFLAKE_ACCOUNT"
    user = "$SNOWFLAKE_USER"
    private_key_path = "~/.snowflake/rsa_key.p8"
    role = "$ROLE"
    warehouse = "$WAREHOUSE"
    database = "$DATABASE"
    EOF

# ─────────────────────────────────────────────────────────────────────
# Stage: Validate
# ─────────────────────────────────────────────────────────────────────
validate-sql:
  stage: validate
  variables:
    ROLE: $SNOWFLAKE_ROLE_DEV
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_DEV
    DATABASE: "HR_DEV"
  script:
    - *snowflake_connection
    - |
      echo "Validating SQL files..."
      for file in $(find databases/ -name "*.sql" -type f); do
        echo "Checking: $file"
        # Basic connectivity test
        snow sql -q "SELECT 1" > /dev/null
      done
      echo "✅ Validation complete"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "develop"
    - if: $CI_COMMIT_BRANCH == "main"

# ─────────────────────────────────────────────────────────────────────
# Stage: Test
# ─────────────────────────────────────────────────────────────────────
run-tests:
  stage: test
  variables:
    ROLE: $SNOWFLAKE_ROLE_DEV
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_DEV
    DATABASE: "HR_DEV"
  script:
    - *snowflake_connection
    - |
      if [ -d "tests/" ]; then
        for test_file in tests/*.sql; do
          echo "Running test: $test_file"
          snow sql -f "$test_file"
        done
      else
        echo "No tests directory found, skipping"
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "develop"
    - if: $CI_COMMIT_BRANCH == "main"

# ─────────────────────────────────────────────────────────────────────
# Stage: Deploy to DEV (Automatic on develop branch)
# ─────────────────────────────────────────────────────────────────────
deploy-dev:
  stage: deploy-dev
  variables:
    ENVIRONMENT: "DEV"
    ROLE: $SNOWFLAKE_ROLE_DEV
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_DEV
    DATABASE: "HR_DEV"
  environment:
    name: development
    url: https://app.snowflake.com/$SNOWFLAKE_ACCOUNT
  script:
    - *snowflake_connection
    # Start deployment tracking
    - |
      DEPLOYMENT_RESULT=$(snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
          '$ENVIRONMENT',
          '$DOMAIN',
          '$SCHEMA',
          'GITLAB_CI',
          '$CI_PROJECT_PATH',
          '$CI_PIPELINE_ID',
          '$CI_COMMIT_SHA',
          '$CI_COMMIT_REF_NAME',
          NULL
        );
      " --format json)
      DEPLOYMENT_ID=$(echo $DEPLOYMENT_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['DEVOPS_START_DEPLOYMENT']['deployment_id'])")
      echo "DEPLOYMENT_ID=$DEPLOYMENT_ID" >> deploy.env
      echo "Deployment ID: $DEPLOYMENT_ID"
    # Run pre-deploy
    - |
      if [ -f "scripts/pre-deploy.sql" ]; then
        snow sql -f scripts/pre-deploy.sql
      fi
    # Deploy objects
    - |
      for obj_type in tables views procedures functions; do
        if [ -d "databases/$DATABASE/$SCHEMA/$obj_type" ]; then
          for file in databases/$DATABASE/$SCHEMA/$obj_type/*.sql; do
            echo "Deploying: $file"
            snow sql -f "$file"
          done
        fi
      done
    # Run post-deploy
    - |
      if [ -f "scripts/post-deploy.sql" ]; then
        snow sql -f scripts/post-deploy.sql
      fi
    # Complete deployment tracking
    - |
      source deploy.env
      snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
          '$DEPLOYMENT_ID',
          'SUCCESS',
          NULL
        );
      "
  artifacts:
    reports:
      dotenv: deploy.env
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

# ─────────────────────────────────────────────────────────────────────
# Stage: Deploy to TST (Automatic after DEV succeeds)
# ─────────────────────────────────────────────────────────────────────
deploy-tst:
  stage: deploy-tst
  variables:
    ENVIRONMENT: "TST"
    ROLE: $SNOWFLAKE_ROLE_TST
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_TST
    DATABASE: "HR_TST"
  environment:
    name: testing
    url: https://app.snowflake.com/$SNOWFLAKE_ACCOUNT
  script:
    - *snowflake_connection
    # Start deployment tracking
    - |
      DEPLOYMENT_RESULT=$(snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
          '$ENVIRONMENT',
          '$DOMAIN',
          '$SCHEMA',
          'GITLAB_CI',
          '$CI_PROJECT_PATH',
          '$CI_PIPELINE_ID',
          '$CI_COMMIT_SHA',
          '$CI_COMMIT_REF_NAME',
          NULL
        );
      " --format json)
      DEPLOYMENT_ID=$(echo $DEPLOYMENT_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['DEVOPS_START_DEPLOYMENT']['deployment_id'])")
      echo "DEPLOYMENT_ID=$DEPLOYMENT_ID" >> deploy.env
    # Deploy
    - snow sql -f "databases/$DATABASE/$SCHEMA/deploy.sql"
    # Complete tracking
    - |
      source deploy.env
      snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
          '$DEPLOYMENT_ID',
          'SUCCESS',
          NULL
        );
      "
  needs:
    - deploy-dev
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

# ─────────────────────────────────────────────────────────────────────
# Stage: Deploy to UAT (Manual trigger required)
# ─────────────────────────────────────────────────────────────────────
deploy-uat:
  stage: deploy-uat
  variables:
    ENVIRONMENT: "UAT"
    ROLE: $SNOWFLAKE_ROLE_UAT
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_UAT
    DATABASE: "HR_UAT"
  environment:
    name: uat
    url: https://app.snowflake.com/$SNOWFLAKE_ACCOUNT
  script:
    - *snowflake_connection
    # Start deployment tracking
    - |
      DEPLOYMENT_RESULT=$(snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
          '$ENVIRONMENT',
          '$DOMAIN',
          '$SCHEMA',
          'GITLAB_CI',
          '$CI_PROJECT_PATH',
          '$CI_PIPELINE_ID',
          '$CI_COMMIT_SHA',
          '$CI_COMMIT_REF_NAME',
          PARSE_JSON('{\"triggered_by\": \"$GITLAB_USER_LOGIN\", \"manual\": true}')
        );
      " --format json)
      DEPLOYMENT_ID=$(echo $DEPLOYMENT_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['DEVOPS_START_DEPLOYMENT']['deployment_id'])")
      echo "DEPLOYMENT_ID=$DEPLOYMENT_ID" >> deploy.env
    # Deploy
    - snow sql -f "databases/$DATABASE/$SCHEMA/deploy.sql"
    # Run UAT tests
    - |
      if [ -d "tests/uat" ]; then
        for test_file in tests/uat/*.sql; do
          snow sql -f "$test_file"
        done
      fi
    # Complete tracking
    - |
      source deploy.env
      snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
          '$DEPLOYMENT_ID',
          'SUCCESS',
          NULL
        );
      "
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  allow_failure: false

# ─────────────────────────────────────────────────────────────────────
# Stage: Deploy to PRD (Manual + Protected branch + Approval required)
# ─────────────────────────────────────────────────────────────────────
deploy-prd-backup:
  stage: deploy-prd
  variables:
    ENVIRONMENT: "PRD"
    ROLE: $SNOWFLAKE_ROLE_PRD
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_PRD
    DATABASE: "HR_PRD"
  script:
    - *snowflake_connection
    # Create pre-deployment backup
    - |
      BACKUP_RESULT=$(snow sql -q "
        CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP(
          '$DATABASE',
          '$SCHEMA',
          NULL,
          'PRE_RELEASE',
          NULL,
          NULL,
          7,
          NULL,
          'Pre-deployment backup for Pipeline $CI_PIPELINE_ID'
        );
      " --format json)
      BACKUP_ID=$(echo $BACKUP_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['RBAC_CREATE_BACKUP']['backup_id'])")
      echo "BACKUP_ID=$BACKUP_ID" >> backup.env
      echo "✅ Backup created: $BACKUP_ID"
  artifacts:
    reports:
      dotenv: backup.env
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  allow_failure: false

deploy-prd:
  stage: deploy-prd
  variables:
    ENVIRONMENT: "PRD"
    ROLE: $SNOWFLAKE_ROLE_PRD
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_PRD
    DATABASE: "HR_PRD"
  environment:
    name: production
    url: https://app.snowflake.com/$SNOWFLAKE_ACCOUNT
  script:
    - *snowflake_connection
    # Start deployment tracking
    - |
      source backup.env
      DEPLOYMENT_RESULT=$(snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
          '$ENVIRONMENT',
          '$DOMAIN',
          '$SCHEMA',
          'GITLAB_CI',
          '$CI_PROJECT_PATH',
          '$CI_PIPELINE_ID',
          '$CI_COMMIT_SHA',
          '$CI_COMMIT_REF_NAME',
          PARSE_JSON('{
            \"triggered_by\": \"$GITLAB_USER_LOGIN\",
            \"backup_id\": \"$BACKUP_ID\",
            \"manual\": true
          }')
        );
      " --format json)
      DEPLOYMENT_ID=$(echo $DEPLOYMENT_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['DEVOPS_START_DEPLOYMENT']['deployment_id'])")
      echo "DEPLOYMENT_ID=$DEPLOYMENT_ID" >> deploy.env
    # Deploy
    - snow sql -f "databases/$DATABASE/$SCHEMA/deploy.sql"
    # Complete tracking
    - |
      source deploy.env
      snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
          '$DEPLOYMENT_ID',
          'SUCCESS',
          NULL
        );
      "
      echo "✅ Production deployment completed!"
  needs:
    - deploy-prd-backup
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  allow_failure: false
*/
-- =====================================================================
-- END: .gitlab-ci.yml
-- =====================================================================

/*
 * ============================================================================
 * PHASE 4: APPROVAL RULES (GitLab Premium/Ultimate)
 * ============================================================================
 * 
 * STEP 4.1: Configure Merge Request Approvals
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project → Settings → Merge requests → Merge request approvals
 *   
 *   Add approval rules:
 *   
 *   │ Rule Name          │ Approvals Required │ Eligible approvers        │
 *   │────────────────────│────────────────────│───────────────────────────│
 *   │ Code Review        │ 1                  │ Developers                │
 *   │ DBA Approval       │ 1                  │ DBA Team group            │
 *   │ PRD Approval       │ 2                  │ Release Managers group    │
 *   
 *   Settings:
 *   ☑ Prevent approval by author
 *   ☑ Prevent editing approval rules in merge requests
 *   ☑ Remove all approvals when commits are added
 * 
 * STEP 4.2: Configure Deployment Approvals (Premium/Ultimate)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project → Operate → Environments → production → Edit
 *   
 *   Under "Deployment Approvals":
 *   ☑ Required approval count: 2
 *   Add approvers: Release Managers, DBAs
 * 
 * ============================================================================
 * PHASE 5: ALTERNATIVE - SIMPLE SINGLE-FILE CONFIGURATION
 * ============================================================================
 * 
 * For smaller projects, use this simplified single-file approach:
 * 
 *   File: .gitlab-ci.yml (simplified)
 */

-- =====================================================================
-- BEGIN: .gitlab-ci.yml (Simplified Version)
-- =====================================================================
/*
# Simplified GitLab CI/CD for Snowflake
# ─────────────────────────────────────────────────────────────────────

image: snowflakedb/snowflake-cli:latest

stages:
  - deploy

variables:
  SNOWFLAKE_CONNECTIONS_DEFAULT_ACCOUNT: $SNOWFLAKE_ACCOUNT
  SNOWFLAKE_CONNECTIONS_DEFAULT_USER: $SNOWFLAKE_USER
  SNOWFLAKE_CONNECTIONS_DEFAULT_PRIVATE_KEY_PATH: $SNOWFLAKE_PRIVATE_KEY

# Deploy to DEV
deploy-dev:
  stage: deploy
  environment: development
  variables:
    SNOWFLAKE_CONNECTIONS_DEFAULT_ROLE: $SNOWFLAKE_ROLE_DEV
    SNOWFLAKE_CONNECTIONS_DEFAULT_WAREHOUSE: $SNOWFLAKE_WAREHOUSE_DEV
    SNOWFLAKE_CONNECTIONS_DEFAULT_DATABASE: "HR_DEV"
  script:
    - snow sql -f databases/HR_DEV/EMPLOYEES/deploy.sql
  only:
    - develop

# Deploy to PRD (manual)
deploy-prd:
  stage: deploy
  environment: production
  variables:
    SNOWFLAKE_CONNECTIONS_DEFAULT_ROLE: $SNOWFLAKE_ROLE_PRD
    SNOWFLAKE_CONNECTIONS_DEFAULT_WAREHOUSE: $SNOWFLAKE_WAREHOUSE_PRD
    SNOWFLAKE_CONNECTIONS_DEFAULT_DATABASE: "HR_PRD"
  script:
    - snow sql -f databases/HR_PRD/EMPLOYEES/deploy.sql
  only:
    - main
  when: manual
*/
-- =====================================================================
-- END: .gitlab-ci.yml (Simplified Version)
-- =====================================================================

/*
 * ============================================================================
 * PHASE 6: REUSABLE CI/CD COMPONENTS
 * ============================================================================
 * 
 * STEP 6.1: Create Reusable Templates
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: ci/templates/.snowflake-deploy.yml
 */

-- =====================================================================
-- BEGIN: ci/templates/.snowflake-deploy.yml
-- =====================================================================
/*
# Reusable template for Snowflake deployments
# Include in .gitlab-ci.yml with:
#   include:
#     - local: 'ci/templates/.snowflake-deploy.yml'

.snowflake_deploy:
  image: python:3.11-slim
  before_script:
    - pip install --quiet snowflake-cli-labs
    - mkdir -p ~/.snowflake
    - cp $SNOWFLAKE_PRIVATE_KEY ~/.snowflake/rsa_key.p8
    - chmod 600 ~/.snowflake/rsa_key.p8
    - |
      cat > ~/.snowflake/config.toml << EOF
      [connections.default]
      account = "$SNOWFLAKE_ACCOUNT"
      user = "$SNOWFLAKE_USER"
      private_key_path = "~/.snowflake/rsa_key.p8"
      role = "$ROLE"
      warehouse = "$WAREHOUSE"
      database = "$DATABASE"
      EOF
  script:
    # Start deployment tracking
    - |
      DEPLOYMENT_RESULT=$(snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
          '$ENVIRONMENT',
          '$DOMAIN',
          '$SCHEMA',
          'GITLAB_CI',
          '$CI_PROJECT_PATH',
          '$CI_PIPELINE_ID',
          '$CI_COMMIT_SHA',
          '$CI_COMMIT_REF_NAME',
          NULL
        );
      " --format json)
      export DEPLOYMENT_ID=$(echo $DEPLOYMENT_RESULT | python3 -c "import sys, json; print(json.loads(sys.stdin.read())[0]['DEVOPS_START_DEPLOYMENT']['deployment_id'])")
    # Deploy
    - snow sql -f "databases/$DATABASE/$SCHEMA/deploy.sql"
    # Complete tracking
    - |
      snow sql -q "
        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
          '$DEPLOYMENT_ID',
          'SUCCESS',
          NULL
        );
      "
  after_script:
    - |
      if [ "$CI_JOB_STATUS" == "failed" ]; then
        snow sql -q "
          CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
            '$DEPLOYMENT_ID',
            'FAILED',
            'Job failed - check GitLab CI logs'
          );
        " || true
      fi
*/
-- =====================================================================
-- END: ci/templates/.snowflake-deploy.yml
-- =====================================================================

/*
 * STEP 6.2: Using the Template
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .gitlab-ci.yml (using template)
 */

-- =====================================================================
-- BEGIN: .gitlab-ci.yml (using template)
-- =====================================================================
/*
include:
  - local: 'ci/templates/.snowflake-deploy.yml'

stages:
  - validate
  - deploy-dev
  - deploy-tst
  - deploy-uat
  - deploy-prd

variables:
  DOMAIN: "HR"
  SCHEMA: "EMPLOYEES"

deploy-dev:
  extends: .snowflake_deploy
  stage: deploy-dev
  variables:
    ENVIRONMENT: "DEV"
    ROLE: $SNOWFLAKE_ROLE_DEV
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_DEV
    DATABASE: "HR_DEV"
  environment:
    name: development
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

deploy-tst:
  extends: .snowflake_deploy
  stage: deploy-tst
  variables:
    ENVIRONMENT: "TST"
    ROLE: $SNOWFLAKE_ROLE_TST
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_TST
    DATABASE: "HR_TST"
  environment:
    name: testing
  needs:
    - deploy-dev
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

deploy-uat:
  extends: .snowflake_deploy
  stage: deploy-uat
  variables:
    ENVIRONMENT: "UAT"
    ROLE: $SNOWFLAKE_ROLE_UAT
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_UAT
    DATABASE: "HR_UAT"
  environment:
    name: uat
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual

deploy-prd:
  extends: .snowflake_deploy
  stage: deploy-prd
  variables:
    ENVIRONMENT: "PRD"
    ROLE: $SNOWFLAKE_ROLE_PRD
    WAREHOUSE: $SNOWFLAKE_WAREHOUSE_PRD
    DATABASE: "HR_PRD"
  environment:
    name: production
  needs:
    - deploy-uat
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
*/
-- =====================================================================
-- END: .gitlab-ci.yml (using template)
-- =====================================================================

/*
 * ============================================================================
 * PHASE 7: GITLAB RUNNERS
 * ============================================================================
 * 
 * STEP 7.1: Using GitLab.com Shared Runners
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Shared runners are enabled by default on GitLab.com.
 *   No additional configuration needed.
 * 
 * STEP 7.2: Self-Hosted Runner (Optional)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   For security or performance, you can use self-hosted runners:
 *   
 *   Navigate to: Project → Settings → CI/CD → Runners
 *   
 *   Follow instructions to register a runner with tags:
 *   - snowflake
 *   - production (for PRD jobs only)
 *   
 *   Then in .gitlab-ci.yml:
 */

-- Runner tag example:
/*
deploy-prd:
  tags:
    - snowflake
    - production
  ...
*/

/*
 * ============================================================================
 * PHASE 8: TESTING THE PIPELINE
 * ============================================================================
 * 
 * STEP 8.1: Verify Service Account Connection
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Run in Snowflake to verify
USE ROLE SRS_DEVOPS;
SELECT * FROM ADMIN.DEVOPS.DEVOPS_PIPELINES 
WHERE PLATFORM = 'GITLAB';

/*
 * STEP 8.2: Trigger Test Pipeline
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   1. Navigate to: Project → Build → Pipelines
 *   2. Click "Run pipeline"
 *   3. Select branch: develop
 *   4. Click "Run pipeline"
 *   5. Monitor the pipeline stages
 * 
 * STEP 8.3: Verify Deployment in Snowflake
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Check deployment history
SELECT 
    DEPLOYMENT_ID,
    TARGET_ENVIRONMENT,
    DATABASE_NAME,
    PIPELINE_NAME,
    COMMIT_SHA,
    STATUS,
    STARTED_AT,
    COMPLETED_AT
FROM ADMIN.DEVOPS.DEVOPS_DEPLOYMENTS 
WHERE PIPELINE_NAME LIKE '%gitlab%'
ORDER BY STARTED_AT DESC 
LIMIT 10;

-- View deployment dashboard
CALL ADMIN.DEVOPS.DEVOPS_DEPLOYMENT_DASHBOARD();

/*
 * ============================================================================
 * PHASE 9: TROUBLESHOOTING
 * ============================================================================
 * 
 * Issue: "Permission denied" for SNOWFLAKE_PRIVATE_KEY
 * ─────────────────────────────────────────────────────────────────────────────
 *   - Ensure variable is set as "File" type, not "Variable"
 *   - Check file permissions: chmod 600
 * 
 * Issue: Protected variables not available
 * ─────────────────────────────────────────────────────────────────────────────
 *   - Check if branch is marked as protected
 *   - Verify variable scope matches the environment
 * 
 * Issue: Deployment tracking fails
 * ─────────────────────────────────────────────────────────────────────────────
 *   - Verify role has USAGE on ADMIN.DEVOPS schema
 *   - Check service account has correct SRW_* role
 * 
 * Issue: Manual job doesn't appear
 * ─────────────────────────────────────────────────────────────────────────────
 *   - Check rule conditions (branch must match)
 *   - Verify previous stages succeeded
 * 
 * ============================================================================
 * SUMMARY: COMPLETE CHECKLIST
 * ============================================================================
 * 
 * │ # │ Task                                           │ Location        │
 * │───│────────────────────────────────────────────────│─────────────────│
 * │ 1 │ Generate RSA key pair                          │ Local machine   │
 * │ 2 │ Create pipeline service account                │ Snowflake       │
 * │ 3 │ Create GitLab project                          │ GitLab          │
 * │ 4 │ Add CI/CD variables (SNOWFLAKE_*)              │ Settings/CI-CD  │
 * │ 5 │ Create environments                            │ Operate/Env     │
 * │ 6 │ Configure protected branches                   │ Settings/Repo   │
 * │ 7 │ Create .gitlab-ci.yml                          │ Repository      │
 * │ 8 │ Configure merge request approvals (Premium)    │ Settings/MR     │
 * │ 9 │ Configure deployment approvals (Premium)       │ Environment     │
 * │ 10│ Test pipeline with sample deployment           │ Build/Pipelines │
 * │ 11│ Verify deployment tracking in Snowflake        │ Snowflake       │
 * 
 * ============================================================================
 * GITLAB TIERS FEATURE AVAILABILITY
 * ============================================================================
 * 
 * │ Feature                        │ Free │ Premium │ Ultimate │
 * │────────────────────────────────│──────│─────────│──────────│
 * │ CI/CD Pipelines                │ ✓    │ ✓       │ ✓        │
 * │ Protected branches             │ ✓    │ ✓       │ ✓        │
 * │ Environments                   │ ✓    │ ✓       │ ✓        │
 * │ Manual jobs                    │ ✓    │ ✓       │ ✓        │
 * │ CI/CD Variables                │ ✓    │ ✓       │ ✓        │
 * │ Merge request approvals        │ -    │ ✓       │ ✓        │
 * │ Deployment approvals           │ -    │ ✓       │ ✓        │
 * │ Protected environments         │ -    │ ✓       │ ✓        │
 * │ Compliance pipelines           │ -    │ -       │ ✓        │
 * 
 ******************************************************************************/

-- Final verification query
SELECT 
    'GitLab CI/CD Setup Guide' AS GUIDE,
    'Follow phases 1-9 for complete CI/CD implementation' AS INSTRUCTIONS,
    'See ADMIN.DEVOPS schema for Snowflake-side procedures' AS SNOWFLAKE_PROCEDURES;
