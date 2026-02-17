/*******************************************************************************
 * AZURE DEVOPS SETUP GUIDE FOR SNOWFLAKE CI/CD
 * 
 * This guide details all the steps needed on the Azure DevOps side to implement
 * a complete CI/CD workflow that integrates with the RBAC framework.
 * 
 * ============================================================================
 * ARCHITECTURE OVERVIEW
 * ============================================================================
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                    AZURE DEVOPS + SNOWFLAKE CI/CD                       │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │   AZURE DEVOPS                          SNOWFLAKE                       │
 *   │   ─────────────                         ─────────                       │
 *   │                                                                         │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Azure Repos │  ─────────────────►  Git Repository (optional)       │
 *   │   │ (Git)       │                      Native Snowflake Git             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Service Account                                  │
 *   │   │  Pipelines  │  ─────────────────►  SVC_AZURE_DEVOPS_*_DEPLOYER     │
 *   │   │  (YAML)     │      Key Pair Auth   SRW_*_DEPLOYER role             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Snowflake CLI                                    │
 *   │   │   Agents    │  ─────────────────►  ADMIN.DEVOPS.DEVOPS_*           │
 *   │   │ (Microsoft/ │      or SnowSQL      procedures                      │
 *   │   │  Self-host) │                                                       │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ├──────►  DEV  ───►  TST  ───►  UAT  ───►  PRD                │
 *   │          │         (auto)     (auto)    (manual)   (manual+approval)   │
 *   │          │                                                              │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Artifacts   │  ─────────────────►  Deployment tracking             │
 *   │   │ & Releases  │                      ADMIN.DEVOPS tables             │
 *   │   └─────────────┘                                                       │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 * PREREQUISITES
 * ============================================================================
 * 
 * Before starting Azure DevOps setup:
 * 
 *   1. RBAC Framework deployed to Snowflake
 *      - RBAC_INITIAL_CONFIG executed
 *      - RBAC_SP_DevOps.sql deployed to ADMIN.DEVOPS schema
 *   
 *   2. Azure DevOps organization and project created
 *      - Azure DevOps Services or Azure DevOps Server 2020+
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

-- Setup Azure DevOps pipeline (replace <PUBLIC_KEY> with your key)
CALL ADMIN.DEVOPS.DEVOPS_SETUP_AZURE_DEVOPS(
    'MY_PROJECT',                    -- Azure DevOps project name
    'HR',                            -- Domain this pipeline deploys to
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',  -- RSA public key
    ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PRD')         -- Environments
);

-- The procedure returns:
-- {
--   "service_account": "AZURE_DEVOPS_MY_PROJECT_HR_DEPLOYER",
--   "azure_devops_config": {
--     "account_identifier": "xy12345.snowflakecomputing.com",
--     "username": "AZURE_DEVOPS_MY_PROJECT_HR_DEPLOYER",
--     "role": "SRW_DEV_HR_DEVELOPER",
--     "warehouse": "DEV_WH"
--   }
-- }

/*
 * ============================================================================
 * PHASE 2: AZURE DEVOPS SETUP
 * ============================================================================
 * 
 * STEP 2.1: Create Azure DevOps Project Structure
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   In Azure DevOps, create the following structure:
 *   
 *   my-snowflake-project/
 *   ├── Repos/
 *   │   └── snowflake-deployments/          # Git repository
 *   │       ├── .azuredevops/
 *   │       │   └── pipelines/
 *   │       │       ├── ci-pipeline.yml     # Build/validation pipeline
 *   │       │       └── cd-pipeline.yml     # Deployment pipeline
 *   │       ├── databases/
 *   │       │   ├── HR_DEV/
 *   │       │   │   └── EMPLOYEES/
 *   │       │   │       ├── tables/
 *   │       │   │       ├── views/
 *   │       │   │       ├── procedures/
 *   │       │   │       └── deploy.sql
 *   │       │   ├── HR_TST/
 *   │       │   ├── HR_UAT/
 *   │       │   └── HR_PRD/
 *   │       └── scripts/
 *   │           ├── pre-deploy.sql
 *   │           ├── post-deploy.sql
 *   │           └── rollback.sql
 *   │
 *   ├── Pipelines/
 *   │   ├── CI - Validate SQL              # Continuous Integration
 *   │   └── CD - Deploy to Snowflake       # Continuous Deployment
 *   │
 *   └── Environments/
 *       ├── DEV                            # Auto-deploy
 *       ├── TST                            # Auto-deploy after DEV
 *       ├── UAT                            # Manual approval required
 *       └── PRD                            # Manual approval + change board
 * 
 * STEP 2.2: Configure Service Connection
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project Settings → Service connections → New service connection
 *   
 *   Option A: Generic Service Connection (Recommended)
 *   ─────────────────────────────────────────────────────
 *   1. Select "Generic" as the connection type
 *   2. Configure:
 *      - Server URL: https://<account>.snowflakecomputing.com
 *      - Username: AZURE_DEVOPS_MY_PROJECT_HR_DEPLOYER
 *      - Password/Token: (leave blank - using key pair)
 *   3. Service connection name: Snowflake-DEV (create one per environment)
 *   
 *   Option B: Use Variable Groups (Alternative)
 *   ─────────────────────────────────────────────────────
 *   Navigate to: Pipelines → Library → Variable groups
 *   
 *   Create variable group: "Snowflake-Credentials"
 *   
 *   Variables:
 *   │ Variable Name          │ Value                                    │ Secret │
 *   │────────────────────────│──────────────────────────────────────────│────────│
 *   │ SNOWFLAKE_ACCOUNT      │ xy12345                                  │ No     │
 *   │ SNOWFLAKE_USER         │ AZURE_DEVOPS_MY_PROJECT_HR_DEPLOYER      │ No     │
 *   │ SNOWFLAKE_PRIVATE_KEY  │ <contents of rsa_key.p8>                 │ Yes    │
 *   │ SNOWFLAKE_ROLE_DEV     │ SRW_DEV_HR_DEVELOPER                     │ No     │
 *   │ SNOWFLAKE_ROLE_TST     │ SRW_TST_HR_DEVELOPER                     │ No     │
 *   │ SNOWFLAKE_ROLE_UAT     │ SRW_UAT_HR_DEVELOPER                     │ No     │
 *   │ SNOWFLAKE_ROLE_PRD     │ SRW_PRD_HR_DEVELOPER                     │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_DEV│ DEV_WH                                   │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_TST│ TST_WH                                   │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_UAT│ UAT_WH                                   │ No     │
 *   │ SNOWFLAKE_WAREHOUSE_PRD│ PRD_WH                                   │ No     │
 * 
 * STEP 2.3: Create Environments with Approvals
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Pipelines → Environments → New environment
 *   
 *   Create these environments:
 *   
 *   │ Environment │ Approvals Required     │ Checks                           │
 *   │─────────────│────────────────────────│──────────────────────────────────│
 *   │ DEV         │ None                   │ None                             │
 *   │ TST         │ None (or team lead)    │ Required template                │
 *   │ UAT         │ QA Manager             │ All CI tests passed              │
 *   │ PRD         │ Release Manager + DBA  │ Change request approved          │
 *   
 *   For each environment:
 *   1. Click on the environment name
 *   2. Click "Approvals and checks"
 *   3. Add approvers:
 *      - UAT: Add QA team
 *      - PRD: Add Release Manager, DBA team
 *   4. Add checks:
 *      - "Required template" - ensure standard pipeline is used
 *      - "Business hours" (optional) - PRD only during change windows
 * 
 * ============================================================================
 * PHASE 3: CREATE PIPELINE FILES
 * ============================================================================
 * 
 * STEP 3.1: CI Pipeline (Validation)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .azuredevops/pipelines/ci-pipeline.yml
 */

-- =====================================================================
-- BEGIN: ci-pipeline.yml
-- =====================================================================
/*
# CI Pipeline - Validates SQL syntax and runs tests
# Triggers on: Pull Requests to main/develop branches

trigger: none  # CI only runs on PR

pr:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - databases/**
      - scripts/**

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: Snowflake-Credentials

stages:
  # ─────────────────────────────────────────────────────────────────────
  # Stage 1: Validate SQL Syntax
  # ─────────────────────────────────────────────────────────────────────
  - stage: Validate
    displayName: 'Validate SQL'
    jobs:
      - job: ValidateSQL
        displayName: 'Validate SQL Syntax'
        steps:
          - checkout: self
            fetchDepth: 0
          
          # Install Snowflake CLI
          - task: Bash@3
            displayName: 'Install Snowflake CLI'
            inputs:
              targetType: 'inline'
              script: |
                pip install snowflake-cli-labs
                snow --version
          
          # Create connection config
          - task: Bash@3
            displayName: 'Configure Snowflake Connection'
            inputs:
              targetType: 'inline'
              script: |
                mkdir -p ~/.snowflake
                echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                chmod 600 ~/.snowflake/rsa_key.p8
                
                cat > ~/.snowflake/config.toml << EOF
                [connections.default]
                account = "$(SNOWFLAKE_ACCOUNT)"
                user = "$(SNOWFLAKE_USER)"
                private_key_path = "~/.snowflake/rsa_key.p8"
                role = "$(SNOWFLAKE_ROLE_DEV)"
                warehouse = "$(SNOWFLAKE_WAREHOUSE_DEV)"
                EOF
            env:
              SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
          
          # Validate SQL files compile
          - task: Bash@3
            displayName: 'Validate SQL Compilation'
            inputs:
              targetType: 'inline'
              script: |
                # Find all changed SQL files
                CHANGED_FILES=$(git diff --name-only origin/main...HEAD -- '*.sql')
                
                for file in $CHANGED_FILES; do
                  echo "Validating: $file"
                  # Use EXPLAIN to validate without executing
                  snow sql -q "EXPLAIN USING TEXT $(cat $file)" || exit 1
                done

  # ─────────────────────────────────────────────────────────────────────
  # Stage 2: Run Tests (if test files exist)
  # ─────────────────────────────────────────────────────────────────────
  - stage: Test
    displayName: 'Run Tests'
    dependsOn: Validate
    jobs:
      - job: RunTests
        displayName: 'Execute Test Scripts'
        steps:
          - task: Bash@3
            displayName: 'Run SQL Tests'
            inputs:
              targetType: 'inline'
              script: |
                if [ -d "tests/" ]; then
                  for test_file in tests/*.sql; do
                    echo "Running test: $test_file"
                    snow sql -f "$test_file"
                  done
                else
                  echo "No tests directory found, skipping"
                fi
*/
-- =====================================================================
-- END: ci-pipeline.yml
-- =====================================================================

/*
 * STEP 3.2: CD Pipeline (Deployment)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .azuredevops/pipelines/cd-pipeline.yml
 */

-- =====================================================================
-- BEGIN: cd-pipeline.yml
-- =====================================================================
/*
# CD Pipeline - Deploys to Snowflake environments
# Triggers on: Merge to main/develop branches

trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - databases/**
      - scripts/**

pr: none  # CD only runs on merge, not PR

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: Snowflake-Credentials

stages:
  # ─────────────────────────────────────────────────────────────────────
  # Stage 1: Deploy to DEV (Automatic)
  # ─────────────────────────────────────────────────────────────────────
  - stage: Deploy_DEV
    displayName: 'Deploy to DEV'
    condition: always()
    jobs:
      - deployment: DeployDEV
        displayName: 'Deploy to DEV Environment'
        environment: DEV
        strategy:
          runOnce:
            deploy:
              steps:
                - checkout: self
                
                - task: Bash@3
                  displayName: 'Install Snowflake CLI'
                  inputs:
                    targetType: 'inline'
                    script: |
                      pip install snowflake-cli-labs
                
                - task: Bash@3
                  displayName: 'Configure Connection'
                  inputs:
                    targetType: 'inline'
                    script: |
                      mkdir -p ~/.snowflake
                      echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                      chmod 600 ~/.snowflake/rsa_key.p8
                      
                      cat > ~/.snowflake/config.toml << EOF
                      [connections.default]
                      account = "$(SNOWFLAKE_ACCOUNT)"
                      user = "$(SNOWFLAKE_USER)"
                      private_key_path = "~/.snowflake/rsa_key.p8"
                      role = "$(SNOWFLAKE_ROLE_DEV)"
                      warehouse = "$(SNOWFLAKE_WAREHOUSE_DEV)"
                      database = "HR_DEV"
                      EOF
                  env:
                    SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
                
                # Start deployment tracking
                - task: Bash@3
                  displayName: 'Start Deployment Tracking'
                  inputs:
                    targetType: 'inline'
                    script: |
                      snow sql -q "
                        CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
                          'DEV',
                          'HR',
                          'EMPLOYEES',
                          'PIPELINE',
                          'Azure DevOps',
                          '$(Build.BuildId)',
                          '$(Build.SourceVersion)',
                          '$(Build.SourceBranchName)',
                          NULL
                        );
                      " > deployment_result.json
                      
                      DEPLOYMENT_ID=$(cat deployment_result.json | jq -r '.deployment_id')
                      echo "##vso[task.setvariable variable=DEPLOYMENT_ID]$DEPLOYMENT_ID"
                
                # Execute pre-deployment script
                - task: Bash@3
                  displayName: 'Pre-Deployment'
                  inputs:
                    targetType: 'inline'
                    script: |
                      if [ -f "scripts/pre-deploy.sql" ]; then
                        snow sql -f scripts/pre-deploy.sql
                      fi
                
                # Deploy database objects
                - task: Bash@3
                  displayName: 'Deploy Database Objects'
                  inputs:
                    targetType: 'inline'
                    script: |
                      # Deploy in order: tables, views, procedures, functions
                      for obj_type in tables views procedures functions; do
                        if [ -d "databases/HR_DEV/EMPLOYEES/$obj_type" ]; then
                          for sql_file in databases/HR_DEV/EMPLOYEES/$obj_type/*.sql; do
                            echo "Deploying: $sql_file"
                            snow sql -f "$sql_file"
                            
                            # Log each object
                            snow sql -q "
                              CALL ADMIN.DEVOPS.DEVOPS_LOG_DEPLOYMENT_OBJECT(
                                '$(DEPLOYMENT_ID)',
                                '$obj_type',
                                '$(basename $sql_file .sql)',
                                'CREATE_OR_REPLACE',
                                NULL
                              );
                            "
                          done
                        fi
                      done
                
                # Execute post-deployment script
                - task: Bash@3
                  displayName: 'Post-Deployment'
                  inputs:
                    targetType: 'inline'
                    script: |
                      if [ -f "scripts/post-deploy.sql" ]; then
                        snow sql -f scripts/post-deploy.sql
                      fi
                
                # Complete deployment tracking
                - task: Bash@3
                  displayName: 'Complete Deployment Tracking'
                  condition: always()
                  inputs:
                    targetType: 'inline'
                    script: |
                      if [ "$(Agent.JobStatus)" == "Succeeded" ]; then
                        STATUS="SUCCESS"
                      else
                        STATUS="FAILED"
                      fi
                      
                      snow sql -q "
                        CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
                          '$(DEPLOYMENT_ID)',
                          '$STATUS',
                          NULL
                        );
                      "

  # ─────────────────────────────────────────────────────────────────────
  # Stage 2: Deploy to TST (Automatic after DEV success)
  # ─────────────────────────────────────────────────────────────────────
  - stage: Deploy_TST
    displayName: 'Deploy to TST'
    dependsOn: Deploy_DEV
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/develop'))
    jobs:
      - deployment: DeployTST
        displayName: 'Deploy to TST Environment'
        environment: TST
        strategy:
          runOnce:
            deploy:
              steps:
                - checkout: self
                
                - task: Bash@3
                  displayName: 'Install & Configure'
                  inputs:
                    targetType: 'inline'
                    script: |
                      pip install snowflake-cli-labs
                      mkdir -p ~/.snowflake
                      echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                      chmod 600 ~/.snowflake/rsa_key.p8
                      
                      cat > ~/.snowflake/config.toml << EOF
                      [connections.default]
                      account = "$(SNOWFLAKE_ACCOUNT)"
                      user = "$(SNOWFLAKE_USER)"
                      private_key_path = "~/.snowflake/rsa_key.p8"
                      role = "$(SNOWFLAKE_ROLE_TST)"
                      warehouse = "$(SNOWFLAKE_WAREHOUSE_TST)"
                      database = "HR_TST"
                      EOF
                  env:
                    SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
                
                - task: Bash@3
                  displayName: 'Deploy to TST'
                  inputs:
                    targetType: 'inline'
                    script: |
                      # Similar deployment steps as DEV
                      # Using TST-specific database/role/warehouse
                      snow sql -f databases/HR_TST/EMPLOYEES/deploy.sql

  # ─────────────────────────────────────────────────────────────────────
  # Stage 3: Deploy to UAT (Manual approval required)
  # ─────────────────────────────────────────────────────────────────────
  - stage: Deploy_UAT
    displayName: 'Deploy to UAT'
    dependsOn: Deploy_TST
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployUAT
        displayName: 'Deploy to UAT Environment'
        environment: UAT  # Has approval gates configured
        strategy:
          runOnce:
            deploy:
              steps:
                - checkout: self
                
                - task: Bash@3
                  displayName: 'Install & Configure'
                  inputs:
                    targetType: 'inline'
                    script: |
                      pip install snowflake-cli-labs
                      mkdir -p ~/.snowflake
                      echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                      chmod 600 ~/.snowflake/rsa_key.p8
                      
                      cat > ~/.snowflake/config.toml << EOF
                      [connections.default]
                      account = "$(SNOWFLAKE_ACCOUNT)"
                      user = "$(SNOWFLAKE_USER)"
                      private_key_path = "~/.snowflake/rsa_key.p8"
                      role = "$(SNOWFLAKE_ROLE_UAT)"
                      warehouse = "$(SNOWFLAKE_WAREHOUSE_UAT)"
                      database = "HR_UAT"
                      EOF
                  env:
                    SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
                
                - task: Bash@3
                  displayName: 'Deploy to UAT'
                  inputs:
                    targetType: 'inline'
                    script: |
                      snow sql -f databases/HR_UAT/EMPLOYEES/deploy.sql

  # ─────────────────────────────────────────────────────────────────────
  # Stage 4: Deploy to PRD (Manual approval + change board required)
  # ─────────────────────────────────────────────────────────────────────
  - stage: Deploy_PRD
    displayName: 'Deploy to PRD'
    dependsOn: Deploy_UAT
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployPRD
        displayName: 'Deploy to PRD Environment'
        environment: PRD  # Has approval gates + business hours check
        strategy:
          runOnce:
            preDeploy:
              steps:
                - task: Bash@3
                  displayName: 'Create Backup Before Deployment'
                  inputs:
                    targetType: 'inline'
                    script: |
                      pip install snowflake-cli-labs
                      mkdir -p ~/.snowflake
                      echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                      
                      cat > ~/.snowflake/config.toml << EOF
                      [connections.default]
                      account = "$(SNOWFLAKE_ACCOUNT)"
                      user = "$(SNOWFLAKE_USER)"
                      private_key_path = "~/.snowflake/rsa_key.p8"
                      role = "$(SNOWFLAKE_ROLE_PRD)"
                      warehouse = "$(SNOWFLAKE_WAREHOUSE_PRD)"
                      EOF
                      
                      # Create pre-deployment backup
                      snow sql -q "
                        CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP(
                          'HR_PRD',
                          'EMPLOYEES',
                          NULL,
                          'PRE_RELEASE',
                          NULL,
                          NULL,
                          7,
                          NULL,
                          'Backup before Build $(Build.BuildId)'
                        );
                      "
                  env:
                    SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
            
            deploy:
              steps:
                - checkout: self
                
                - task: Bash@3
                  displayName: 'Deploy to PRD'
                  inputs:
                    targetType: 'inline'
                    script: |
                      pip install snowflake-cli-labs
                      mkdir -p ~/.snowflake
                      echo "$SNOWFLAKE_PRIVATE_KEY" > ~/.snowflake/rsa_key.p8
                      
                      cat > ~/.snowflake/config.toml << EOF
                      [connections.default]
                      account = "$(SNOWFLAKE_ACCOUNT)"
                      user = "$(SNOWFLAKE_USER)"
                      private_key_path = "~/.snowflake/rsa_key.p8"
                      role = "$(SNOWFLAKE_ROLE_PRD)"
                      warehouse = "$(SNOWFLAKE_WAREHOUSE_PRD)"
                      database = "HR_PRD"
                      EOF
                      
                      snow sql -f databases/HR_PRD/EMPLOYEES/deploy.sql
                  env:
                    SNOWFLAKE_PRIVATE_KEY: $(SNOWFLAKE_PRIVATE_KEY)
            
            on:
              failure:
                steps:
                  - task: Bash@3
                    displayName: 'Rollback on Failure'
                    inputs:
                      targetType: 'inline'
                      script: |
                        echo "Deployment failed. Consider rollback."
                        # Rollback procedure would be called here
                        # snow sql -q "CALL ADMIN.DEVOPS.DEVOPS_ROLLBACK_DEPLOYMENT('$(DEPLOYMENT_ID)');"
*/
-- =====================================================================
-- END: cd-pipeline.yml
-- =====================================================================

/*
 * ============================================================================
 * PHASE 4: REPOSITORY STRUCTURE
 * ============================================================================
 * 
 * STEP 4.1: Recommended Folder Structure
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   snowflake-deployments/
 *   │
 *   ├── .azuredevops/
 *   │   └── pipelines/
 *   │       ├── ci-pipeline.yml          # PR validation
 *   │       ├── cd-pipeline.yml          # Deployment
 *   │       └── templates/
 *   │           ├── snowflake-setup.yml  # Reusable setup steps
 *   │           └── deploy-schema.yml    # Reusable deployment steps
 *   │
 *   ├── databases/
 *   │   ├── HR_DEV/                      # Environment-specific
 *   │   │   └── EMPLOYEES/               # Schema
 *   │   │       ├── tables/
 *   │   │       │   ├── EMPLOYEES.sql
 *   │   │       │   └── DEPARTMENTS.sql
 *   │   │       ├── views/
 *   │   │       │   └── V_EMPLOYEE_SUMMARY.sql
 *   │   │       ├── procedures/
 *   │   │       │   └── SP_UPDATE_EMPLOYEE.sql
 *   │   │       ├── functions/
 *   │   │       │   └── FN_CALCULATE_TENURE.sql
 *   │   │       └── deploy.sql           # Master deployment script
 *   │   │
 *   │   ├── HR_TST/                      # Copy of DEV structure
 *   │   ├── HR_UAT/                      # Copy of DEV structure
 *   │   └── HR_PRD/                      # Copy of DEV structure
 *   │
 *   ├── scripts/
 *   │   ├── pre-deploy.sql               # Run before deployment
 *   │   ├── post-deploy.sql              # Run after deployment
 *   │   └── rollback.sql                 # Rollback procedures
 *   │
 *   ├── tests/
 *   │   ├── test_employees.sql
 *   │   └── test_procedures.sql
 *   │
 *   └── README.md
 * 
 * STEP 4.2: Sample deploy.sql Master Script
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- File: databases/HR_DEV/EMPLOYEES/deploy.sql

-- Set context
USE DATABASE HR_DEV;
USE SCHEMA EMPLOYEES;

-- Deploy tables
!source tables/EMPLOYEES.sql
!source tables/DEPARTMENTS.sql

-- Deploy views
!source views/V_EMPLOYEE_SUMMARY.sql

-- Deploy procedures
!source procedures/SP_UPDATE_EMPLOYEE.sql

-- Deploy functions
!source functions/FN_CALCULATE_TENURE.sql

-- Verify deployment
SHOW TABLES;
SHOW VIEWS;
SHOW PROCEDURES;

/*
 * ============================================================================
 * PHASE 5: TESTING THE PIPELINE
 * ============================================================================
 * 
 * STEP 5.1: Verify Service Account Connection
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Run in Snowflake to test the pipeline connection
USE ROLE SRS_DEVOPS;
CALL ADMIN.DEVOPS.DEVOPS_TEST_PIPELINE_CONNECTION();

/*
 * STEP 5.2: Trigger Test Pipeline Run
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   In Azure DevOps:
 *   1. Navigate to Pipelines
 *   2. Select your CD pipeline
 *   3. Click "Run pipeline"
 *   4. Select branch: develop (for DEV/TST) or main (for UAT/PRD)
 *   5. Click "Run"
 *   6. Monitor the pipeline execution
 * 
 * STEP 5.3: Verify Deployment in Snowflake
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Check deployment history
SELECT * FROM ADMIN.DEVOPS.DEVOPS_DEPLOYMENTS 
ORDER BY STARTED_AT DESC 
LIMIT 10;

-- Check deployment objects
SELECT d.DEPLOYMENT_ID, d.STATUS, d.PIPELINE_NAME, d.COMMIT_SHA,
       o.OBJECT_TYPE, o.OBJECT_NAME, o.OPERATION
FROM ADMIN.DEVOPS.DEVOPS_DEPLOYMENTS d
JOIN ADMIN.DEVOPS.DEVOPS_DEPLOYMENT_OBJECTS o ON d.DEPLOYMENT_ID = o.DEPLOYMENT_ID
WHERE d.STARTED_AT > DATEADD(DAY, -1, CURRENT_TIMESTAMP())
ORDER BY d.STARTED_AT DESC;

-- View DevOps monitoring dashboard
CALL ADMIN.DEVOPS.DEVOPS_DEPLOYMENT_DASHBOARD();

/*
 * ============================================================================
 * PHASE 6: ADVANCED CONFIGURATIONS
 * ============================================================================
 * 
 * STEP 6.1: Branch Policies
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Repos → Branches → Branch policies (for main branch)
 *   
 *   Configure:
 *   │ Policy                        │ Setting                              │
 *   │───────────────────────────────│──────────────────────────────────────│
 *   │ Require minimum reviewers     │ 2 reviewers                          │
 *   │ Check for linked work items   │ Required                             │
 *   │ Check for comment resolution  │ Required                             │
 *   │ Build validation              │ CI pipeline must pass                │
 *   │ Limit merge types             │ Squash merge only                    │
 * 
 * STEP 6.2: Work Item Integration
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Connect deployments to work items:
 *   1. Create a custom work item query for "Ready for Deployment"
 *   2. Link commits to work items using #<work-item-id> in commit messages
 *   3. Configure automatic state transitions when deployed
 * 
 * STEP 6.3: Notifications
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Project Settings → Notifications
 *   
 *   Create subscriptions:
 *   - Pipeline failure → Team channel
 *   - PRD deployment → Release managers
 *   - Approval pending → Approvers
 * 
 * ============================================================================
 * TROUBLESHOOTING
 * ============================================================================
 * 
 * Issue: Authentication failed
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. Verify private key format (must be PKCS#8)
 *   2. Check public key was correctly added to Snowflake user
 *   3. Ensure no extra whitespace in key variables
 *   4. Verify account identifier format (account.region.cloud)
 * 
 * Issue: Permission denied
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. Check service account has correct SRW_* role
 *   2. Verify role has access to target database/schema
 *   3. Ensure warehouse is accessible to the role
 * 
 * Issue: Pipeline hangs
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. Check for SQL syntax errors
 *   2. Verify warehouse is not suspended
 *   3. Check for long-running queries blocking deployment
 * 
 * ============================================================================
 * SUMMARY: COMPLETE CHECKLIST
 * ============================================================================
 * 
 * │ # │ Task                                           │ Location        │
 * │───│────────────────────────────────────────────────│─────────────────│
 * │ 1 │ Generate RSA key pair                          │ Local machine   │
 * │ 2 │ Create pipeline service account                │ Snowflake       │
 * │ 3 │ Create Azure DevOps project                    │ Azure DevOps    │
 * │ 4 │ Create Git repository                          │ Azure Repos     │
 * │ 5 │ Configure variable group with credentials      │ Pipelines/Lib   │
 * │ 6 │ Create environments (DEV/TST/UAT/PRD)          │ Pipelines/Env   │
 * │ 7 │ Configure approvals for UAT/PRD                │ Environment     │
 * │ 8 │ Create CI pipeline (ci-pipeline.yml)           │ Git repo        │
 * │ 9 │ Create CD pipeline (cd-pipeline.yml)           │ Git repo        │
 * │ 10│ Setup branch policies                          │ Repos/Branches  │
 * │ 11│ Configure notifications                        │ Project Settings│
 * │ 12│ Test pipeline with sample deployment           │ Pipelines       │
 * │ 13│ Verify deployment tracking in Snowflake        │ Snowflake       │
 * 
 ******************************************************************************/

-- Final verification query
SELECT 
    'Azure DevOps Setup Guide' AS GUIDE,
    'Follow phases 1-6 for complete CI/CD implementation' AS INSTRUCTIONS,
    'See ADMIN.DEVOPS schema for Snowflake-side procedures' AS SNOWFLAKE_PROCEDURES;
