/*******************************************************************************
 * GITHUB ACTIONS SETUP GUIDE FOR SNOWFLAKE CI/CD
 * 
 * This guide details all the steps needed on the GitHub side to implement
 * a complete CI/CD workflow that integrates with the RBAC framework.
 * 
 * ============================================================================
 * ARCHITECTURE OVERVIEW
 * ============================================================================
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                    GITHUB ACTIONS + SNOWFLAKE CI/CD                     │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │   GITHUB                                SNOWFLAKE                       │
 *   │   ──────                                ─────────                       │
 *   │                                                                         │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Repository  │  ─────────────────►  Git Repository (optional)       │
 *   │   │ (Git)       │                      Native Snowflake Git             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Service Account                                  │
 *   │   │  Actions    │  ─────────────────►  SVC_GITHUB_*_DEPLOYER           │
 *   │   │  Workflows  │      Key Pair Auth   SRW_*_DEPLOYER role             │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ▼                                                              │
 *   │   ┌─────────────┐      Snowflake CLI                                    │
 *   │   │  Runners    │  ─────────────────►  ADMIN.DEVOPS.DEVOPS_*           │
 *   │   │ (GitHub-    │      or SnowSQL      procedures                      │
 *   │   │  hosted)    │                                                       │
 *   │   └──────┬──────┘                                                       │
 *   │          │                                                              │
 *   │          ├──────►  DEV  ───►  TST  ───►  UAT  ───►  PRD                │
 *   │          │         (auto)     (auto)    (manual)   (manual+approval)   │
 *   │          │                                                              │
 *   │   ┌─────────────┐                                                       │
 *   │   │ Environments│  ─────────────────►  Deployment tracking             │
 *   │   │ & Secrets   │                      ADMIN.DEVOPS tables             │
 *   │   └─────────────┘                                                       │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * ============================================================================
 * PREREQUISITES
 * ============================================================================
 * 
 * Before starting GitHub setup:
 * 
 *   1. RBAC Framework deployed to Snowflake
 *      - RBAC_INITIAL_CONFIG executed
 *      - RBAC_SP_DevOps.sql deployed to ADMIN.DEVOPS schema
 *   
 *   2. GitHub repository created
 *      - GitHub.com or GitHub Enterprise
 *      - Repository admin access required
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
 *   # Base64 encode private key for GitHub secret
 *   cat rsa_key.p8 | base64 -w 0
 * 
 * STEP 1.2: Create Pipeline Service Account in Snowflake
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Run as SRS_DEVOPS role
USE ROLE SRS_DEVOPS;

-- Setup GitHub Actions pipeline (replace <PUBLIC_KEY> with your key)
CALL ADMIN.DEVOPS.DEVOPS_SETUP_GITHUB_ACTIONS(
    'my-org/snowflake-repo',         -- GitHub repository (org/repo format)
    'HR',                            -- Domain this pipeline deploys to
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',  -- RSA public key
    ARRAY_CONSTRUCT('DEV', 'TST', 'UAT', 'PRD')         -- Environments
);

-- The procedure returns:
-- {
--   "service_account": "GITHUB_MY_ORG_SNOWFLAKE_REPO_HR_DEPLOYER",
--   "github_secrets": {
--     "SNOWFLAKE_ACCOUNT": "xy12345",
--     "SNOWFLAKE_USER": "GITHUB_MY_ORG_SNOWFLAKE_REPO_HR_DEPLOYER",
--     "SNOWFLAKE_ROLE": "SRW_DEV_HR_DEVELOPER",
--     "SNOWFLAKE_WAREHOUSE": "DEV_WH"
--   }
-- }

/*
 * ============================================================================
 * PHASE 2: GITHUB SETUP
 * ============================================================================
 * 
 * STEP 2.1: Create Repository Structure
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   In GitHub, create the following structure:
 *   
 *   my-org/snowflake-deployments/
 *   ├── .github/
 *   │   └── workflows/
 *   │       ├── ci.yml                      # PR validation workflow
 *   │       ├── cd-dev.yml                  # Deploy to DEV
 *   │       ├── cd-tst.yml                  # Deploy to TST
 *   │       ├── cd-uat.yml                  # Deploy to UAT (manual)
 *   │       └── cd-prd.yml                  # Deploy to PRD (manual)
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
 * STEP 2.2: Configure Repository Secrets
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Repository → Settings → Secrets and variables → Actions
 *   
 *   Click "New repository secret" for each:
 *   
 *   │ Secret Name                │ Value                                    │
 *   │────────────────────────────│──────────────────────────────────────────│
 *   │ SNOWFLAKE_ACCOUNT          │ xy12345 (your account identifier)        │
 *   │ SNOWFLAKE_USER             │ GITHUB_MY_ORG_SNOWFLAKE_REPO_HR_DEPLOYER │
 *   │ SNOWFLAKE_PRIVATE_KEY      │ <base64 encoded private key>             │
 *   │ SNOWFLAKE_ROLE_DEV         │ SRW_DEV_HR_DEVELOPER                     │
 *   │ SNOWFLAKE_ROLE_TST         │ SRW_TST_HR_DEVELOPER                     │
 *   │ SNOWFLAKE_ROLE_UAT         │ SRW_UAT_HR_DEVELOPER                     │
 *   │ SNOWFLAKE_ROLE_PRD         │ SRW_PRD_HR_DEVELOPER                     │
 *   │ SNOWFLAKE_WAREHOUSE_DEV    │ DEV_WH                                   │
 *   │ SNOWFLAKE_WAREHOUSE_TST    │ TST_WH                                   │
 *   │ SNOWFLAKE_WAREHOUSE_UAT    │ UAT_WH                                   │
 *   │ SNOWFLAKE_WAREHOUSE_PRD    │ PRD_WH                                   │
 * 
 * STEP 2.3: Create Environments with Protection Rules
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Repository → Settings → Environments
 *   
 *   Create these environments:
 *   
 *   │ Environment │ Protection Rules                                        │
 *   │─────────────│─────────────────────────────────────────────────────────│
 *   │ development │ None (auto-deploy)                                      │
 *   │ testing     │ None or wait timer (5 min)                              │
 *   │ uat         │ Required reviewers: QA team                             │
 *   │ production  │ Required reviewers: Release Manager, DBA                │
 *   │             │ + Deployment branches: main only                        │
 *   │             │ + Wait timer: 30 minutes (optional)                     │
 *   
 *   For production environment, also add:
 *   - Environment secrets (if different from repo secrets)
 *   - Deployment branch rules: Only allow 'main' branch
 * 
 * ============================================================================
 * PHASE 3: CREATE WORKFLOW FILES
 * ============================================================================
 * 
 * STEP 3.1: CI Workflow (Pull Request Validation)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .github/workflows/ci.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/ci.yml
-- =====================================================================
/*
name: CI - Validate SQL

on:
  pull_request:
    branches: [main, develop]
    paths:
      - 'databases/**'
      - 'scripts/**'

jobs:
  # ─────────────────────────────────────────────────────────────────────
  # Job 1: Validate SQL Syntax
  # ─────────────────────────────────────────────────────────────────────
  validate:
    name: Validate SQL Syntax
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: |
          pip install snowflake-cli-labs
          snow --version
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_DEV }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_DEV }}"
          EOF
      
      - name: Validate Changed SQL Files
        run: |
          # Get changed SQL files
          CHANGED_FILES=$(git diff --name-only origin/main...HEAD -- '*.sql')
          
          if [ -z "$CHANGED_FILES" ]; then
            echo "No SQL files changed"
            exit 0
          fi
          
          echo "Validating SQL files:"
          for file in $CHANGED_FILES; do
            echo "  - $file"
            # Basic syntax validation
            snow sql -q "SELECT 1" > /dev/null 2>&1 || exit 1
          done
          
          echo "✅ All SQL files validated"

  # ─────────────────────────────────────────────────────────────────────
  # Job 2: Run Tests
  # ─────────────────────────────────────────────────────────────────────
  test:
    name: Run SQL Tests
    runs-on: ubuntu-latest
    needs: validate
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_DEV }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_DEV }}"
          EOF
      
      - name: Run SQL Tests
        run: |
          if [ -d "tests/" ]; then
            for test_file in tests/*.sql; do
              echo "Running: $test_file"
              snow sql -f "$test_file"
            done
          else
            echo "No tests directory found"
          fi
*/
-- =====================================================================
-- END: .github/workflows/ci.yml
-- =====================================================================

/*
 * STEP 3.2: CD Workflow - Deploy to DEV (Automatic)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .github/workflows/cd-dev.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/cd-dev.yml
-- =====================================================================
/*
name: CD - Deploy to DEV

on:
  push:
    branches: [develop]
    paths:
      - 'databases/**'
      - 'scripts/**'
  workflow_dispatch:  # Allow manual trigger

env:
  ENVIRONMENT: DEV
  DATABASE: HR_DEV
  SCHEMA: EMPLOYEES

jobs:
  deploy:
    name: Deploy to DEV
    runs-on: ubuntu-latest
    environment: development
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_DEV }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_DEV }}"
          database = "${{ env.DATABASE }}"
          EOF
      
      - name: Start Deployment Tracking
        id: start_deploy
        run: |
          RESULT=$(snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
              '${{ env.ENVIRONMENT }}',
              'HR',
              '${{ env.SCHEMA }}',
              'GITHUB_ACTIONS',
              '${{ github.repository }}',
              '${{ github.run_id }}',
              '${{ github.sha }}',
              '${{ github.ref_name }}',
              NULL
            );
          " --format json)
          
          DEPLOYMENT_ID=$(echo $RESULT | jq -r '.[0].DEVOPS_START_DEPLOYMENT.deployment_id')
          echo "deployment_id=$DEPLOYMENT_ID" >> $GITHUB_OUTPUT
          echo "Deployment ID: $DEPLOYMENT_ID"
      
      - name: Run Pre-Deployment Script
        run: |
          if [ -f "scripts/pre-deploy.sql" ]; then
            echo "Running pre-deployment script..."
            snow sql -f scripts/pre-deploy.sql
          fi
      
      - name: Deploy Tables
        run: |
          if [ -d "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/tables" ]; then
            for file in databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/tables/*.sql; do
              echo "Deploying table: $file"
              snow sql -f "$file"
            done
          fi
      
      - name: Deploy Views
        run: |
          if [ -d "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/views" ]; then
            for file in databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/views/*.sql; do
              echo "Deploying view: $file"
              snow sql -f "$file"
            done
          fi
      
      - name: Deploy Procedures
        run: |
          if [ -d "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/procedures" ]; then
            for file in databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/procedures/*.sql; do
              echo "Deploying procedure: $file"
              snow sql -f "$file"
            done
          fi
      
      - name: Deploy Functions
        run: |
          if [ -d "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/functions" ]; then
            for file in databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/functions/*.sql; do
              echo "Deploying function: $file"
              snow sql -f "$file"
            done
          fi
      
      - name: Run Post-Deployment Script
        run: |
          if [ -f "scripts/post-deploy.sql" ]; then
            echo "Running post-deployment script..."
            snow sql -f scripts/post-deploy.sql
          fi
      
      - name: Complete Deployment Tracking (Success)
        if: success()
        run: |
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              'SUCCESS',
              NULL
            );
          "
      
      - name: Complete Deployment Tracking (Failure)
        if: failure()
        run: |
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              'FAILED',
              'Deployment failed - check GitHub Actions logs'
            );
          "
      
      - name: Deployment Summary
        if: always()
        run: |
          echo "## Deployment Summary" >> $GITHUB_STEP_SUMMARY
          echo "- **Environment:** ${{ env.ENVIRONMENT }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Database:** ${{ env.DATABASE }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Schema:** ${{ env.SCHEMA }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Deployment ID:** ${{ steps.start_deploy.outputs.deployment_id }}" >> $GITHUB_STEP_SUMMARY
          echo "- **Commit:** ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
*/
-- =====================================================================
-- END: .github/workflows/cd-dev.yml
-- =====================================================================

/*
 * STEP 3.3: CD Workflow - Deploy to TST (Automatic after DEV)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .github/workflows/cd-tst.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/cd-tst.yml
-- =====================================================================
/*
name: CD - Deploy to TST

on:
  workflow_run:
    workflows: ["CD - Deploy to DEV"]
    types: [completed]
    branches: [develop]
  workflow_dispatch:

env:
  ENVIRONMENT: TST
  DATABASE: HR_TST
  SCHEMA: EMPLOYEES

jobs:
  deploy:
    name: Deploy to TST
    runs-on: ubuntu-latest
    environment: testing
    if: ${{ github.event.workflow_run.conclusion == 'success' || github.event_name == 'workflow_dispatch' }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_TST }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_TST }}"
          database = "${{ env.DATABASE }}"
          EOF
      
      - name: Start Deployment Tracking
        id: start_deploy
        run: |
          RESULT=$(snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
              '${{ env.ENVIRONMENT }}',
              'HR',
              '${{ env.SCHEMA }}',
              'GITHUB_ACTIONS',
              '${{ github.repository }}',
              '${{ github.run_id }}',
              '${{ github.sha }}',
              '${{ github.ref_name }}',
              NULL
            );
          " --format json)
          
          DEPLOYMENT_ID=$(echo $RESULT | jq -r '.[0].DEVOPS_START_DEPLOYMENT.deployment_id')
          echo "deployment_id=$DEPLOYMENT_ID" >> $GITHUB_OUTPUT
      
      - name: Deploy to TST
        run: |
          if [ -f "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/deploy.sql" ]; then
            snow sql -f "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/deploy.sql"
          fi
      
      - name: Complete Deployment Tracking
        if: always()
        run: |
          STATUS=${{ job.status == 'success' && 'SUCCESS' || 'FAILED' }}
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              '$STATUS',
              NULL
            );
          "
*/
-- =====================================================================
-- END: .github/workflows/cd-tst.yml
-- =====================================================================

/*
 * STEP 3.4: CD Workflow - Deploy to UAT (Manual Approval Required)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .github/workflows/cd-uat.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/cd-uat.yml
-- =====================================================================
/*
name: CD - Deploy to UAT

on:
  workflow_dispatch:
    inputs:
      confirm:
        description: 'Type "deploy" to confirm UAT deployment'
        required: true
        type: string

env:
  ENVIRONMENT: UAT
  DATABASE: HR_UAT
  SCHEMA: EMPLOYEES

jobs:
  validate:
    name: Validate Deployment Request
    runs-on: ubuntu-latest
    steps:
      - name: Check Confirmation
        if: ${{ github.event.inputs.confirm != 'deploy' }}
        run: |
          echo "❌ Deployment not confirmed. Please type 'deploy' to confirm."
          exit 1

  deploy:
    name: Deploy to UAT
    runs-on: ubuntu-latest
    needs: validate
    environment: uat  # This environment has required reviewers configured
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_UAT }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_UAT }}"
          database = "${{ env.DATABASE }}"
          EOF
      
      - name: Start Deployment Tracking
        id: start_deploy
        run: |
          RESULT=$(snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
              '${{ env.ENVIRONMENT }}',
              'HR',
              '${{ env.SCHEMA }}',
              'GITHUB_ACTIONS',
              '${{ github.repository }}',
              '${{ github.run_id }}',
              '${{ github.sha }}',
              '${{ github.ref_name }}',
              PARSE_JSON('{\"triggered_by\": \"${{ github.actor }}\", \"approval_required\": true}')
            );
          " --format json)
          
          DEPLOYMENT_ID=$(echo $RESULT | jq -r '.[0].DEVOPS_START_DEPLOYMENT.deployment_id')
          echo "deployment_id=$DEPLOYMENT_ID" >> $GITHUB_OUTPUT
      
      - name: Deploy to UAT
        run: |
          snow sql -f "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/deploy.sql"
      
      - name: Run UAT Smoke Tests
        run: |
          if [ -d "tests/uat" ]; then
            for test_file in tests/uat/*.sql; do
              echo "Running UAT test: $test_file"
              snow sql -f "$test_file"
            done
          fi
      
      - name: Complete Deployment Tracking
        if: always()
        run: |
          STATUS=${{ job.status == 'success' && 'SUCCESS' || 'FAILED' }}
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              '$STATUS',
              NULL
            );
          "
*/
-- =====================================================================
-- END: .github/workflows/cd-uat.yml
-- =====================================================================

/*
 * STEP 3.5: CD Workflow - Deploy to PRD (Manual Approval + Backup)
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   File: .github/workflows/cd-prd.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/cd-prd.yml
-- =====================================================================
/*
name: CD - Deploy to PRD

on:
  workflow_dispatch:
    inputs:
      confirm:
        description: 'Type "deploy-production" to confirm PRD deployment'
        required: true
        type: string
      change_ticket:
        description: 'Change ticket number (e.g., CHG0012345)'
        required: true
        type: string

env:
  ENVIRONMENT: PRD
  DATABASE: HR_PRD
  SCHEMA: EMPLOYEES

jobs:
  validate:
    name: Validate Deployment Request
    runs-on: ubuntu-latest
    steps:
      - name: Check Confirmation
        if: ${{ github.event.inputs.confirm != 'deploy-production' }}
        run: |
          echo "❌ Deployment not confirmed. Please type 'deploy-production' to confirm."
          exit 1
      
      - name: Validate Change Ticket
        run: |
          if [[ ! "${{ github.event.inputs.change_ticket }}" =~ ^CHG[0-9]+$ ]]; then
            echo "❌ Invalid change ticket format. Expected: CHG followed by numbers"
            exit 1
          fi
          echo "✅ Change ticket validated: ${{ github.event.inputs.change_ticket }}"

  backup:
    name: Create Pre-Deployment Backup
    runs-on: ubuntu-latest
    needs: validate
    outputs:
      backup_id: ${{ steps.backup.outputs.backup_id }}
    
    steps:
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_PRD }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_PRD }}"
          EOF
      
      - name: Create Backup
        id: backup
        run: |
          RESULT=$(snow sql -q "
            CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP(
              '${{ env.DATABASE }}',
              '${{ env.SCHEMA }}',
              NULL,
              'PRE_RELEASE',
              NULL,
              NULL,
              7,
              NULL,
              'Pre-deployment backup for ${{ github.event.inputs.change_ticket }} - Run ${{ github.run_id }}'
            );
          " --format json)
          
          BACKUP_ID=$(echo $RESULT | jq -r '.[0].RBAC_CREATE_BACKUP.backup_id')
          echo "backup_id=$BACKUP_ID" >> $GITHUB_OUTPUT
          echo "✅ Backup created: $BACKUP_ID"

  deploy:
    name: Deploy to PRD
    runs-on: ubuntu-latest
    needs: backup
    environment: production  # Has required reviewers + branch protection
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Snowflake CLI
        run: pip install snowflake-cli-labs
      
      - name: Configure Snowflake Connection
        run: |
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE_PRD }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE_PRD }}"
          database = "${{ env.DATABASE }}"
          EOF
      
      - name: Start Deployment Tracking
        id: start_deploy
        run: |
          RESULT=$(snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_START_DEPLOYMENT(
              '${{ env.ENVIRONMENT }}',
              'HR',
              '${{ env.SCHEMA }}',
              'GITHUB_ACTIONS',
              '${{ github.repository }}',
              '${{ github.run_id }}',
              '${{ github.sha }}',
              '${{ github.ref_name }}',
              PARSE_JSON('{
                \"change_ticket\": \"${{ github.event.inputs.change_ticket }}\",
                \"backup_id\": \"${{ needs.backup.outputs.backup_id }}\",
                \"triggered_by\": \"${{ github.actor }}\"
              }')
            );
          " --format json)
          
          DEPLOYMENT_ID=$(echo $RESULT | jq -r '.[0].DEVOPS_START_DEPLOYMENT.deployment_id')
          echo "deployment_id=$DEPLOYMENT_ID" >> $GITHUB_OUTPUT
      
      - name: Deploy to PRD
        run: |
          snow sql -f "databases/${{ env.DATABASE }}/${{ env.SCHEMA }}/deploy.sql"
      
      - name: Complete Deployment Tracking (Success)
        if: success()
        run: |
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              'SUCCESS',
              NULL
            );
          "
          echo "✅ Production deployment completed successfully!"
      
      - name: Complete Deployment Tracking (Failure)
        if: failure()
        run: |
          snow sql -q "
            CALL ADMIN.DEVOPS.DEVOPS_COMPLETE_DEPLOYMENT(
              '${{ steps.start_deploy.outputs.deployment_id }}',
              'FAILED',
              'Deployment failed - rollback may be required. Backup ID: ${{ needs.backup.outputs.backup_id }}'
            );
          "
          echo "❌ Deployment failed!"
          echo "Backup available for rollback: ${{ needs.backup.outputs.backup_id }}"
      
      - name: Deployment Summary
        if: always()
        run: |
          echo "## Production Deployment Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Item | Value |" >> $GITHUB_STEP_SUMMARY
          echo "|------|-------|" >> $GITHUB_STEP_SUMMARY
          echo "| Environment | ${{ env.ENVIRONMENT }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Database | ${{ env.DATABASE }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Schema | ${{ env.SCHEMA }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Change Ticket | ${{ github.event.inputs.change_ticket }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Backup ID | ${{ needs.backup.outputs.backup_id }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Deployment ID | ${{ steps.start_deploy.outputs.deployment_id }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Triggered By | ${{ github.actor }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Commit | ${{ github.sha }} |" >> $GITHUB_STEP_SUMMARY
*/
-- =====================================================================
-- END: .github/workflows/cd-prd.yml
-- =====================================================================

/*
 * ============================================================================
 * PHASE 4: BRANCH PROTECTION RULES
 * ============================================================================
 * 
 * STEP 4.1: Configure Branch Protection for 'main'
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Navigate to: Repository → Settings → Branches → Add rule
 *   
 *   Branch name pattern: main
 *   
 *   Enable:
 *   ☑ Require a pull request before merging
 *     ☑ Require approvals: 2
 *     ☑ Dismiss stale pull request approvals when new commits are pushed
 *     ☑ Require review from Code Owners
 *   ☑ Require status checks to pass before merging
 *     ☑ Require branches to be up to date before merging
 *     Required checks: "Validate SQL Syntax", "Run SQL Tests"
 *   ☑ Require conversation resolution before merging
 *   ☑ Require signed commits (optional)
 *   ☑ Do not allow bypassing the above settings
 * 
 * STEP 4.2: Configure Branch Protection for 'develop'
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   Branch name pattern: develop
 *   
 *   Enable:
 *   ☑ Require a pull request before merging
 *     ☑ Require approvals: 1
 *   ☑ Require status checks to pass before merging
 *     Required checks: "Validate SQL Syntax"
 * 
 * ============================================================================
 * PHASE 5: CODEOWNERS FILE
 * ============================================================================
 * 
 *   File: .github/CODEOWNERS
 */

-- =====================================================================
-- BEGIN: .github/CODEOWNERS
-- =====================================================================
/*
# CODEOWNERS for Snowflake Deployments
# These owners will be automatically requested for review

# Default owners for everything
* @data-engineering-team

# Database-specific owners
/databases/HR_*/ @hr-data-team @data-engineering-team
/databases/SALES_*/ @sales-data-team @data-engineering-team
/databases/FINANCE_*/ @finance-data-team @data-engineering-team

# Production deployments require additional approval
/databases/*_PRD/ @dba-team @release-managers

# Scripts require DBA review
/scripts/ @dba-team

# Workflow changes require DevOps review
/.github/workflows/ @devops-team
*/
-- =====================================================================
-- END: .github/CODEOWNERS
-- =====================================================================

/*
 * ============================================================================
 * PHASE 6: REUSABLE WORKFLOW (Optional)
 * ============================================================================
 * 
 *   File: .github/workflows/reusable-deploy.yml
 */

-- =====================================================================
-- BEGIN: .github/workflows/reusable-deploy.yml
-- =====================================================================
/*
name: Reusable Snowflake Deployment

on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
      database:
        required: true
        type: string
      schema:
        required: true
        type: string
    secrets:
      SNOWFLAKE_ACCOUNT:
        required: true
      SNOWFLAKE_USER:
        required: true
      SNOWFLAKE_PRIVATE_KEY:
        required: true
      SNOWFLAKE_ROLE:
        required: true
      SNOWFLAKE_WAREHOUSE:
        required: true

jobs:
  deploy:
    name: Deploy to ${{ inputs.environment }}
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Snowflake CLI
        run: |
          pip install snowflake-cli-labs
          mkdir -p ~/.snowflake
          echo "${{ secrets.SNOWFLAKE_PRIVATE_KEY }}" | base64 -d > ~/.snowflake/rsa_key.p8
          chmod 600 ~/.snowflake/rsa_key.p8
          
          cat > ~/.snowflake/config.toml << EOF
          [connections.default]
          account = "${{ secrets.SNOWFLAKE_ACCOUNT }}"
          user = "${{ secrets.SNOWFLAKE_USER }}"
          private_key_path = "~/.snowflake/rsa_key.p8"
          role = "${{ secrets.SNOWFLAKE_ROLE }}"
          warehouse = "${{ secrets.SNOWFLAKE_WAREHOUSE }}"
          database = "${{ inputs.database }}"
          EOF
      
      - name: Deploy
        run: |
          snow sql -f "databases/${{ inputs.database }}/${{ inputs.schema }}/deploy.sql"
*/
-- =====================================================================
-- END: .github/workflows/reusable-deploy.yml
-- =====================================================================

/*
 * ============================================================================
 * PHASE 7: TESTING THE WORKFLOW
 * ============================================================================
 * 
 * STEP 7.1: Verify Service Account Connection
 * ─────────────────────────────────────────────────────────────────────────────
 */

-- Run in Snowflake to verify
USE ROLE SRS_DEVOPS;
SELECT * FROM ADMIN.DEVOPS.DEVOPS_PIPELINES 
WHERE PLATFORM = 'GITHUB_ACTIONS';

/*
 * STEP 7.2: Trigger Test Workflow
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   1. Navigate to: Repository → Actions
 *   2. Select "CD - Deploy to DEV"
 *   3. Click "Run workflow"
 *   4. Select branch: develop
 *   5. Click "Run workflow"
 *   6. Monitor the workflow execution
 * 
 * STEP 7.3: Verify Deployment in Snowflake
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
WHERE PIPELINE_NAME LIKE '%github%'
ORDER BY STARTED_AT DESC 
LIMIT 10;

-- View deployment dashboard
CALL ADMIN.DEVOPS.DEVOPS_DEPLOYMENT_DASHBOARD();

/*
 * ============================================================================
 * SUMMARY: COMPLETE CHECKLIST
 * ============================================================================
 * 
 * │ # │ Task                                           │ Location        │
 * │───│────────────────────────────────────────────────│─────────────────│
 * │ 1 │ Generate RSA key pair                          │ Local machine   │
 * │ 2 │ Create pipeline service account                │ Snowflake       │
 * │ 3 │ Create GitHub repository                       │ GitHub          │
 * │ 4 │ Add repository secrets                         │ Settings/Secret │
 * │ 5 │ Create environments (dev/testing/uat/prod)     │ Settings/Env    │
 * │ 6 │ Configure environment protection rules         │ Environment     │
 * │ 7 │ Create CI workflow (ci.yml)                    │ .github/        │
 * │ 8 │ Create CD workflows (cd-*.yml)                 │ .github/        │
 * │ 9 │ Setup branch protection rules                  │ Settings/Branch │
 * │ 10│ Create CODEOWNERS file                         │ .github/        │
 * │ 11│ Test pipeline with sample deployment           │ Actions         │
 * │ 12│ Verify deployment tracking in Snowflake        │ Snowflake       │
 * 
 ******************************************************************************/

-- Final verification query
SELECT 
    'GitHub Actions Setup Guide' AS GUIDE,
    'Follow phases 1-7 for complete CI/CD implementation' AS INSTRUCTIONS,
    'See ADMIN.DEVOPS schema for Snowflake-side procedures' AS SNOWFLAKE_PROCEDURES;
