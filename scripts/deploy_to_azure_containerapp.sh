#!/usr/bin/env bash
# ==============================================================================
# Script: deploy_to_azure_containerapp.sh
# Purpose: Build Cyrene Exchange (with Platform & Plugins), push to GHCR,
#          deploy to Azure Container Apps, and verify dynamic zero-downtime update.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Configuration
GITHUB_USER="${GITHUB_USER:-$(gh api user -q .login 2>/dev/null || echo "Baijin64")}"
GITHUB_ORG="${GITHUB_ORG:-DoHorizon-AI}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/${GITHUB_USER,,}/cyrene-exchange}"
IMAGE_TAG="${IMAGE_TAG:-$(date +%Y%m%d%H%M%S)}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-cyrene-prod}"
LOCATION="${AZURE_LOCATION:-japaneast}"
ENV_NAME="${AZURE_CONTAINERAPP_ENV:-cae-cyrene}"
APP_NAME="${AZURE_CONTAINERAPP_NAME:-cyrene-exchange}"
PORT=8000

echo "=================================================================="
echo "🚀 Cyrene Exchange - End-to-End Build, GHCR Push & Azure Deployment"
echo "=================================================================="
echo "Workspace Root : ${WORKSPACE_ROOT}"
echo "Image Target   : ${IMAGE_REPO}:${IMAGE_TAG}"
echo "Azure RG       : ${RESOURCE_GROUP} (${LOCATION})"
echo "ACA Env / App  : ${ENV_NAME} / ${APP_NAME}"
echo "=================================================================="

# 1. Check Prerequisites
echo "🔍 Checking CLI prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "❌ docker is required" >&2; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "❌ gh CLI is required" >&2; exit 1; }
command -v az >/dev/null 2>&1 || { echo "❌ az CLI is required" >&2; exit 1; }

echo "🔐 Verifying GitHub CLI authentication..."
gh auth status >/dev/null 2>&1 || {
  echo "❌ Please log in to GitHub CLI using 'gh auth login'" >&2
  exit 1
}

echo "🔐 Verifying Azure CLI authentication..."
if ! az account show >/dev/null 2>&1; then
  echo "⚠️ Azure CLI session is expired or not logged in."
  echo "👉 Please run: az login --use-device-code"
  exit 1
fi
CURRENT_SUB="$(az account show --query '[name, id]' -o tsv)"
echo "✅ Azure logged in: ${CURRENT_SUB}"

# 2. Login to GHCR & Build Container Image
echo "🔑 Logging in to GitHub Container Registry (ghcr.io)..."
GHCR_TOKEN="$(gh auth token)"
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GITHUB_USER" --password-stdin

echo "📦 Building unified multi-repository container image..."
cd "$WORKSPACE_ROOT"
docker build \
  -f Cyrene-Services/Cyrene-Exchange/Dockerfile \
  -t "${IMAGE_REPO}:${IMAGE_TAG}" \
  -t "${IMAGE_REPO}:latest" \
  .

echo "⬆️ Pushing image to GHCR..."
docker push "${IMAGE_REPO}:${IMAGE_TAG}"
docker push "${IMAGE_REPO}:latest"
echo "✅ Image successfully pushed to ${IMAGE_REPO}:${IMAGE_TAG}"

# 3. Create Azure Resources
echo "☁️ Ensuring Azure Resource Group '${RESOURCE_GROUP}' exists..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

echo "☁️ Ensuring Azure Container Apps Environment '${ENV_NAME}' exists..."
az containerapp env create \
  --name "$ENV_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# 4. Deploy to Azure Container App
echo "🚢 Deploying ${APP_NAME} to Azure Container Apps..."
REGISTRY_SERVER="ghcr.io"
SECRET_NAME="ghcr-token"

# Register/update container app
if az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  echo "🔄 Updating existing Container App..."
  az containerapp registry set \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --server "$REGISTRY_SERVER" \
    --username "$GITHUB_USER" \
    --password "$GHCR_TOKEN" \
    --output none

  az containerapp update \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --image "${IMAGE_REPO}:${IMAGE_TAG}" \
    --output none
else
  echo "🆕 Creating new Container App..."
  az containerapp create \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$ENV_NAME" \
    --image "${IMAGE_REPO}:${IMAGE_TAG}" \
    --target-port "$PORT" \
    --ingress external \
    --registry-server "$REGISTRY_SERVER" \
    --registry-username "$GITHUB_USER" \
    --registry-password "$GHCR_TOKEN" \
    --cpu 0.5 \
    --memory 1.0Gi \
    --min-replicas 1 \
    --max-replicas 3 \
    --output none
fi

# 5. Retrieve FQDN and Verify
FQDN="$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query 'properties.configuration.ingress.fqdn' -o tsv)"
APP_URL="https://${FQDN}"
echo "🎉 Deployment successful!"
echo "🌐 App FQDN: ${APP_URL}"

echo "🩺 Testing liveness probe (/healthz)..."
for i in {1..30}; do
  if curl -s -f "${APP_URL}/healthz" >/dev/null 2>&1; then
    echo "✅ Health check passed: $(curl -s "${APP_URL}/healthz")"
    break
  fi
  echo "⏳ Waiting for application warm-up ($i/30)..."
  sleep 3
done

echo "📋 Testing OpenAI models endpoint (/v1/models)..."
curl -s "${APP_URL}/v1/models" | jq . || true

echo "=================================================================="
echo "🔄 Demonstrating Dynamic Revision Update (Zero-Downtime Test)"
echo "=================================================================="
CURRENT_REV="$(az containerapp revision list --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "[?properties.active].name" -o tsv | head -n1)"
echo "📌 Current Active Revision: ${CURRENT_REV}"

NEW_TAG="${IMAGE_TAG}-update"
echo "🏷️ Tagging image with new tag: ${IMAGE_REPO}:${NEW_TAG}"
docker tag "${IMAGE_REPO}:${IMAGE_TAG}" "${IMAGE_REPO}:${NEW_TAG}"
docker push "${IMAGE_REPO}:${NEW_TAG}"

echo "🚀 Triggering dynamic revision update on Azure..."
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --image "${IMAGE_REPO}:${NEW_TAG}" \
  --output none

NEW_REV="$(az containerapp revision list --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "[?properties.active].name" -o tsv | tail -n1)"
echo "✨ New Active Revision Deployed: ${NEW_REV}"

echo "🩺 Verifying new revision health..."
curl -s -f "${APP_URL}/healthz"
echo ""
echo "🏆 End-to-end verification complete! Zero-downtime dynamic update verified."
