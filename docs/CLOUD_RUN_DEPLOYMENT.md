# AIBOM Inspector — Cloud Run deployment

This deployment keeps FastAPI and the bundled static web UI together in one container. No Cloudflare or Vercel is required. The existing Dockerfile honors Cloud Run's `PORT` and runs as an unprivileged user.

## Prerequisites

- A Google Cloud project with billing enabled
- Google Cloud CLI (`gcloud`) installed and authenticated with `gcloud auth login`
- Permissions to enable APIs, build images, deploy Cloud Run, and manage the service
- Domain `aibom-inspector.com` registered at お名前.com

## Deploy

From the repository root:

```bash
export GCP_PROJECT_ID="YOUR_PROJECT_ID"
bash scripts/deploy-cloud-run.sh
```

The script prompts before creating resources. It uses Tokyo (`asia-northeast1`), zero minimum instances, one maximum instance, 1 vCPU, 1 GiB memory, concurrency 1, and a 300-second request timeout. Source deployments may create an Artifact Registry repository and incur build and storage charges. Verify available quota and CPU allocation/billing configuration in the Google Cloud console. Do not assume this setup is free.

After deployment, open the generated `https://...run.app` URL and verify:

- `GET /api/health` returns `status: ok`
- The web UI loads at `/`
- Built-in demo completes
- A small public GitHub repository can be scanned
- A drift demo completes

## Automatic deployment from `main`

`.github/workflows/deploy-cloud-run.yml` deploys every commit on `main` once
CI has passed on it, by running the same `scripts/deploy-cloud-run.sh`
(`--non-interactive`), then checks `/api/health` and the built-in demo on the
new revision. It can also be started by hand (*Actions → Deploy to Cloud Run →
Run workflow*, `main` only). Merging to `main` therefore publishes the site.

No key is stored in GitHub. The workflow exchanges GitHub's OIDC token for a
short-lived credential through Workload Identity Federation, and the provider
below accepts only this repository's deploy workflow running on `main`.
Until the repository variables exist, the job is skipped.

One-time setup, run by a project owner (Cloud Shell works):

```bash
PROJECT_ID="YOUR_PROJECT_ID"
REPO="d01ki/AIBOM-Inspector"
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
SA="github-deployer@${PROJECT_ID}.iam.gserviceaccount.com"

# 1. A deploy-only service account.
gcloud iam service-accounts create github-deployer --project "$PROJECT_ID" \
  --display-name "GitHub Actions: deploy to Cloud Run"
for role in roles/run.sourceDeveloper roles/serviceusage.serviceUsageConsumer \
            roles/logging.viewer; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member "serviceAccount:${SA}" --role "$role" --condition None
done
# It deploys revisions that run as the default compute service account.
gcloud iam service-accounts add-iam-policy-binding \
  "${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" --project "$PROJECT_ID" \
  --member "serviceAccount:${SA}" --role roles/iam.serviceAccountUser

# 2. Workload Identity Federation for GitHub, limited to the deploy workflow on main.
gcloud iam workload-identity-pools create github --project "$PROJECT_ID" \
  --location global --display-name "GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc aibom-inspector \
  --project "$PROJECT_ID" --location global --workload-identity-pool github \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "assertion.repository == '${REPO}' && assertion.job_workflow_ref == '${REPO}/.github/workflows/deploy-cloud-run.yml@refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding "$SA" --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/attribute.repository/${REPO}"

# 3. Tell the workflow where to deploy (repository variables, not secrets).
gh variable set GCP_PROJECT_ID --repo "$REPO" --body "$PROJECT_ID"
gh variable set GCP_DEPLOY_SA --repo "$REPO" --body "$SA"
gh variable set GCP_WIF_PROVIDER --repo "$REPO" \
  --body "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/providers/aibom-inspector"
# Optional, if they differ from the defaults: GCP_REGION (asia-northeast1),
# GCP_SERVICE (aibom-inspector).
```

Optional: require a person to approve each deploy under *Settings →
Environments → production → Required reviewers*. To stop automatic deploys,
delete the `GCP_PROJECT_ID` variable (the job is then skipped), or disable the
workflow. To roll back, shift traffic to an earlier revision in Cloud Run.

## Domain mapping without Cloudflare

The simplest configuration is an eligible **Cloud Run domain mapping** where available. This feature is preview and Google does not recommend it for production workloads; check current region availability and restrictions before selecting it. In Cloud Run, open **Domain mappings**, verify ownership of `aibom-inspector.com`, and follow the exact DNS records Google provides. Create those records in お名前.com DNS management. Do not invent A/AAAA/CNAME values. Wait for the Google-managed TLS certificate to become active. Apex and `www` may require separate mappings/records.

If domain mapping is unavailable or unsuitable, evaluate **Firebase Hosting in front of Cloud Run** (rewrite proxy) as an alternative, with its own pricing, limits, and domain verification. A Google Cloud external Application Load Balancer is another production option but can introduce material fixed costs. Do not provision one solely for a low-budget demo without reviewing charges.

## Security and operational notes

- Public access means anyone can trigger analysis. Cloud Run's maximum instance count is **not** a hard spending cap. Set a Google Cloud budget and alerts; alerts do not automatically stop billing.
- The current scanner already restricts repository URLs to selected public forges, uses shallow clones and timeouts, and deletes temporary checkout directories. Review DNS redirect behavior and upstream enrichment requests before treating it as hardened against all SSRF/resource exhaustion.
- `AIBOM_MAX_CLONE_MB=100` and `AIBOM_MAX_CLONE_FILES=15000` reduce checkout size. They are not network transfer caps.
- `--concurrency 1` limits simultaneous requests **per instance**, not the number of total requests. A public endpoint can still be abused; consider rate limiting or authenticated access before a high-profile event.
- Source scanning and enrichment can take longer than a browser or upstream proxy timeout. Test with realistic repositories.
- Do not store secrets in repository files or CLI arguments. Use Secret Manager and a least-privilege service account for any future credentials.
- To roll back, use Cloud Run **Revisions** to shift traffic to a previously verified revision.
- To avoid ongoing charges after the event, remove unused services, images, and build artifacts.

## Local smoke test

```bash
docker build -t aibom-inspector .
docker run --rm -p 8080:8080 -e PORT=8080 aibom-inspector
curl -f http://localhost:8080/api/health
```

Domain setup and live deployment require access to your own Google Cloud and お名前.com accounts; the GitHub change alone does not publish the website.
