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
