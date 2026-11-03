# Cloud Run cost planning

Cloud Run can scale to zero when idle. This does **not** guarantee a $0 invoice. Confirm current Tokyo-region prices and free-tier eligibility using the official Google Cloud pricing calculator.

| Monthly scans | Illustrative average request duration | Total request-seconds |
|---|---:|---:|
| 100 | 30 s | 3,000 |
| 500 | 30 s | 15,000 |
| 1,000 | 30 s | 30,000 |

At 1 vCPU and 1 GiB, these correspond to approximately 3,000 / 15,000 / 30,000 vCPU-seconds and GiB-seconds, **assuming no additional billed startup/idle time and one instance per request**. These are usage estimates, not prices or guaranteed invoice amounts. Actual scans may be much slower, and request-based billing has additional rules.

Include Cloud Run compute and requests, Cloud Build, Artifact Registry storage, outbound internet traffic, Cloud Logging, and the selected custom-domain frontend in the estimate. Domain registration and renewal at お名前.com are separate. External load balancing may add fixed hourly costs.

Create a small Google Cloud budget with alert thresholds (for example 50%, 90%, 100%) and check billing regularly. Budgets are notifications, not hard caps. Limit Cloud Run instances, request concurrency, clone size, and request timeout; add application-level rate limiting if public usage grows.
