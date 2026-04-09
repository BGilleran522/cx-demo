# Coralogix TAM Technical Assessment

A production-grade observability setup for OpenTelemetry Demo on GKE, featuring Kubernetes metadata enrichment, log parsing rules, Events2Metrics, custom dashboards, intelligent alerting, and cost optimization — all managed as Infrastructure as Code with Pulumi.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              otel-demo namespace          │
                    │                                          │
                    │  frontend ──► checkout ──► payment       │
                    │      │           │           │           │
                    │      ▼           ▼           ▼           │
                    │  cart        shipping     email          │
                    │  recommendation  currency  ad            │
                    │  product-catalog                         │
                    │      │                                   │
                    │      ▼ (Kafka)                           │
                    │  accounting   fraud-detection             │
                    │      │                                   │
                    │      ▼                                   │
                    │  otel-demo collector (Deployment)         │
                    │  - spanmetrics connector                  │
                    │  - OTLP exporter ─────────────────┐      │
                    └───────────────────────────────────┼──────┘
                                                        │
                                                  OTLP gRPC :4317
                                                        │
                    ┌───────────────────────────────────┼──────┐
                    │         coralogix namespace        │      │
                    │                                    ▼      │
                    │  Cluster Collector (Deployment) ◄──┘      │
                    │  - K8s events, cluster metrics            │
                    │  - API server metrics                     │
                    │  - OTLP receiver (port 4317)              │
                    │  - Coralogix exporter ──────────────┐     │
                    │                                     │     │
                    │  Node Agent (DaemonSet, per node)    │     │
                    │  - Log collection (container logs)   │     │
                    │  - Host/kubelet metrics              │     │
                    │  - eBPF instrumentation              │     │
                    │  - Coralogix exporter ──────────┐    │     │
                    └─────────────────────────────────┼────┼─────┘
                                                      │    │
                                                      ▼    ▼
                                              ┌────────────────┐
                                              │   Coralogix    │
                                              │  (Your Region) │
                                              │                │
                                              │  Logs          │
                                              │  Metrics       │
                                              │  Traces        │
                                              └────────────────┘
```

The otel-demo collector forwards telemetry to the Coralogix cluster collector via OTLP, which handles enrichment and export. This mirrors real-world customer architectures where application teams ship OTLP to a central collector.

## Prerequisites

- **GCP account** with an active GKE cluster
- **Coralogix account** (any region: EU1, EU2, US1, US2, AP1, AP2, AP3)
- **Pulumi CLI** (`>= 3.0`)
- **Go 1.25+**
- **Helm 3.x**
- **kubectl** configured to access your GKE cluster

## Quick Start

### 1. Deploy Coralogix Integration

```bash
kubectl create namespace coralogix
helm repo add coralogix https://coralogix.jfrog.io/artifactory/api/helm/coralogix-helm-charts
helm install coralogix-otel coralogix/opentelemetry-integration \
  -n coralogix \
  -f cx-values.yaml
```

Verify deployment:
```bash
kubectl get pods -n coralogix
```

### 2. Deploy OpenTelemetry Demo

```bash
kubectl create namespace otel-demo
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm install otel-demo open-telemetry/opentelemetry-demo \
  -n otel-demo \
  -f otel-demo-values.yaml
```

Wait for all pods to be ready (27 pods across 14 microservices):
```bash
kubectl rollout status deployment -n otel-demo --timeout=300s
```

### 3. Deploy Pulumi Stack

```bash
cd coralogix-pulumi
pulumi config set coralogix:env <YOUR_REGION>
pulumi config set --secret coralogix:apiKey "your-api-key"
pulumi up
```

This deploys:
- **Parsing Rules** (9 rules across 7 sub-groups)
- **Enrichments** (Geo IP, Suspicious IP, Custom CSV product lookup)
- **Events2Metrics** (3 metric definitions)
- **Dashboards** (4 custom dashboards)
- **Alerts** (5 threshold + flow alerts)
- **Recording Rules** (pre-computed metrics)
- **TCO Policies** (3-tier cost optimization)

## What Gets Deployed

| Resource Type | Count | Details |
|---|---|---|
| **Parsing Rules** | 9 | Email access logs, cart operations, gRPC errors, PCI redaction, noise blocking, severity extraction |
| **Enrichments** | 3 | Geo IP on client_ip, Suspicious IP threat intel, Custom CSV product lookup |
| **Events2Metrics** | 3 | Email response time (histogram), cart actions (counter), fraud checks (counter) |
| **Dashboards** | 4 | Full Stack Observability (SRE), Executive Business, Developer & Debugging, Enrichment Intelligence |
| **Alerts** | 6 | 3 threshold (logs), 1 helper, 1 flow (cascading checkout→payment), 1 tracing (latency p95) |
| **Recording Rules** | 2 | Checkout success rate, orders per minute |
| **TCO Policies** | 3 | High (business-critical), Medium (source data), Low (supporting services) |

## Project Structure

```
├── README.md                          # This file
├── cx-values.yaml                     # Coralogix K8s integration Helm values
├── otel-demo-values.yaml              # OTel Demo Helm values (with feature flags enabled)
├── coralogix-setup/
│   ├── main.go                        # Go script: REST API approach (reference)
│   └── go.mod                         # Go module (stdlib only)
├── coralogix-pulumi/
│   ├── main.go                        # Pulumi program (primary IaC)
│   ├── Pulumi.yaml                    # Pulumi project config
│   ├── products.csv                   # Product lookup table (10 items)
│   └── sdks/                          # Generated Coralogix Pulumi provider SDK
```

## Feature Flags

The OTel Demo includes `flagd` for injecting realistic failures. These are enabled in `otel-demo-values.yaml`:

| Flag | Service | Effect |
|---|---|---|
| `cartServiceFailure` | Cart | Errors on every `EmptyCart` call |
| `productCatalogFailure` | Product Catalog | Errors on `GetProduct` for specific product |
| `paymentServiceFailure` | Payment | Errors on `charge` method — drops checkout success rate |
| `recommendationServiceCacheFailure` | Recommendation | Memory leak (1.4x exponential growth) |
| `kafkaQueueProblems` | Kafka | Consumer lag spikes |

These create realistic failure conditions that trigger dashboards and alerts. To enable flags manually:

```bash
helm upgrade otel-demo open-telemetry/opentelemetry-demo \
  -n otel-demo -f otel-demo-values.yaml
```

## Troubleshooting

### 1. DaemonSet Port Conflict
**Problem:** OTLP receiver port 4317 collision between otel-demo and Coralogix agents.
**Fix:** Set otel-demo collector to `mode: deployment` (not DaemonSet).

### 2. Coralogix Exporter Not in Demo Image
**Problem:** otel-demo collector image lacks the vendor-specific Coralogix exporter.
**Fix:** Use standard OTLP exporter → forward to Coralogix cluster collector at `coralogix-opentelemetry-collector.coralogix.svc.cluster.local:4317`.

### 3. OTel Collector Memory Backpressure
**Problem:** Services log "data refused due to high memory usage" — collector rejecting telemetry.
**Status:** Alerting configured. Increase collector memory limits or add rate-limiting/sampling.

### 4. Accounting Service Crash-Looping
**Problem:** Accounting pod restarted 66 times in 21 hours (likely OOMKilled).
**Status:** Alerting configured. Increase memory limit or optimize Kafka consumer batch size.

### 5. Trial Account Rule Group Limit
**Problem:** Trial accounts allow only 1 parsing rule group.
**Fix:** Consolidated all rules into a single group with 7 sub-groups. Regex patterns are specific enough to avoid false matches.

## References

### Key Documentation
- [Kubernetes Observability using OpenTelemetry](https://coralogix.com/docs/opentelemetry/kubernetes-observability/kubernetes-observability-using-opentelemetry/)
- [Log Parsing Rules](https://coralogix.com/docs/user-guides/data-transformation/parsing/log-parsing-rules/)
- [Events2Metrics](https://coralogix.com/docs/user-guides/monitoring-and-insights/events2metrics/)
- [Custom Dashboards](https://coralogix.com/docs/user-guides/custom-dashboards/introduction/)
- [Alerts & Flow Alerts](https://coralogix.com/docs/user-guides/alerting/introduction-to-alerts/)
- [Coralogix Terraform Provider](https://registry.terraform.io/providers/coralogix/coralogix/latest/docs)
- [Pulumi Coralogix Provider](https://www.pulumi.com/registry/packages/coralogix/)

### Academy Courses
- [Coralogix User Certification](https://academy.coralogix.com/p/platform-introduction)
- [Parsing & Data Transformation](https://coralogix.com/academy/get-to-know-coralogix/parse/)
- [Events2Metrics Querying](https://coralogix.com/academy/mastering-metrics-in-coralogix/events2metrics-querying/)
- [Enriching IP Addresses](https://coralogix.com/academy/edge-and-waf-monitoring-security/coralogix-edge-waf-academy-enriching-ip-addresses-with-geo-locational-information/)

---

**Author:** Bill Gilleran
**Assignment:** Coralogix TAM Technical Assessment
