package main

import (
	"coralogix-otel-demo/internal/config"
	"coralogix-otel-demo/internal/coralogix"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.Load(ctx)

		// 1. Parsing rules — create the fields everything else depends on
		if err := coralogix.DeployRules(ctx, cfg); err != nil {
			return err
		}

		// 2. Alerts — includes flow alert (wires its own dependencies internally)
		if _, err := coralogix.DeployAlerts(ctx, cfg); err != nil {
			return err
		}

		// 3. Dashboards — query the parsed and enriched data
		if err := coralogix.DeployDashboards(ctx, cfg); err != nil {
			return err
		}

		// 4. Events2Metrics — log fields → Prometheus metrics
		if err := coralogix.DeployE2M(ctx, cfg); err != nil {
			return err
		}

		// 5. Enrichments — Geo IP, Suspicious IP, Custom CSV
		if err := coralogix.DeployEnrichments(ctx, cfg); err != nil {
			return err
		}

		// 6. Recording rules — pre-computed PromQL
		if err := coralogix.DeployRecordingRules(ctx, cfg); err != nil {
			return err
		}

		// 7. TCO policies — data tiering by business value
		if err := coralogix.DeployTCOPolicies(ctx, cfg); err != nil {
			return err
		}

		ctx.Export("note", pulumi.String("All resources deployed via IaC: rules, alerts (incl. tracing), dashboards, E2M, enrichments, recording rules, TCO policies."))
		return nil
	})
}
