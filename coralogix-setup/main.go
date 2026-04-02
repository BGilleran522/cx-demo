package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration — set via environment variables
// ---------------------------------------------------------------------------

type Config struct {
	APIKey     string // Personal API key with Alerts + ParsingRules roles
	Region     string // e.g. "eu1", "us1", "us2", "eu2", "ap1", "ap2", "ap3"
	BaseURL    string // derived from Region
	RulesURL   string // v1 rules endpoint
	AlertsURL  string // v2 alerts endpoint
	DashURL    string // OpenAPI dashboards endpoint
	E2MURL     string // Events2Metrics endpoint
}

var regionDomains = map[string]string{
	"eu1": "coralogix.com",
	"eu2": "eu2.coralogix.com",
	"us1": "coralogix.us",
	"us2": "cx498.coralogix.com",
	"ap1": "coralogix.in",
	"ap2": "coralogixsg.com",
	"ap3": "ap3.coralogix.com",
}

func loadConfig() Config {
	apiKey := os.Getenv("CX_API_KEY")
	if apiKey == "" {
		log.Fatal("CX_API_KEY environment variable is required")
	}
	region := os.Getenv("CX_REGION")
	if region == "" {
		region = "eu1"
	}
	domain, ok := regionDomains[region]
	if !ok {
		log.Fatalf("Unknown region %q. Use one of: eu1, eu2, us1, us2, ap1, ap2, ap3", region)
	}

	// E2M uses ng-api-http endpoints, not the standard api. endpoints
	e2mDomains := map[string]string{
		"eu1": "ng-api-http.coralogix.com",
		"eu2": "ng-api-http.eu2.coralogix.com",
		"us1": "ng-api-http.coralogix.us",
		"us2": "ng-api-http.cx498.coralogix.com",
		"ap1": "ng-api-http.app.coralogix.in",
		"ap2": "ng-api-http.coralogixsg.com",
		"ap3": "ng-api-http.cx498-aws-ap-northeast-1.coralogix.com",
	}

	return Config{
		APIKey:    apiKey,
		Region:    region,
		BaseURL:   fmt.Sprintf("https://api.%s", domain),
		RulesURL:  fmt.Sprintf("https://api.%s/api/v1/external/rule/rule-set", domain),
		AlertsURL: fmt.Sprintf("https://api.%s/api/v2/external/alerts", domain),
		DashURL:   fmt.Sprintf("https://api.%s/mgmt/openapi/latest/v1/dashboards/dashboards", domain),
		E2MURL:    fmt.Sprintf("https://%s/events2metrics/events2metrics/v2", e2mDomains[region]),
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func doRequest(method, url, apiKey string, body interface{}) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

func postJSON(url, apiKey string, payload interface{}) (map[string]interface{}, error) {
	body, status, err := doRequest("POST", url, apiKey, payload)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Some endpoints return non-JSON on success
		return map[string]interface{}{"raw": string(body)}, nil
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// 1. PARSING RULES
// ---------------------------------------------------------------------------

// createParsingRules creates a single consolidated rule group (trial accounts
// are limited to 1 group). All rules live in separate sub-groups within that
// group. Extract rules that don't match a given log line are harmless no-ops.
// No ruleMatchers are set so the group applies to all subsystems.
func createParsingRules(cfg Config) {
	fmt.Println("\n========== CREATING PARSING RULES ==========")

	// Rule group structure:
	//   Sub-group 1: JSON Extract (body → Text) — AND —
	//   Sub-group 2: All Extract/Block rules (OR between them)
	//
	// The JSON Extract runs first on every log (AND), replacing Text with
	// just the body content. Then whichever OR rule matches the body fires.
	ruleGroup := map[string]interface{}{
		"name":        "OTel Demo - All Services",
		"description": "JSON Extract (body→Text) AND then OR-chain: cart parser, fraud parser, checkout gRPC parser, email access log parser, ad noise block.",
		"enabled":     true,
		"rulesGroups": []map[string]interface{}{
			// ── Sub-group 1: JSON Extract body → Text (AND with sub-group 2) ──
			{
				"order": 1,
				"rules": []map[string]interface{}{
					{
						"name":            "Extract body to Text",
						"description":     "Extracts the OTel log body field into Coralogix Text, giving downstream rules clean text to parse.",
						"enabled":         true,
						"type":            "jsonextract",
						"sourceField":     "text",
						"destinationField": "text",
						"rule":            "body",
						"order":           1,
					},
				},
			},
			// ── Sub-group 2: All service rules (OR logic between rules) ──
			{
				"order": 2,
				"rules": []map[string]interface{}{
					// Cart — extracts cart_action, user_id, product_id, quantity
					{
						"name":        "Cart - Extract operation fields",
						"description": "Extracts cart_action, user_id, product_id, quantity from cart service logs.",
						"enabled":     true,
						"type":        "extract",
						"sourceField": "text",
						"rule":        `(?P<cart_action>\w+Async) called with userId=(?P<user_id>[^,\s]*)(?:, productId=(?P<product_id>[^,\s]*))?(?:, quantity=(?P<quantity>\d+))?`,
						"order":       1,
					},
					// Fraud detection — extracts order_id, total_count
					{
						"name":        "Fraud - Extract order fields",
						"description": "Extracts order_id and total_count from fraud-detection Kafka consumer logs.",
						"enabled":     true,
						"type":        "extract",
						"sourceField": "text",
						"rule":        `orderId: (?P<order_id>[^,]+), and updated total count to: (?P<total_count>\d+)`,
						"order":       2,
					},
					// Checkout — extracts grpc_code, grpc_status, error_message
					{
						"name":        "Checkout - Extract gRPC error fields",
						"description": "Extracts grpc_code, grpc_status, error_message from checkout connection errors.",
						"enabled":     true,
						"type":        "extract",
						"sourceField": "text",
						"rule":        `Error: (?P<grpc_code>\d+) (?P<grpc_status>\w+): (?P<error_message>.+)`,
						"order":       3,
					},
					// Email — extracts client_ip, method, path, status, response_time
					{
						"name":        "Email - Extract access log fields",
						"description": "Extracts client_ip, method, path, status, response_time. IP feeds Geo/Security enrichment; response_time feeds E2M.",
						"enabled":     true,
						"type":        "extract",
						"sourceField": "text",
						"rule":        `(?P<client_ip>\d+\.\d+\.\d+\.\d+) - - \[[^\]]+\] ..(?P<method>\w+) (?P<path>\S+) \S+ (?P<status>\d{3}) - (?P<response_time>[\d.]+)`,
						"order":       4,
					},
					// Ad — blocks "no baggage found in context" noise
					{
						"name":        "Ad - Block 'no baggage' noise",
						"description": "Drops 'no baggage found in context' — fires every request, doubles volume, zero value.",
						"enabled":     true,
						"type":        "block",
						"sourceField": "text",
						"rule":        `no baggage found in context`,
						"order":       5,
					},
				},
			},
		},
	}

	fmt.Printf("  Creating rule group: %s ... ", ruleGroup["name"])
	result, err := postJSON(cfg.RulesURL, cfg.APIKey, ruleGroup)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	fmt.Printf("OK %v\n", extractID(result))
	fmt.Println("  (2 sub-groups: JSON Extract AND 5 OR-chained rules)")
}

// ---------------------------------------------------------------------------
// 2. ALERTS
// ---------------------------------------------------------------------------

func createAlerts(cfg Config) {
	fmt.Println("\n========== CREATING ALERTS ==========")

	// We'll create 3 standard alerts first, then a flow alert referencing them.
	var alertIDs []string

	standardAlerts := []map[string]interface{}{
		// ── Alert 1: OTel Collector Backpressure ──
		{
			"name":        "OTel Collector - High Memory Backpressure",
			"description": "Fires when the OTel collector rejects data due to high memory usage. Indicates pipeline saturation — risk of data loss.",
			"severity":    "critical",
			"is_active":   true,
			"log_filter": map[string]interface{}{
				"text":        "data refused due to high memory usage",
				"filter_type": "text",
				"severity":    []string{"error", "warning", "info"},
			},
			"condition": map[string]interface{}{
				"condition_type": "more_than",
				"threshold":      5,
				"timeframe":      "5Min",
			},
			"notification_groups": []map[string]interface{}{
				{
					"notifications": []map[string]interface{}{
						{
							"retriggeringPeriodSeconds": 300,
							"notifyOn":                  "triggered_only",
						},
					},
				},
			},
			"meta_labels": []map[string]interface{}{
				{"key": "service", "value": "otel-collector"},
				{"key": "category", "value": "infrastructure"},
			},
		},

		// ── Alert 2: Checkout Connectivity Failure ──
		{
			"name":        "Checkout Service - Downstream Connection Failures",
			"description": "Fires when the checkout service cannot reach downstream services (ECONNREFUSED). Directly impacts order flow.",
			"severity":    "critical",
			"is_active":   true,
			"log_filter": map[string]interface{}{
				"text":            "ECONNREFUSED",
				"filter_type":     "text",
				"subsystem_name":  []string{"checkout"},
			},
			"condition": map[string]interface{}{
				"condition_type": "more_than",
				"threshold":      3,
				"timeframe":      "5Min",
			},
			"notification_groups": []map[string]interface{}{
				{
					"notifications": []map[string]interface{}{
						{
							"retriggeringPeriodSeconds": 120,
							"notifyOn":                  "triggered_and_resolved",
						},
					},
				},
			},
			"meta_labels": []map[string]interface{}{
				{"key": "service", "value": "checkout"},
				{"key": "category", "value": "connectivity"},
			},
		},

		// ── Alert 3: Accounting Pod CrashLoop (high restart rate) ──
		{
			"name":        "Accounting Service - Excessive Restarts",
			"description": "Fires when accounting service logs indicate repeated restarts. The pod has been crash-looping (66 restarts in 21h observed).",
			"severity":    "warning",
			"is_active":   true,
			"log_filter": map[string]interface{}{
				"text":            "started|Starting|Hosting environment",
				"filter_type":     "text",
				"subsystem_name":  []string{"accounting"},
			},
			"condition": map[string]interface{}{
				"condition_type": "more_than",
				"threshold":      3,
				"timeframe":      "1H",
			},
			"notification_groups": []map[string]interface{}{
				{
					"notifications": []map[string]interface{}{
						{
							"retriggeringPeriodSeconds": 600,
							"notifyOn":                  "triggered_only",
						},
					},
				},
			},
			"meta_labels": []map[string]interface{}{
				{"key": "service", "value": "accounting"},
				{"key": "category", "value": "stability"},
			},
		},
	}

	for _, alert := range standardAlerts {
		name := alert["name"].(string)
		fmt.Printf("  Creating alert: %s ... ", name)
		result, err := postJSON(cfg.AlertsURL, cfg.APIKey, alert)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			alertIDs = append(alertIDs, "")
			continue
		}
		id := extractAlertID(result)
		alertIDs = append(alertIDs, id)
		fmt.Printf("OK (id=%s)\n", id)
	}

	// ── Alert 4: Flow Alert — Cascading Checkout Failure ──
	// Stage 1: checkout ECONNREFUSED → Stage 2: payment stops charging → Stage 3: email stops confirming
	// This requires the IDs of the first two alerts + a third condition.
	// We create a "payment silence" alert as a helper, then wire the flow.

	fmt.Printf("  Creating helper alert: Payment Silence Detector ... ")
	paymentSilence := map[string]interface{}{
		"name":        "Payment Service - No Charges Received",
		"description": "Helper alert for flow: detects when payment service stops logging charge requests.",
		"severity":    "warning",
		"is_active":   true,
		"log_filter": map[string]interface{}{
			"text":            "Charge request received",
			"filter_type":     "text",
			"subsystem_name":  []string{"payment"},
		},
		"condition": map[string]interface{}{
			"condition_type": "less_than",
			"threshold":      1,
			"timeframe":      "10Min",
		},
		"notification_groups": []map[string]interface{}{
			{
				"notifications": []map[string]interface{}{
					{
						"retriggeringPeriodSeconds": 600,
						"notifyOn":                  "triggered_only",
					},
				},
			},
		},
	}
	paymentResult, err := postJSON(cfg.AlertsURL, cfg.APIKey, paymentSilence)
	paymentAlertID := ""
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
	} else {
		paymentAlertID = extractAlertID(paymentResult)
		fmt.Printf("OK (id=%s)\n", paymentAlertID)
	}

	// Now create the flow alert if we have the prerequisite alert IDs
	checkoutAlertID := ""
	if len(alertIDs) > 1 {
		checkoutAlertID = alertIDs[1]
	}

	if checkoutAlertID != "" && paymentAlertID != "" {
		fmt.Printf("  Creating flow alert: Cascading Checkout Failure ... ")

		// Flow alerts use the v3 REST API endpoint
		flowAlertURL := cfg.BaseURL + "/mgmt/openapi/latest/alerts/alerts-general/v3"

		flowPayload := map[string]interface{}{
			"alertDefProperties": map[string]interface{}{
				"name":        "Flow: Cascading Checkout → Payment Failure",
				"description": "Detects cascading failure: checkout loses connectivity, then payment stops receiving charges. Indicates full order pipeline breakdown.",
				"enabled":     true,
				"priority":    "ALERT_DEF_PRIORITY_P1",
				"type":        "ALERT_DEF_TYPE_FLOW",
				"flow": map[string]interface{}{
					"stages": []map[string]interface{}{
						{
							"timeframeMs":   300000, // 5 minutes
							"timeframeType": "TIMEFRAME_TYPE_UP_TO",
							"flowStagesGroups": map[string]interface{}{
								"groups": []map[string]interface{}{
									{
										"alertDefs": []map[string]interface{}{
											{"id": checkoutAlertID, "not": false},
										},
										"alertsOp": "ALERTS_OP_AND_OR_UNSPECIFIED",
										"nextOp":   "NEXT_OP_AND_OR_UNSPECIFIED",
									},
								},
							},
						},
						{
							"timeframeMs":   600000, // 10 minutes
							"timeframeType": "TIMEFRAME_TYPE_UP_TO",
							"flowStagesGroups": map[string]interface{}{
								"groups": []map[string]interface{}{
									{
										"alertDefs": []map[string]interface{}{
											{"id": paymentAlertID, "not": false},
										},
										"alertsOp": "ALERTS_OP_AND_OR_UNSPECIFIED",
										"nextOp":   "NEXT_OP_AND_OR_UNSPECIFIED",
									},
								},
							},
						},
					},
					"enforceSuppression": false,
				},
				"entityLabels": map[string]interface{}{
					"service":  "checkout,payment",
					"category": "cascading-failure",
				},
			},
		}

		result, err := postJSON(flowAlertURL, cfg.APIKey, flowPayload)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
		} else {
			fmt.Printf("OK %v\n", extractID(result))
		}
	} else {
		fmt.Println("  SKIPPED flow alert — prerequisite alerts failed to create")
	}
}

// ---------------------------------------------------------------------------
// 3. DASHBOARDS
// ---------------------------------------------------------------------------

func createDashboards(cfg Config) {
	fmt.Println("\n========== CREATING DASHBOARDS ==========")

	// ── Dashboard 1: Full Stack Observability ──
	fmt.Printf("  Creating dashboard: Full Stack Observability ... ")
	fsoPayload := buildFullStackDashboard()
	result, err := postJSON(cfg.DashURL, cfg.APIKey, fsoPayload)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
	} else {
		fmt.Printf("OK %v\n", extractID(result))
	}

	// ── Dashboard 2: Business Insights ──
	fmt.Printf("  Creating dashboard: Business Insights ... ")
	bizPayload := buildBusinessDashboard()
	result, err = postJSON(cfg.DashURL, cfg.APIKey, bizPayload)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
	} else {
		fmt.Printf("OK %v\n", extractID(result))
	}

	// ── Dashboard 3: Developer / Debugging ──
	fmt.Printf("  Creating dashboard: Developer & Debugging ... ")
	devPayload := buildDeveloperDashboard()
	result, err = postJSON(cfg.DashURL, cfg.APIKey, devPayload)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
	} else {
		fmt.Printf("OK %v\n", extractID(result))
	}
}

func buildFullStackDashboard() map[string]interface{} {
	return map[string]interface{}{
		"requestId": fmt.Sprintf("fso-%d", time.Now().UnixMilli()),
		"dashboard": map[string]interface{}{
			"name":        "OTel Demo - Full Stack Observability",
			"description": "End-to-end view: infrastructure health, service errors, trace latency, and pipeline status across all otel-demo microservices.",
			"layout": map[string]interface{}{
				"sections": []map[string]interface{}{
					// Section 1: Infrastructure Health
					{
						"id": "sec-infra",
						"rows": []map[string]interface{}{
							{
								"id":         "row-infra-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-pod-restarts",
										"title": "Pod Restarts by Service",
										"definition": map[string]interface{}{
											"barChart": map[string]interface{}{
												"query": map[string]interface{}{
													"metrics": map[string]interface{}{
														"promqlQuery":    `sum(kube_pod_container_status_restarts_total{namespace="otel-demo"}) by (container)`,
														"editorMode":     "text",
														"timeAggregation": "instant",
													},
												},
												"groupNameTemplate": "{{container}}",
												"stackDefinition": map[string]interface{}{
													"maxSlicesPerBar": 10,
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-cpu",
										"title": "CPU Usage by Pod",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "cpu-q",
														"query":    `sum(rate(container_cpu_usage_seconds_total{namespace="otel-demo"}[5m])) by (pod)`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-memory",
										"title": "Memory Usage by Pod",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "mem-q",
														"query":    `sum(container_memory_working_set_bytes{namespace="otel-demo"}) by (pod) / 1024 / 1024`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 2: Service Errors & Logs
					{
						"id": "sec-errors",
						"rows": []map[string]interface{}{
							{
								"id":         "row-errors-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-error-rate",
										"title": "Error Log Rate by Service",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id": "err-q",
														"query": `sum(rate(cx_data_usage_bytes_total{subsystem_name=~".+", severity="error"}[5m])) by (subsystem_name)`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-collector-backpressure",
										"title": "OTel Collector Backpressure Events",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "bp-q",
														"query":    `count_over_time({subsystem_name=~"currency|product-catalog"} |= "data refused due to high memory usage" [5m])`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-checkout-errors",
										"title": "Checkout gRPC Errors",
										"definition": map[string]interface{}{
											"dataTable": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"ECONNREFUSED" OR "Connection dropped"`,
														"filters": []map[string]interface{}{
															{
																"field":    "subsystemName",
																"operator": "equals",
																"values":   []string{"checkout"},
															},
														},
													},
												},
												"columns": []map[string]interface{}{
													{"field": "timestamp"},
													{"field": "text"},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 3: Traces & E2M
					{
						"id": "sec-traces",
						"rows": []map[string]interface{}{
							{
								"id":         "row-traces-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-e2m-response-time",
										"title": "Email Response Time p95 (Events2Metrics)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "e2m-q",
														"query":    `histogram_quantile(0.95, sum(rate(cx_email_response_time_seconds_bucket[5m])) by (le))`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-trace-duration",
										"title": "Trace Duration by Service (p95)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "trace-q",
														"query":    `histogram_quantile(0.95, sum(rate(duration_milliseconds_bucket{service_name=~".+"}[5m])) by (le, service_name))`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
				},
			},
			"relativeTimeFrame": "3600",
		},
	}
}

func buildBusinessDashboard() map[string]interface{} {
	return map[string]interface{}{
		"requestId": fmt.Sprintf("biz-%d", time.Now().UnixMilli()),
		"dashboard": map[string]interface{}{
			"name":        "OTel Demo - Business Insights",
			"description": "Non-technical dashboard: order volume, popular products, cart activity, customer engagement. Intended for business stakeholders.",
			"layout": map[string]interface{}{
				"sections": []map[string]interface{}{
					// Section 1: Order Activity
					{
						"id": "sec-orders",
						"rows": []map[string]interface{}{
							{
								"id":         "row-orders-1",
								"appearance": map[string]interface{}{"height": 12},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-orders-per-min",
										"title": "Orders Completed per Minute",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "opm-q",
														"query":    `count_over_time({subsystem_name="email"} |= "Order confirmation email sent" [1m])`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-order-recipients",
										"title": "Orders by Customer",
										"definition": map[string]interface{}{
											"barChart": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"Order confirmation email sent to"`,
														"filters": []map[string]interface{}{
															{
																"field":    "subsystemName",
																"operator": "equals",
																"values":   []string{"email"},
															},
														},
														"aggregations": []map[string]interface{}{
															{
																"type":  "count",
																"field": "_count",
															},
														},
														"groupBy": []string{"text"},
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 2: Cart Activity
					{
						"id": "sec-cart",
						"rows": []map[string]interface{}{
							{
								"id":         "row-cart-1",
								"appearance": map[string]interface{}{"height": 12},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-cart-actions",
										"title": "Cart Actions (Add / View / Empty)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "add-q",
														"query":    `count_over_time({subsystem_name="cart"} |= "AddItemAsync" [5m])`,
														"editorMode": "text",
													},
													{
														"id":       "empty-q",
														"query":    `count_over_time({subsystem_name="cart"} |= "EmptyCartAsync" [5m])`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-top-products",
										"title": "Top Products Added to Cart",
										"definition": map[string]interface{}{
											"barChart": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"AddItemAsync" AND productId:*`,
														"filters": []map[string]interface{}{
															{
																"field":    "subsystemName",
																"operator": "equals",
																"values":   []string{"cart"},
															},
														},
														"aggregations": []map[string]interface{}{
															{
																"type":  "count",
																"field": "_count",
															},
														},
														"groupBy": []string{"product_id"},
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 3: E2M Visualization (PromQL)
					{
						"id": "sec-e2m",
						"rows": []map[string]interface{}{
							{
								"id":         "row-e2m-1",
								"appearance": map[string]interface{}{"height": 12},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-e2m-cart-rate",
										"title": "Add-to-Cart Rate by Product (E2M / PromQL)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":       "e2m-cart-q",
														"query":    `sum(rate(cx_cart_actions_total{cart_action="AddItemAsync"}[5m])) by (product_id)`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-fraud-count",
										"title": "Fraud Detection - Orders Processed Total",
										"definition": map[string]interface{}{
											"gauge": map[string]interface{}{
												"query": map[string]interface{}{
													"metrics": map[string]interface{}{
														"promqlQuery":    `max(cx_fraud_detection_total_count)`,
														"editorMode":     "text",
														"timeAggregation": "instant",
													},
												},
												"min": 0,
												"max": 10000,
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
				},
			},
			"relativeTimeFrame": "3600",
		},
	}
}

func buildDeveloperDashboard() map[string]interface{} {
	return map[string]interface{}{
		"requestId": fmt.Sprintf("dev-%d", time.Now().UnixMilli()),
		"dashboard": map[string]interface{}{
			"name":        "OTel Demo - Developer & Debugging",
			"description": "Developer-focused: gRPC error breakdown, trace latency by endpoint, log volume by service, Kafka consumer lag, service error logs, and deployment events.",
			"layout": map[string]interface{}{
				"sections": []map[string]interface{}{
					// Section 1: Error Analysis
					{
						"id": "sec-dev-errors",
						"rows": []map[string]interface{}{
							{
								"id":         "row-dev-err-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-grpc-errors-by-code",
										"title": "Checkout gRPC Errors by Status Code",
										"definition": map[string]interface{}{
											"barChart": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"Error:" AND ("UNAVAILABLE" OR "DEADLINE_EXCEEDED" OR "INTERNAL")`,
														"filters": []map[string]interface{}{
															{
																"field":    "subsystemName",
																"operator": "equals",
																"values":   []string{"checkout"},
															},
														},
														"aggregations": []map[string]interface{}{
															{"type": "count", "field": "_count"},
														},
														"groupBy": []string{"grpc_status"},
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-error-services",
										"title": "Error Log Volume by Service (5m buckets)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "err-vol-q",
														"query":      `sum by (subsystem_name) (count_over_time({severity=~"error|Error|ERROR"} [5m]))`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-conn-refused-targets",
										"title": "ECONNREFUSED Target IPs (which backends are down?)",
										"definition": map[string]interface{}{
											"dataTable": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"ECONNREFUSED"`,
														"aggregations": []map[string]interface{}{
															{"type": "count", "field": "_count"},
														},
														"groupBy": []string{"target_ip", "target_port"},
													},
												},
												"columns": []map[string]interface{}{
													{"field": "target_ip"},
													{"field": "target_port"},
													{"field": "_count"},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 2: Trace Latency & Service Performance
					{
						"id": "sec-dev-traces",
						"rows": []map[string]interface{}{
							{
								"id":         "row-dev-trace-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-trace-p50-p95-p99",
										"title": "Trace Latency Percentiles (p50 / p95 / p99)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "p50-q",
														"query":      `histogram_quantile(0.50, sum(rate(duration_milliseconds_bucket{service_name=~".+"}[5m])) by (le))`,
														"editorMode": "text",
													},
													{
														"id":         "p95-q",
														"query":      `histogram_quantile(0.95, sum(rate(duration_milliseconds_bucket{service_name=~".+"}[5m])) by (le))`,
														"editorMode": "text",
													},
													{
														"id":         "p99-q",
														"query":      `histogram_quantile(0.99, sum(rate(duration_milliseconds_bucket{service_name=~".+"}[5m])) by (le))`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-trace-error-rate",
										"title": "Span Error Rate by Service",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "span-err-q",
														"query":      `sum(rate(calls_total{status_code="STATUS_CODE_ERROR"}[5m])) by (service_name) / sum(rate(calls_total[5m])) by (service_name)`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 3: Pipeline Health & Throughput
					{
						"id": "sec-dev-pipeline",
						"rows": []map[string]interface{}{
							{
								"id":         "row-dev-pipe-1",
								"appearance": map[string]interface{}{"height": 19},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-log-volume",
										"title": "Log Volume by Service (bytes/sec)",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "vol-q",
														"query":      `sum(rate(cx_data_usage_bytes_total{namespace="otel-demo"}[5m])) by (subsystem_name)`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-kafka-lag",
										"title": "Kafka Consumer Processing Rate",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "kafka-fraud-q",
														"query":      `count_over_time({subsystem_name="fraud-detection"} |= "Consumed record" [5m])`,
														"editorMode": "text",
													},
													{
														"id":         "kafka-acct-q",
														"query":      `count_over_time({subsystem_name="accounting"} |= "Order details" [5m])`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-collector-memory",
										"title": "OTel Collector Backpressure Rate",
										"definition": map[string]interface{}{
											"lineChart": map[string]interface{}{
												"queryDefinitions": []map[string]interface{}{
													{
														"id":         "bp-rate-q",
														"query":      `sum(count_over_time({subsystem_name=~"currency|product-catalog"} |= "data refused due to high memory usage" [5m]))`,
														"editorMode": "text",
													},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
					// Section 4: Recent Errors Log Stream
					{
						"id": "sec-dev-logs",
						"rows": []map[string]interface{}{
							{
								"id":         "row-dev-logs-1",
								"appearance": map[string]interface{}{"height": 25},
								"widgets": []map[string]interface{}{
									{
										"id":    "w-recent-errors",
										"title": "Live Error Stream (all services)",
										"definition": map[string]interface{}{
											"dataTable": map[string]interface{}{
												"query": map[string]interface{}{
													"logs": map[string]interface{}{
														"luceneQuery": `"Error" OR "error" OR "ECONNREFUSED" OR "failed" OR "refused"`,
														"filters": []map[string]interface{}{
															{
																"field":    "applicationName",
																"operator": "equals",
																"values":   []string{"otel-demo"},
															},
														},
													},
												},
												"columns": []map[string]interface{}{
													{"field": "timestamp"},
													{"field": "subsystemName"},
													{"field": "text"},
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
									{
										"id":    "w-pod-restarts-dev",
										"title": "Container Restart Count (spot crash-loops)",
										"definition": map[string]interface{}{
											"barChart": map[string]interface{}{
												"query": map[string]interface{}{
													"metrics": map[string]interface{}{
														"promqlQuery":     `sort_desc(sum(kube_pod_container_status_restarts_total{namespace="otel-demo"}) by (container))`,
														"editorMode":      "text",
														"timeAggregation": "instant",
													},
												},
												"groupNameTemplate": "{{container}}",
												"stackDefinition": map[string]interface{}{
													"maxSlicesPerBar": 10,
												},
											},
										},
										"appearance": map[string]interface{}{"width": 0},
									},
								},
							},
						},
					},
				},
			},
			"relativeTimeFrame": "3600",
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func extractID(m map[string]interface{}) string {
	for _, key := range []string{"id", "dashboardId", "ruleGroupId", "ID"} {
		if v, ok := m[key]; ok {
			return fmt.Sprintf("(id=%v)", v)
		}
	}
	return ""
}

func extractAlertID(m map[string]interface{}) string {
	// v2 API returns: {"alert_id":["uuid"], "unique_identifier":["uuid"]}
	if ids, ok := m["alert_id"].([]interface{}); ok && len(ids) > 0 {
		return fmt.Sprintf("%v", ids[0])
	}
	if uid, ok := m["unique_identifier"].([]interface{}); ok && len(uid) > 0 {
		return fmt.Sprintf("%v", uid[0])
	}
	// v3 API returns nested: {"alertDef":{"id":"uuid"}}
	if alertDef, ok := m["alertDef"].(map[string]interface{}); ok {
		if id, ok := alertDef["id"]; ok {
			return fmt.Sprintf("%v", id)
		}
	}
	return fmt.Sprintf("%v", m)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  Coralogix OTel-Demo Setup                             ║")
	fmt.Println("║  Creates: Rules, Alerts, Dashboards, Events2Metrics    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	cfg := loadConfig()
	fmt.Printf("\nRegion: %s\nRules API:  %s\nAlerts API: %s\nDash API:   %s\nE2M API:    %s\n",
		cfg.Region, cfg.RulesURL, cfg.AlertsURL, cfg.DashURL, cfg.E2MURL)

	createParsingRules(cfg)
	createAlerts(cfg)
	createDashboards(cfg)
	createEvents2Metrics(cfg)

	fmt.Println("\n========== DONE ==========")
	fmt.Println("Remaining manual step:")
	fmt.Println("  Enable Geo + Security enrichment on 'client_ip' field")
	fmt.Println("  (Data Flow → Data Enrichment → Geo Enrichment → Add 'client_ip')")
}

// ---------------------------------------------------------------------------
// 4. EVENTS2METRICS
// ---------------------------------------------------------------------------

func createEvents2Metrics(cfg Config) {
	fmt.Println("\n========== CREATING EVENTS2METRICS ==========")

	e2ms := []map[string]interface{}{
		// ── E2M 1: Email response time histogram ──
		{
			"name":        "cx_email_response_time",
			"description": "Histogram of email service HTTP response times from parsed response_time field.",
			"type":        "E2M_TYPE_LOGS2METRICS",
			"logsQuery": map[string]interface{}{
				"lucene":               "response_time:*",
				"subsystemnameFilters": []string{"email"},
			},
			"metricLabels": []map[string]interface{}{
				{"targetLabel": "method", "sourceField": "method"},
				{"targetLabel": "status", "sourceField": "status"},
				{"targetLabel": "path", "sourceField": "path"},
			},
			"metricFields": []map[string]interface{}{
				{
					"targetBaseMetricName": "cx_email_response_time",
					"sourceField":          "response_time",
					"aggregations": []map[string]interface{}{
						{
							"aggType":          "AGG_TYPE_HISTOGRAM",
							"enabled":          true,
							"targetMetricName": "cx_email_response_time_histogram",
							"histogram": map[string]interface{}{
								"buckets": []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
							},
						},
						{
							"aggType":          "AGG_TYPE_AVG",
							"enabled":          true,
							"targetMetricName": "cx_email_response_time_avg",
						},
						{
							"aggType":          "AGG_TYPE_MAX",
							"enabled":          true,
							"targetMetricName": "cx_email_response_time_max",
						},
					},
				},
			},
		},

		// ── E2M 2: Cart actions counter ──
		{
			"name":        "cx_cart_actions",
			"description": "Counter of cart operations by action type and product from parsed cart_action and product_id fields.",
			"type":        "E2M_TYPE_LOGS2METRICS",
			"logsQuery": map[string]interface{}{
				"lucene":               "cart_action:*",
				"subsystemnameFilters": []string{"cart"},
			},
			"metricLabels": []map[string]interface{}{
				{"targetLabel": "cart_action", "sourceField": "cart_action"},
				{"targetLabel": "product_id", "sourceField": "product_id"},
			},
			"metricFields": []map[string]interface{}{
				{
					"targetBaseMetricName": "cx_cart_actions",
					"sourceField":          "cart_action",
					"aggregations": []map[string]interface{}{
						{
							"aggType":          "AGG_TYPE_COUNT",
							"enabled":          true,
							"targetMetricName": "cx_cart_actions_total",
						},
					},
				},
			},
		},

		// ── E2M 3: Fraud detection order counter ──
		{
			"name":        "cx_fraud_orders",
			"description": "Max of total_count from fraud-detection service, tracking cumulative orders processed.",
			"type":        "E2M_TYPE_LOGS2METRICS",
			"logsQuery": map[string]interface{}{
				"lucene":               "total_count:*",
				"subsystemnameFilters": []string{"fraud-detection"},
			},
			"metricLabels": []map[string]interface{}{},
			"metricFields": []map[string]interface{}{
				{
					"targetBaseMetricName": "cx_fraud_orders",
					"sourceField":          "total_count",
					"aggregations": []map[string]interface{}{
						{
							"aggType":          "AGG_TYPE_MAX",
							"enabled":          true,
							"targetMetricName": "cx_fraud_orders_total",
						},
					},
				},
			},
		},
	}

	for _, e2m := range e2ms {
		name := e2m["name"].(string)
		fmt.Printf("  Creating E2M: %s ... ", name)
		result, err := postJSON(cfg.E2MURL, cfg.APIKey, e2m)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			continue
		}
		fmt.Printf("OK %v\n", extractID(result))
	}
}
