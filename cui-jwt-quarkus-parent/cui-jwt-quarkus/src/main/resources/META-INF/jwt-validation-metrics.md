# JWT Validation Metrics

This document describes the metrics exposed by the cui-jwt-quarkus module for monitoring JWT token validation.

## Metrics Overview

All metrics are exposed through Micrometer and follow Micrometer naming conventions. The metrics are automatically collected when JWT tokens are validated using the `TokenValidator` and when security events are triggered.

## Metric Naming

All metrics are prefixed with `cui.jwt` to clearly identify them as part of the cui-jwt library.

## Available Metrics

### Token Validation Metrics

| Metric Name | Type | Description | Tags | Unit |
|-------------|------|-------------|------|------|
| `cui.jwt.validation.attempts` | Counter | Number of token validation attempts | issuer, token_type, result | attempts |
| `cui.jwt.validation.errors` | Counter | Number of validation errors by type | issuer, event_type, category, result | errors |
| `cui.jwt.validation.duration` | Timer | Duration of token validation operations | issuer, token_type | milliseconds |
| `cui.jwt.jwks.cache.size` | Gauge | Size of JWKS cache | issuer | entries |

### Metric Tags

Each metric includes relevant tags to enable filtering and drilling down:

* `issuer`: The issuer URL (when available)
* `event_type`: The type of security event (for error metrics)
* `token_type`: The type of token (access, id, refresh)
* `result`: The validation result (success, failure)
* `category`: The category of event (structure, signature, semantic)

## Example Prometheus Queries

### Basic Queries

```
# Total validation attempts
sum(cui_jwt_validation_attempts_total)

# Success rate for token validation
sum(cui_jwt_validation_attempts_total{result="success"}) / sum(cui_jwt_validation_attempts_total) * 100

# Error rate by issuer
sum(cui_jwt_validation_errors_total) by (issuer)

# Error rate by category
sum(cui_jwt_validation_errors_total) by (category)

# Validation duration (99th percentile)
histogram_quantile(0.99, sum(rate(cui_jwt_validation_duration_seconds_bucket[5m])) by (le))
```

### Alert Examples

```
# Alert on high error rate
alert: JwtValidationHighErrorRate
expr: sum(rate(cui_jwt_validation_errors_total[5m])) / sum(rate(cui_jwt_validation_attempts_total[5m])) > 0.1
for: 5m
labels:
  severity: warning
annotations:
  summary: "High JWT validation error rate"
  description: "JWT validation error rate is above 10% for 5 minutes"

# Alert on signature verification failures (potential attack)
alert: JwtSignatureVerificationFailures
expr: rate(cui_jwt_validation_errors_total{event_type="SIGNATURE_VERIFICATION_FAILED"}[5m]) > 0
for: 5m
labels:
  severity: critical
annotations:
  summary: "JWT signature verification failures detected"
  description: "Potential attack: JWT tokens with invalid signatures are being processed"
```

### Dashboard Examples

A typical dashboard for JWT validation monitoring would include:

1. Overall validation success rate
2. Error counts by category and type
3. Validation duration trends
4. JWKS cache size and health

Example Grafana dashboard JSON:

```json
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": null,
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 2,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "dataLinks": []
      },
      "percentage": false,
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "sum(rate(cui_jwt_validation_attempts_total[5m])) by (result)",
          "interval": "",
          "legendFormat": "",
          "refId": "A"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "JWT Validation Rate",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    }
  ],
  "schemaVersion": 25,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {
    "refresh_intervals": [
      "10s",
      "30s",
      "1m",
      "5m",
      "15m",
      "30m",
      "1h",
      "2h",
      "1d"
    ]
  },
  "timezone": "",
  "title": "JWT Validation Dashboard",
  "uid": "jwt-validation",
  "version": 1
}
```

## Using the Metrics in Your Application

These metrics are automatically collected when the cui-jwt-quarkus module is used in your application. To use them:

1. Ensure the `quarkus-micrometer` extension is enabled in your application
2. Optionally, add a registry implementation like `quarkus-micrometer-registry-prometheus` for Prometheus integration
3. Use the TokenValidator with the @TokenValidationMetrics annotation (automatically applied by the producer)

The metrics will be available at the standard Micrometer/Prometheus endpoint: `/q/metrics`
