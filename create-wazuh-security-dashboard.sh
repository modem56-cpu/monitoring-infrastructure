#!/usr/bin/env bash
# Create Wazuh Security Events dashboard in Grafana
# Uses Wazuh Indexer (OpenSearch) datasource UID: ffk7w5f7pkv7kd
set -euo pipefail

GRAFANA="http://127.0.0.1:3000"
AUTH="Authorization: Basic $(echo -n 'admin:admin' | base64)"
DS_UID="ffk7w5f7pkv7kd"
DS_NAME="Wazuh Indexer"

echo "Creating Wazuh Security Events dashboard..."

curl -sf -X POST "$GRAFANA/api/dashboards/db" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d @- << PAYLOAD
{
  "overwrite": true,
  "folderId": 0,
  "dashboard": {
    "uid": "wazuh-security-events",
    "title": "Wazuh Security Events",
    "tags": ["wazuh", "security", "siem"],
    "timezone": "browser",
    "refresh": "60s",
    "time": { "from": "now-24h", "to": "now" },
    "schemaVersion": 36,
    "panels": [

      {
        "id": 1,
        "type": "stat",
        "title": "Total Alerts (24h)",
        "gridPos": { "x": 0, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 10000 },
              { "color": "red", "value": 100000 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 2,
        "type": "stat",
        "title": "Critical (Level ≥ 12)",
        "gridPos": { "x": 4, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "green", "value": null },
              { "color": "orange", "value": 1 },
              { "color": "red", "value": 10 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.level:>=12",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 3,
        "type": "stat",
        "title": "High (Level 7–11)",
        "gridPos": { "x": 8, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 100 },
              { "color": "orange", "value": 1000 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.level:[7 TO 11]",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 4,
        "type": "stat",
        "title": "SSH Auth Failures (24h)",
        "gridPos": { "x": 12, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 50 },
              { "color": "red", "value": 500 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.groups:authentication_failed",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 5,
        "type": "stat",
        "title": "Sudo / Root Events (24h)",
        "gridPos": { "x": 16, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 20 },
              { "color": "red", "value": 200 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.groups:sudo OR rule.description:*sudo* OR rule.description:*ROOT*",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 6,
        "type": "stat",
        "title": "Unique Agents Reporting",
        "gridPos": { "x": 20, "y": 0, "w": 4, "h": 3 },
        "fieldConfig": {
          "defaults": {
            "color": { "mode": "thresholds" },
            "thresholds": { "mode": "absolute", "steps": [
              { "color": "red", "value": null },
              { "color": "yellow", "value": 3 },
              { "color": "green", "value": 6 }
            ]},
            "mappings": []
          }
        },
        "options": { "reduceOptions": { "calcs": ["lastNotNull"] }, "orientation": "auto", "textMode": "auto", "colorMode": "background" },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "",
          "queryType": "lucene",
          "metrics": [{ "type": "cardinality", "id": "1", "field": "agent.name" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 10,
        "type": "timeseries",
        "title": "Alert Volume by Severity (24h)",
        "gridPos": { "x": 0, "y": 3, "w": 16, "h": 8 },
        "fieldConfig": {
          "defaults": {
            "custom": { "lineWidth": 2, "fillOpacity": 10 },
            "color": { "mode": "palette-classic" }
          }
        },
        "options": {
          "tooltip": { "mode": "multi" },
          "legend": { "displayMode": "list", "placement": "bottom" }
        },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [
          {
            "refId": "Critical",
            "query": "rule.level:>=12",
            "queryType": "lucene",
            "metrics": [{ "type": "count", "id": "1" }],
            "bucketAggs": [{ "type": "date_histogram", "id": "2", "field": "@timestamp", "settings": { "interval": "10m", "min_doc_count": "0" } }],
            "timeField": "@timestamp",
            "alias": "Critical (≥12)"
          },
          {
            "refId": "High",
            "query": "rule.level:[7 TO 11]",
            "queryType": "lucene",
            "metrics": [{ "type": "count", "id": "1" }],
            "bucketAggs": [{ "type": "date_histogram", "id": "2", "field": "@timestamp", "settings": { "interval": "10m", "min_doc_count": "0" } }],
            "timeField": "@timestamp",
            "alias": "High (7-11)"
          },
          {
            "refId": "Medium",
            "query": "rule.level:[5 TO 6]",
            "queryType": "lucene",
            "metrics": [{ "type": "count", "id": "1" }],
            "bucketAggs": [{ "type": "date_histogram", "id": "2", "field": "@timestamp", "settings": { "interval": "10m", "min_doc_count": "0" } }],
            "timeField": "@timestamp",
            "alias": "Medium (5-6)"
          },
          {
            "refId": "Low",
            "query": "rule.level:[3 TO 4]",
            "queryType": "lucene",
            "metrics": [{ "type": "count", "id": "1" }],
            "bucketAggs": [{ "type": "date_histogram", "id": "2", "field": "@timestamp", "settings": { "interval": "10m", "min_doc_count": "0" } }],
            "timeField": "@timestamp",
            "alias": "Low (3-4)"
          }
        ]
      },

      {
        "id": 11,
        "type": "piechart",
        "title": "Alerts by Agent",
        "gridPos": { "x": 16, "y": 3, "w": 8, "h": 8 },
        "fieldConfig": {
          "defaults": { "color": { "mode": "palette-classic" } }
        },
        "options": {
          "pieType": "pie",
          "displayLabels": ["name", "percent"],
          "legend": { "displayMode": "list", "placement": "bottom" }
        },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [{ "type": "terms", "id": "2", "field": "agent.name", "settings": { "size": "10", "order": "desc", "orderBy": "1" } }],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 20,
        "type": "table",
        "title": "Top Fired Rules",
        "gridPos": { "x": 0, "y": 11, "w": 12, "h": 8 },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Count" }, "properties": [
              { "id": "custom.width", "value": 90 },
              { "id": "custom.align", "value": "center" }
            ]},
            { "matcher": { "id": "byName", "options": "Rule ID" }, "properties": [
              { "id": "custom.width", "value": 90 }
            ]},
            { "matcher": { "id": "byName", "options": "Level" }, "properties": [
              { "id": "custom.width", "value": 65 },
              { "id": "custom.align", "value": "center" },
              { "id": "custom.displayMode", "value": "color-background" },
              { "id": "thresholds", "value": { "mode": "absolute", "steps": [
                { "color": "blue", "value": null },
                { "color": "yellow", "value": 7 },
                { "color": "orange", "value": 10 },
                { "color": "red", "value": 12 }
              ]}}
            ]}
          ]
        },
        "options": { "sortBy": [{ "displayName": "Count", "desc": true }] },
        "transformations": [
          { "id": "organize", "options": { "renameByName": { "1": "Count", "2 orderby": "", "rule.id": "Rule ID", "rule.level": "Level", "rule.description": "Description" } } }
        ],
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "",
          "queryType": "lucene",
          "metrics": [
            { "type": "count", "id": "1" },
            { "type": "max", "id": "3", "field": "rule.level" }
          ],
          "bucketAggs": [
            { "type": "terms", "id": "2", "field": "rule.description", "settings": { "size": "20", "order": "desc", "orderBy": "1" } }
          ],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 21,
        "type": "table",
        "title": "SSH Authentication Failures",
        "gridPos": { "x": 12, "y": 11, "w": 12, "h": 8 },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Count" }, "properties": [
              { "id": "custom.width", "value": 80 },
              { "id": "custom.align", "value": "center" }
            ]},
            { "matcher": { "id": "byName", "options": "Source IP" }, "properties": [
              { "id": "custom.width", "value": 140 }
            ]}
          ]
        },
        "options": { "sortBy": [{ "displayName": "Count", "desc": true }] },
        "transformations": [
          { "id": "organize", "options": { "renameByName": { "1": "Count", "data.srcip": "Source IP", "data.dstuser": "Target User" } } }
        ],
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.groups:authentication_failed AND data.srcip:*",
          "queryType": "lucene",
          "metrics": [{ "type": "count", "id": "1" }],
          "bucketAggs": [
            { "type": "terms", "id": "2", "field": "data.srcip", "settings": { "size": "20", "order": "desc", "orderBy": "1" } }
          ],
          "timeField": "@timestamp"
        }]
      },

      {
        "id": 30,
        "type": "table",
        "title": "Critical & High Alerts (Level ≥ 7) — Live",
        "gridPos": { "x": 0, "y": 19, "w": 24, "h": 10 },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Level" }, "properties": [
              { "id": "custom.width", "value": 65 },
              { "id": "custom.align", "value": "center" },
              { "id": "custom.displayMode", "value": "color-background" },
              { "id": "thresholds", "value": { "mode": "absolute", "steps": [
                { "color": "yellow", "value": null },
                { "color": "orange", "value": 10 },
                { "color": "red", "value": 12 }
              ]}}
            ]},
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [
              { "id": "custom.width", "value": 180 }
            ]},
            { "matcher": { "id": "byName", "options": "Agent" }, "properties": [
              { "id": "custom.width", "value": 140 }
            ]},
            { "matcher": { "id": "byName", "options": "Rule ID" }, "properties": [
              { "id": "custom.width", "value": 85 }
            ]}
          ]
        },
        "options": {
          "frameIndex": 0,
          "showHeader": true,
          "sortBy": [{ "displayName": "Level", "desc": true }],
          "footer": { "show": false }
        },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.level:>=7",
          "queryType": "lucene",
          "metrics": [{ "type": "logs", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }],
        "transformations": [
          {
            "id": "organize",
            "options": {
              "excludeByName": {
                "predecoder.hostname": true,
                "predecoder.timestamp": true,
                "input.type": true,
                "decoder.name": true,
                "manager.name": true,
                "rule.mail": true,
                "rule.firedtimes": true,
                "rule.gpg13": true,
                "rule.gdpr": true,
                "rule.groups": false,
                "id": true
              },
              "renameByName": {
                "@timestamp": "Time",
                "agent.name": "Agent",
                "rule.level": "Level",
                "rule.id": "Rule ID",
                "rule.description": "Description",
                "full_log": "Log",
                "rule.groups": "Groups"
              }
            }
          }
        ]
      },

      {
        "id": 40,
        "type": "table",
        "title": "Sudo / Root Privilege Escalations",
        "gridPos": { "x": 0, "y": 29, "w": 24, "h": 8 },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.width", "value": 180 }] },
            { "matcher": { "id": "byName", "options": "Agent" }, "properties": [{ "id": "custom.width", "value": 140 }] },
            { "matcher": { "id": "byName", "options": "Level" }, "properties": [
              { "id": "custom.width", "value": 65 },
              { "id": "custom.align", "value": "center" },
              { "id": "custom.displayMode", "value": "color-background" },
              { "id": "thresholds", "value": { "mode": "absolute", "steps": [
                { "color": "yellow", "value": null },
                { "color": "orange", "value": 10 },
                { "color": "red", "value": 12 }
              ]}}
            ]}
          ]
        },
        "options": { "frameIndex": 0, "showHeader": true, "footer": { "show": false } },
        "datasource": { "type": "grafana-opensearch-datasource", "uid": "${DS_UID}" },
        "targets": [{
          "refId": "A",
          "query": "rule.groups:sudo OR rule.description:*sudo* OR rule.description:*ROOT*",
          "queryType": "lucene",
          "metrics": [{ "type": "logs", "id": "1" }],
          "bucketAggs": [],
          "timeField": "@timestamp"
        }],
        "transformations": [
          {
            "id": "organize",
            "options": {
              "excludeByName": {
                "predecoder.hostname": true,
                "predecoder.timestamp": true,
                "input.type": true,
                "decoder.name": true,
                "manager.name": true,
                "rule.mail": true,
                "rule.firedtimes": true,
                "rule.gpg13": true,
                "rule.gdpr": true,
                "id": true
              },
              "renameByName": {
                "@timestamp": "Time",
                "agent.name": "Agent",
                "rule.level": "Level",
                "rule.id": "Rule ID",
                "rule.description": "Description",
                "full_log": "Log"
              }
            }
          }
        ]
      }

    ]
  }
}
PAYLOAD

echo ""
echo "Done. Dashboard UID: wazuh-security-events"
echo "URL: http://192.168.10.20:3000/d/wazuh-security-events"
