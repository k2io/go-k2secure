// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_policy

import (
	k2models "github.com/k2io/go-k2secure/v2/internal/k2secure_model"
	"github.com/xeipuuv/gojsonschema"
)

var (
	policyValidationLoader gojsonschema.JSONLoader
)

const POLICY_VALIDATION_SCHEMA = `{
	"title":"LCPolicy",
	"description":"A policy for language collectors",
	"type":"object",
	"properties":{
	   "version":{
		  "type":"string",
		  "minLength": 1
	   },
	   "logLevel":{
		  "type":"string",
		  "enum":[
			 "ALL",
			 "DEBUG",
			 "INFO",
			 "WARN",
			 "ERROR",
			 "FATAL",
			 "OFF"
		  ]
	   },
	   "policyPull":{
		  "type":"boolean"
	   },
	   "policyPullInterval":{
		  "type":"integer",
		  "minimum":0,
		  "maximum":2592000
	   },
	   "vulnerabilityScan":{
		  "type":"object",
		  "properties":{
			 "enabled":{
				"type":"boolean"
			 },
			 "cveScan":{
				"type":"object",
				"properties":{
				   "enabled":{
					  "type":"boolean"
				   },
				   "enableEnvScan":{
					  "type":"boolean"
				   },
				   "cveDefinitionUpdateInterval":{
					  "type":"integer",
					  "minimum":0,
					  "maximum":1440
				   }
				},
				"required":[
				   "enabled",
				   "enableEnvScan",
				   "cveDefinitionUpdateInterval"
				]
			 },
			 "iastScan":{
				"type":"object",
				"properties":{
				   "enabled":{
					  "type":"boolean"
				   },
				   "probing":{
					  "type":"object",
					  "properties":{
						 "interval":{
							"type":"integer",
							"minimum":1,
							"maximum":60
						 },
						 "batchSize":{
							"type":"integer",
							"minimum":1,
							"maximum":300
						 }
					  },
					  "required":[
						 "interval",
						 "batchSize"
					  ]
				   }
				},
				"required":[
				   "enabled",
				   "probing"
				]
			 }
		  },
		  "required":[
			 "enabled",
			 "cveScan",
			 "iastScan"
		  ]
	   },
	   "protectionMode":{
		  "type":"object",
		  "properties":{
			 "enabled":{
				"type":"boolean"
			 },
			 "ipBlocking":{
				"type":"object",
				"properties":{
				   "enabled":{
					  "type":"boolean"
				   },
				   "attackerIpBlocking":{
					  "type":"boolean"
				   },
				   "ipDetectViaXFF":{
					  "type":"boolean"
				   },
				   "timeout":{
					  "type":"integer",
					  "minimum":1,
					  "maximum":4313200
				   }
				},
				"required":[
				   "enabled",
				   "attackerIpBlocking",
				   "ipDetectViaXFF",
				   "timeout"
				]
			 },
			 "apiBlocking":{
				"type":"object",
				"properties":{
				   "enabled":{
					  "type":"boolean"
				   },
				   "protectAllApis":{
					  "type":"boolean"
				   },
				   "protectKnownVulnerableApis":{
					  "type":"boolean"
				   },
				   "protectAttackedApis":{
					  "type":"boolean"
				   }
				},
				"required":[
				   "enabled",
				   "protectAllApis",
				   "protectKnownVulnerableApis",
				   "protectAttackedApis"
				]
			 }
		  },
		  "required":[
			 "enabled",
			 "ipBlocking",
			 "apiBlocking"
		  ]
	   },
	   "sendCompleteStackTrace":{
		  "type":"boolean"
	   },
	   "enableHTTPRequestPrinting":{
		  "type":"boolean"
	   }
	},
	"required":[
	   "version",
	   "logLevel",
	   "policyPull",
	   "policyPullInterval",
	   "vulnerabilityScan",
	   "protectionMode",
	   "sendCompleteStackTrace",
	   "enableHTTPRequestPrinting",
	   "policyParameters"
	]
 }`

func init_defaultPolicy() {
	policyValidationLoader = gojsonschema.NewStringLoader(POLICY_VALIDATION_SCHEMA)
}

func ValidatePolicy(policy k2models.WebAppPolicy) (ok bool) {

	if policyValidationLoader == nil {
		init_defaultPolicy()
	}
	var err error
	policyLoader := gojsonschema.NewGoLoader(policy)
	var result *gojsonschema.Result
	result, err = gojsonschema.Validate(policyValidationLoader, policyLoader)

	if err == nil && result.Valid() {
		ok = true
		return
	} else {
		if err != nil {
			logger.WithError(err).Warnln("Policy validation failed due to error", err)
		} else if result != nil {
			logger.Warnln("Policy validation failed due to issues.")
			for _, err := range result.Errors() {
				logger.
					WithField("issue", err.Description()).
					WithField("field", err.Field()).
					WithField("value", err.Value()).
					WithField("detail", err.String()).
					Warnln("Policy validation failure detail.")
			}
		}
	}
	return
}
