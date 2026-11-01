# Rule Test 001 — Splunk Query Conversion

## Rule
`rule_001_suspicious_wuauclt.yml`

## Backend
Splunk

## Processing Pipeline
`splunk_windows`

## Result
Successful. Sigma converted the rule into a Splunk search query.

## Generated Query
```spl
Image="*\\cmd.exe" ParentImage="*\\wuauclt.exe" ParentCommandLine="*UpdateDeploymentProvider*" ParentCommandLine="*helpa.dll*"
```

## Limitations
This test confirms that Sigma can convert the rule into Splunk query syntax. The query has not yet been executed against the EVTX dataset in Splunk, so detection effectiveness and false-positive rates remain unverified.