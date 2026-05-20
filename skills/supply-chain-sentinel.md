# Sicario Skill: Supply Chain Sentinel

This skill enables the AI to detect and mitigate malicious package dependencies (Supply Chain Attacks) using Sicario's behavioral anomaly engine.

## Workflow

1. **Monitor Dependencies**: When the developer adds a new package (e.g., `npm install`, `pip install`), trigger a behavioral audit.

2. **Analyze Behavioral Rules**: Use the `get_rules` tool to identify behavioral anomaly patterns (IDs starting with `guard/`).
   - *Example:* `guard/unexpected-child-process`, `guard/process-env-access`.

3. **Behavioral Scan**: Run Sicario's behavioral engine (Poison-Pill Interceptor) against the newly added package's source in `node_modules` or similar.

4. **Triage Anomalies**: If an anomaly is detected (e.g., a simple utility package requiring the `net` module), flag it to the developer immediately.
   - *Logic:* "This package is a string formatter but it's attempting to establish a TCP connection. This is a potential Supply Chain Attack."

5. **Mitigation**: Propose removing the package or replacing it with a verified alternative.

## Best Practices
- **Early Detection**: The goal is to catch the anomaly *before* the code is committed or deployed.
- **Contextual Awareness**: Distinguish between legitimate network access (e.g., an HTTP client) and suspicious access (e.g., a left-pad library).
