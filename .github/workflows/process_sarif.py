
import json

# Load the SARIF file
with open('snyk.sarif', 'r') as file:
    sarif_data = json.load(file)

# Extract runs, results, and rules
runs_data = sarif_data['runs']
rules = runs_data[0]['tool']['driver']['rules']
results = runs_data[0]['results']

# Initialize counters and storage for vulnerabilities
total_vulnerabilities = 0
high_vulnerabilities = []
medium_vulnerabilities = []
low_vulnerabilities = []

# Severity mapping
severity_mapping = {
    "error": "High",
    "warning": "Medium",
    "note": "Low"
}

# Find matches between rule ids and result rule ids
for rule in rules:
    rule_id = rule['id']
    rule_severity = severity_mapping.get(rule.get('defaultConfiguration', {}).get('level'), "Unknown")
    rule_description = rule['shortDescription']['text']
    
    for result in results:
        if result['ruleId'] == rule_id:
            result_severity = severity_mapping.get(result['level'], "Unknown")
            for location in result['locations']:
                vulnerability = {
                    'ruleName': rule_description,
                    'path': location['physicalLocation']['artifactLocation']['uri'],
                    'line': location['physicalLocation']['region']['startLine'],
                    'severity': result_severity
                }
                if result_severity == "High":
                    high_vulnerabilities.append(vulnerability)
                elif result_severity == "Medium":
                    medium_vulnerabilities.append(vulnerability)
                elif result_severity == "Low":
                    low_vulnerabilities.append(vulnerability)
                total_vulnerabilities += 1

# Generate report
report = []
report.append(f"Total Vulnerabilities: {total_vulnerabilities}")
report.append(f"High: {len(high_vulnerabilities)}")
for vuln in high_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}")

report.append(f"Medium: {len(medium_vulnerabilities)}")
for vuln in medium_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}")

report.append(f"Low: {len(low_vulnerabilities)}")
for vuln in low_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}")

# Save report to a text file
with open('vulnerability_report.txt', 'w') as output_file:
    output_file.write("\n".join(report))

print("Report generation completed. Results saved in 'vulnerability_report.txt'.")
