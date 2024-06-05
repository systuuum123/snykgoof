# Create output directory
output_dir = ".github/data"
os.makedirs(output_dir, exist_ok=True)

# Save the current report for future comparison
current_report = {
    'timestamp': current_timestamp,
    'high': high_vulnerabilities,
    'medium': medium_vulnerabilities,
    'low': low_vulnerabilities
}
report_json_filename = os.path.join(output_dir, f'vulnerability_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
save_json(current_report, report_json_filename)

# Generate report
report = []
report.append(f"Total Vulnerabilities: {total_vulnerabilities}")
report.append(f"High: {len(high_vulnerabilities)}")
for vuln in high_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

report.append(f"Medium: {len(medium_vulnerabilities)}")
for vuln in medium_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

report.append(f"Low: {len(low_vulnerabilities)}")
for vuln in low_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

# Save report to a text file with timestamp
report_filename = os.path.join(output_dir, f'vulnerability_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
with open(report_filename, 'w') as output_file:
    output_file.write("\n".join(report))

print(f"Report generation completed. Results saved in '{report_filename}' and '{report_json_filename}'.")
