import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from client import IndirectPromptInjectionSanitizerClient

def main():
    client = IndirectPromptInjectionSanitizerClient()
    res = client.sanitize_untrusted_context()
    print("=== Indirect Prompt Injection Sanitizer Output ===")
    print(f"Source: {res['source_name']} | Threat Score: {res['threat_score']} (Verdict: {res['firewall_verdict']})")
    print(f"Safe For Consumption: {res['is_safe_for_agent_consumption']} | Threats Found: {res['threats_detected_count']}")
    if res['detected_threat_details']:
        print("\nThreat Details Flagged:")
        for t in res['detected_threat_details']:
            print(f"  * [{t['threat_type']}] {t['occurrences']} match(es)")
    print("\nIsolated XML Payload Sample:")
    print(res['isolated_context_payload'])

if __name__ == '__main__':
    main()
