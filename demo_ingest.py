from pathlib import Path
from api.ingest import ingest_normalized_scan

def main():
    # Adjust these paths to point to one of your real runs, e.g.:
    # runs/semgrep/juice-shop/2025120201/juice-shop.normalized.json
    # runs/semgrep/juice-shop/2025120201/metadata.json
    normalized_path = Path("runs/semgrep/juice-shop/2025120201/juice-shop.normalized.json")
    metadata_path = Path("runs/semgrep/juice-shop/2025120201/metadata.json")

    scan, findings = ingest_normalized_scan(
        normalized_path=normalized_path,
        metadata_path=metadata_path,
        target_key="juice_shop",
    )

    print("Scan summary:")
    print(scan)
    print()
    print(f"First 3 findings out of {len(findings)}:")
    for f in findings[:3]:
        print(f)

if __name__ == "__main__":
    main()
