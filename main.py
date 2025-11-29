from dotenv import load_dotenv
from openai import OpenAI
import os 
import json
import argparse
import json

load_dotenv()
OPENAI_CHATGPT_KEY=os.getenv("OPENAI_CHATGPT_KEY")
client = OpenAI(api_key= OPENAI_CHATGPT_KEY)

from utils.detect_file_type import analyze_file

def main():
    parser = argparse.ArgumentParser(description="Ultimate file analyzer")
    parser.add_argument("path", help="File path to analyze")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")
    args = parser.parse_args()

    result = analyze_file(args.path)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    # Pretty print mode:
    print(f"File: {result['file_path']}")
    print(f"Size: {result['size']} bytes")
    print(f"Type: {result.get('type')} / {result.get('subtype')} (confidence {result.get('confidence')})")
    print(f"MIME: {result.get('mime')}")
    print(f"Extension guess: {result.get('extension_guess')}")
    print("Hashes:")
    for k, v in result.get("hashes", {}).items():
        print(f"  {k}: {v}")
    print(f"Entropy (first chunk): {result.get('entropy'):.4f}")

    print("Top analysis hints:")
    for hint in result.get("analysis", [])[:10]:
        print(" -", hint)

    if result.get("metadata"):
        print("\nMetadata summary:", ", ".join(result["metadata"].keys()))

        if "pdf_metadata" in result["metadata"]:
            print("PDF metadata:", result["metadata"]["pdf_metadata"])

        if "exif" in result["metadata"]:
            print("EXIF keys:", list(result["metadata"]["exif"].keys())[:20])

        if "ffprobe" in result["metadata"]:
            fmt = result["metadata"]["ffprobe"].get("format", {})
            print("Video format name:", fmt.get("format_name"))
    else:
        print("No metadata extracted.")

    print("\n(Use --json for full JSON output)")

if __name__ == "__main__":
    main()




"""
response = client.responses.create(
  model="gpt-4.1",
  input="write a haiku about ai",
  store=True,
)
"""