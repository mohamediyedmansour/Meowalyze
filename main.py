import os
import sys
import json
import argparse
import tempfile
import zipfile
import shutil
import concurrent.futures
from pathlib import Path
from functools import partial

from dotenv import load_dotenv
import mimetypes
import tarfile

# Gemini SDK
from google import genai
from google.genai import types

# Rich for terminal output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import track
except ImportError:
    Console = None
    def track(it, **kwargs):
        return it
    def Panel(content, **kwargs):
        return content

# Your existing analyzer
from utils.detect_file_type import analyze_file

# Helpers for images/videos/PDF sampling
from utils.media_helpers import extract_video_frame, sample_pdf_text, sample_file_bytes

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
print(GEMINI_API_KEY)
if not GEMINI_API_KEY:
    raise RuntimeError("Please set GEMINI_API_KEY in your environment")

client = genai.Client(api_key=GEMINI_API_KEY)

console = Console() if Console else None

# ----------------------------
# Gemini Helper
# ----------------------------
def send_to_gemini(prompt: str, parts: list = None, max_retries=3) -> str:
    for attempt in range(max_retries):
        try:
            if parts:
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=parts + [prompt]
                )
            else:
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
            return response.text
        except Exception as e:
            if attempt < max_retries - 1:
                continue
            else:
                return f"⚠️ Gemini API failed: {e}"

# ----------------------------
# File Processing
# ----------------------------
def process_file(path: str) -> dict:
    """Analyze file, generate AI summary, return structured result"""
    try:
        res = analyze_file(path)
    except Exception as e:
        return {"path": path, "error": str(e)}

    # Handle special types
    parts = []

    # Images: send sample bytes
    if res.get("type") == "image":
        try:
            data = sample_file_bytes(path, 1024*1024)  # 1 MB max
            part = types.Part.from_bytes(data=data, mime_type=res.get("mime", "image/jpeg"))
            parts.append(part)
        except Exception as e:
            res.setdefault("analysis", []).append(f"Image sampling failed: {e}")

    # PDFs: sample first few pages
    if res.get("subtype") == "pdf":
        try:
            pdf_sample = sample_pdf_text(path, max_pages=2)
            res["metadata"]["pdf_sample"] = pdf_sample
        except Exception as e:
            res.setdefault("analysis", []).append(f"PDF sampling failed: {e}")

    # Videos: extract first frame and sample
    if res.get("type") == "video":
        try:
            frame_bytes = extract_video_frame(path, max_width=512)
            if frame_bytes:
                part = types.Part.from_bytes(data=frame_bytes, mime_type="image/jpeg")
                parts.append(part)
        except Exception as e:
            res.setdefault("analysis", []).append(f"Video frame extraction failed: {e}")

    # Build prompt for AI
    json_snippet = json.dumps(res, indent=2, ensure_ascii=False)
    prompt = f"""
You are a file analysis assistant. Summarize the following file metadata in human-friendly terms.
- Highlight the file type, size, entropy, potential unusual properties.
- Use emojis and bullet points.
- Only include important information, ignore trivial details.
- If it's an image/video, summarize its content briefly.
- If it's a PDF/text, summarize content snippets.
- Do not be overly childish be a professional and consistent summarizer.
File: {os.path.basename(path)}
Metadata:
{json_snippet}
"""

    summary = send_to_gemini(prompt, parts=parts)

    return {"path": path, "summary": summary, "important_metadata": res}

# ----------------------------
# ZIP/TAR Handling
# ----------------------------
def expand_archives(path: str, tmpdir: str) -> list:
    """Extract ZIP/TAR files into tmpdir and return list of contained files"""
    files = []
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as z:
                z.extractall(tmpdir)
                for f in z.namelist():
                    files.append(os.path.join(tmpdir, f))
        except Exception as e:
            if console:
                console.print(f"⚠️ Failed to extract ZIP {path}: {e}")
    elif tarfile.is_tarfile(path):
        try:
            with tarfile.open(path, "r") as t:
                t.extractall(tmpdir)
                for f in t.getnames():
                    files.append(os.path.join(tmpdir, f))
        except Exception as e:
            if console:
                console.print(f"⚠️ Failed to extract TAR {path}: {e}")
    return files

# ----------------------------
# Parallel Processing
# ----------------------------
def process_paths(paths: list) -> list:
    """Process multiple paths in parallel"""
    results = []
    tmpdir = tempfile.mkdtemp()
    try:
        all_files = []
        for path in paths:
            path = os.path.abspath(path)
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for fname in files:
                        all_files.append(os.path.join(root, fname))
            elif zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
                extracted_files = expand_archives(path, tmpdir)
                all_files.extend(extracted_files)
            else:
                all_files.append(path)

        if console:
            iterator = track(all_files, description="Processing files…")
        else:
            iterator = all_files

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for result in executor.map(process_file, iterator):
                results.append(result)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return results

# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Ultimate File Analyzer with Google Gemini")
    parser.add_argument("paths", nargs="+", help="Files, directories, or archives to analyze")
    parser.add_argument("-o", "--output", help="Save results to file (txt or json)")
    args = parser.parse_args()

    results = process_paths(args.paths)

    # Output nicely
    for entry in results:
        if "error" in entry:
            if console:
                console.print(f"⚠️ {entry['path']}: {entry['error']}")
            else:
                print(f"{entry['path']}: {entry['error']}")
            continue
        panel = Panel(entry["summary"], title=f"🧠 {os.path.basename(entry['path'])}", expand=False)
        if console:
            console.print(panel)
        else:
            print(entry["summary"])
    
    # Save if requested
    if args.output:
        out_path = args.output
        if out_path.endswith(".json"):
            # Only save AI-selected important metadata + summary
            simple_output = [
                {
                    "path": r["path"],
                    "summary": r.get("summary"),
                    "important_metadata": r.get("important_metadata")
                } for r in results
            ]
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(simple_output, f, ensure_ascii=False, indent=2)
        else:
            # Save as plain text
            with open(out_path, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(f"File: {r['path']}\n")
                    f.write(f"{r.get('summary')}\n\n")

if __name__ == "__main__":
    main()
