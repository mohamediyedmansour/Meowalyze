"""
detect_file_type.py

Ultimate file analyzer. Usage:
    python detect_file_type.py /path/to/file

Or import:
    from detect_file_type import analyze_file
    result = analyze_file("/path/to/file")

Returns a dict with keys:
- file_path, size, type, subtype, mime, extension_guess, confidence,
  hashes, entropy, metadata (dict), analysis (list of strings used)
"""
from __future__ import annotations
import sys
import os
import io
import json
import math
import mimetypes
import hashlib
import zipfile
import tarfile
import struct
import subprocess
from typing import Optional, Dict, Any, Tuple, List

# Optional imports (use if available)
try:
    import magic as py_magic  # python-magic (libmagic wrapper)
except Exception:
    py_magic = None

try:
    from PIL import Image, ExifTags
except Exception:
    Image = None

try:
    import piexif
except Exception:
    piexif = None

try:
    import exifread
except Exception:
    exifread = None

try:
    import PyPDF2
except Exception:
    PyPDF2 = None

try:
    import mutagen
    from mutagen import File as MutagenFile
except Exception:
    mutagen = None

# --------------------------
# Utility helpers
# --------------------------
def read_chunk(path: str, size: int = 8192, offset: int = 0) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)

def compute_hashes(path: str) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def bytes_to_hex(b: bytes, n: int = 32) -> str:
    return b[:n].hex()

def guess_extension_from_magic(magic_desc: Optional[str]) -> Optional[str]:
    if not magic_desc:
        return None
    desc = magic_desc.lower()
    # rough mapping
    if "pdf document" in desc:
        return ".pdf"
    if "jpeg" in desc or "jpg" in desc:
        return ".jpg"
    if "png image" in desc:
        return ".png"
    if "gif image" in desc:
        return ".gif"
    if "zip archive" in desc:
        return ".zip"
    if "mpeg" in desc or "mp3" in desc:
        return ".mp3"
    if "wav" in desc or "riff" in desc:
        return ".wav"
    if "microsoft word" in desc:
        return ".doc"
    if "microsoft excel" in desc:
        return ".xls"
    if "microsoft powerpoint" in desc:
        return ".ppt"
    if "rar archive" in desc:
        return ".rar"
    return None

def safe_text_sample(path: str, max_bytes: int = 4096) -> str:
    b = read_chunk(path, max_bytes, 0)
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc, errors="strict")
        except Exception:
            continue
    # fallback: replacement chars
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return ""

# --------------------------
# Magic header checks
# --------------------------
def identify_by_magic_bytes(path: str, first: bytes) -> Tuple[Optional[str], Optional[str], List[str]]:
    """
    Return (broad_type, subtype, clues)
    """
    clues = []
    if first.startswith(b"%PDF-"):
        clues.append("PDF header %PDF-")
        return "document", "pdf", clues
    if first.startswith(b"\x89PNG\r\n\x1a\n"):
        clues.append("PNG signature")
        return "image", "png", clues
    if first.startswith(b"\xff\xd8\xff"):
        clues.append("JPEG signature")
        return "image", "jpeg", clues
    if first[:6] in (b"GIF87a", b"GIF89a"):
        clues.append("GIF signature")
        return "image", "gif", clues
    # TIFF (II or MM)
    if first[:4] in (b"II*\x00", b"MM\x00*"):
        clues.append("TIFF signature")
        return "image", "tiff", clues
    # PNG already covered
    if first.startswith(b"PK\x03\x04"):
        # ZIP-based: docx, xlsx, pptx, jar, apk
        clues.append("ZIP/PK archive")
        return "archive", "zip", clues
    if first.startswith(b"Rar!\x1a\x07\x00") or first.startswith(b"Rar!\x1a\x07\x01"):
        clues.append("RAR signature")
        return "archive", "rar", clues
    if first.startswith(b"\x1f\x8b\x08"):
        clues.append("GZIP header")
        return "archive", "gzip", clues
    if first.startswith(b"\x7fELF"):
        clues.append("ELF executable")
        return "executable", "elf", clues
    if first.startswith(b"MZ"):
        clues.append("PE/Windows EXE (MZ)")
        return "executable", "pe", clues
    # RIFF-based (WAV, AVI)
    if first[:4] == b"RIFF" and len(first) >= 12 and first[8:12] in (b"WAVE", b"AVI "):
        if first[8:12] == b"WAVE":
            clues.append("RIFF WAVE")
            return "audio", "wav", clues
        else:
            clues.append("RIFF AVI")
            return "video", "avi", clues
    # MP4/ISO ftyp box (ftyp at offset 4)
    if len(first) >= 12 and first[4:8] == b"ftyp":
        # subtype is brand
        brand = first[8:12].decode("ascii", errors="ignore")
        clues.append(f"ISO/MP4 ftyp brand={brand}")
        return "video", "mp4", clues
    # Matroska (MKV) - EBML header: 0x1A45DFA3
    if first.startswith(b"\x1A\x45\xDF\xA3"):
        clues.append("Matroska/EBML (likely mkv/webm)")
        return "video", "mkv", clues
    # PDF already; check for text (heuristic)
    # Check for JSON, XML starts
    stripped = first.lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        clues.append("Starts like JSON")
        return "data", "json", clues
    if stripped.startswith(b"<?xml"):
        clues.append("XML start")
        return "data", "xml", clues
    # Plain text heuristic: many printable ascii bytes in first chunk
    printable = sum(1 for c in first if 32 <= c <= 126 or c in (9,10,13))
    if len(first) > 0 and printable / len(first) > 0.95:
        clues.append("Mostly printable ASCII — likely text")
        return "text", "plain", clues
    # fallback unknown
    clues.append("No known header matched")
    return None, None, clues

# --------------------------
# EXIF / Image analysis
# --------------------------
def analyze_image_common(path: str, result: Dict[str, Any]):
    meta = {}
    try:
        if Image is None:
            result["analysis"].append("Pillow not installed: cannot open image to extract details")
            return meta
        img = Image.open(path)
        meta["format"] = img.format
        meta["mode"] = img.mode
        meta["size"] = img.size
        result["analysis"].append(f"Pillow recognized image format {img.format}")
        # EXIF via piexif or exifread or PIL._getexif
        exif_data = {}
        # Try piexif first
        if piexif:
            try:
                exif_dict = piexif.load(img.info.get("exif", b"")) if img.info.get("exif") else {}
                if exif_dict:
                    exif_data = exif_dict
                    result["analysis"].append("EXIF extracted via piexif")
            except Exception:
                # fallback
                pass
        # Next, exifread (reads from file)
        if not exif_data and exifread:
            try:
                with open(path, "rb") as f:
                    tags = exifread.process_file(f, details=False)
                    if tags:
                        exif_data = {str(k): str(v) for k, v in tags.items()}
                        result["analysis"].append("EXIF extracted via exifread")
            except Exception:
                pass
        # Next, PIL's _getexif
        if not exif_data:
            try:
                raw = getattr(img, "_getexif", None)
                if raw:
                    rawex = img._getexif()
                    if rawex:
                        exif_data = {}
                        for tag, val in rawex.items():
                            name = ExifTags.TAGS.get(tag, tag)
                            exif_data[name] = val
                        result["analysis"].append("EXIF extracted via PIL._getexif")
            except Exception:
                pass
        if exif_data:
            meta["exif"] = exif_data
            # try to parse GPS if present
            gps = {}
            # piexif structure or tag names possible
            if isinstance(exif_data, dict):
                # piexif style nested dict keys "0th", "Exif", "GPS"
                if "GPS" in exif_data:
                    gps = exif_data.get("GPS", {})
                else:
                    # look for GPSLatitude / GPSLongitude or GPS tags in string keys
                    for k, v in exif_data.items():
                        if "GPS" in str(k).upper() or "GPSLatitude" in str(k) or "GPSLongitude" in str(k):
                            gps[k] = v
            if gps:
                meta["gps_raw"] = gps
                # Best-effort convert typical DMS to decimal if present
                try:
                    def _dms_to_deg(dms, ref=None):
                        # dms might be tuple of rational tuples or strings
                        nums = []
                        for part in dms:
                            if isinstance(part, tuple) and len(part) >= 2:
                                # rational
                                nums.append(part[0] / part[1] if part[1] != 0 else 0)
                            else:
                                try:
                                    nums.append(float(part))
                                except Exception:
                                    nums.append(0.0)
                        deg = nums[0] + nums[1] / 60.0 + nums[2] / 3600.0 if len(nums) >= 3 else nums[0]
                        if ref and str(ref).upper() in ("S", "W"):
                            deg = -deg
                        return deg
                    # Many possible tag names; search common ones
                    lat = None; lon = None
                    # piexif style GPS: keys like 1 (N/S), 2 lat, 3 (E/W), 4 lon
                    if isinstance(gps, dict):
                        # common numeric keys:
                        if 2 in gps and 4 in gps:
                            lat = _dms_to_deg(gps.get(2))
                            lon = _dms_to_deg(gps.get(4))
                            ref_lat = gps.get(1)
                            ref_lon = gps.get(3)
                            if ref_lat:
                                lat = _dms_to_deg(gps.get(2), ref_lat)
                            if ref_lon:
                                lon = _dms_to_deg(gps.get(4), ref_lon)
                    # fallback to tag string keys
                    if not lat or not lon:
                        # look for typical keys
                        for k in gps:
                            if "GPSLatitude" in str(k):
                                lat = _dms_to_deg(gps[k])
                            if "GPSLongitude" in str(k):
                                lon = _dms_to_deg(gps[k])
                    if lat and lon:
                        meta["gps"] = {"latitude": lat, "longitude": lon}
                except Exception:
                    pass
        # basic histogram info
        try:
            meta["mode_counts"] = {"bands": getattr(img, "bands", None)}
        except Exception:
            pass
    except Exception as e:
        result["analysis"].append(f"Image analysis error: {e}")
    return meta

# --------------------------
# PDF analysis
# --------------------------
def analyze_pdf(path: str, result: Dict[str, Any]):
    meta = {}
    if PyPDF2 is None:
        result["analysis"].append("PyPDF2 not installed: cannot extract PDF metadata")
        return meta
    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata or reader.getDocumentInfo() if hasattr(reader, "getDocumentInfo") else None
            if info:
                # PyPDF2 returns a DocumentInformation-like object; convert to dict
                meta["pdf_metadata"] = {str(k): str(v) for k, v in (info.items() if hasattr(info, "items") else info)}
                result["analysis"].append("Extracted PDF metadata via PyPDF2")
            # sample text extraction first page (best-effort)
            try:
                if len(reader.pages) > 0:
                    sample = reader.pages[0].extract_text()
                    if sample:
                        meta["sample_text_first_page"] = sample[:4096]
            except Exception:
                pass
            # page count
            try:
                meta["page_count"] = len(reader.pages)
            except Exception:
                pass
    except Exception as e:
        result["analysis"].append(f"PDF parsing error: {e}")
    return meta

# --------------------------
# Audio analysis via mutagen
# --------------------------
def analyze_audio(path: str, result: Dict[str, Any]):
    meta = {}
    if mutagen is None:
        result["analysis"].append("mutagen not installed: cannot parse audio tags")
        return meta
    try:
        audio = MutagenFile(path, easy=True)
        if audio is None:
            result["analysis"].append("mutagen could not identify file as audio")
            return meta
        meta["tags"] = {k: audio.get(k) for k in audio.keys()}
        # duration and bitrate if available
        if hasattr(audio.info, "length"):
            meta["duration_seconds"] = float(audio.info.length)
        if hasattr(audio.info, "bitrate"):
            meta["bitrate"] = getattr(audio.info, "bitrate")
        result["analysis"].append("Audio tags extracted via mutagen")
    except Exception as e:
        result["analysis"].append(f"Audio parsing error: {e}")
    return meta

# --------------------------
# Video analysis via ffprobe (optional)
# --------------------------
def analyze_video_ffprobe(path: str, result: Dict[str, Any]):
    meta = {}
    # try ffprobe if available
    try:
        proc = subprocess.run(
            ["ffprobe", "-v", "error", "-show_format", "-show_streams", "-print_format", "json", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout:
            try:
                video_info = json.loads(proc.stdout)
                meta["ffprobe"] = video_info
                result["analysis"].append("Video metadata extracted via ffprobe")
            except Exception:
                result["analysis"].append("ffprobe returned non-json or parse error")
        else:
            result["analysis"].append("ffprobe not available or failed")
    except FileNotFoundError:
        result["analysis"].append("ffprobe not found on PATH")
    except Exception as e:
        result["analysis"].append(f"ffprobe error: {e}")
    return meta

# --------------------------
# Office / ZIP analysis
# --------------------------
def analyze_zip_office(path: str, result: Dict[str, Any]):
    meta = {}
    try:
        with zipfile.ZipFile(path, 'r') as z:
            names = z.namelist()
            meta["entries_count"] = len(names)
            meta["top_entries"] = names[:50]
            result["analysis"].append("ZIP archive opened to analyze entries")
            # detect office types by presence of [Content_Types].xml or docProps/core.xml and word/ etc
            if any(n.startswith("word/") for n in names) or "word/document.xml" in names:
                meta["office_type"] = "docx"
            elif any(n.startswith("ppt/") for n in names) or "ppt/presentation.xml" in names:
                meta["office_type"] = "pptx"
            elif any(n.startswith("xl/") for n in names) or "xl/workbook.xml" in names:
                meta["office_type"] = "xlsx"
            if "docProps/core.xml" in names:
                try:
                    core = z.read("docProps/core.xml")
                    # basic string extract of common tags
                    s = core.decode("utf-8", errors="ignore")
                    meta.setdefault("office_core_xml", {})["raw"] = s[:2000]
                    # simple extractions
                    for tag in ("creator", "title", "subject", "description", "lastModifiedBy"):
                        open_tag = f"<{tag}"
                        if open_tag in s:
                            # naive extract
                            start = s.find(open_tag)
                            snippet = s[start:start+200]
                            meta.setdefault("office_core_xml", {}).setdefault("hints", []).append(snippet)
                    result["analysis"].append("Extracted docProps/core.xml hints from Office docx/xlsx/pptx")
                except Exception:
                    pass
    except Exception as e:
        result["analysis"].append(f"ZIP analysis error: {e}")
    return meta

# --------------------------
# Executable analysis (light)
# --------------------------
def analyze_executable(path: str, first: bytes, result: Dict[str, Any]):
    meta = {}
    try:
        if first.startswith(b"\x7fELF"):
            # ELF header: extract class: 1 = 32-bit, 2 = 64-bit
            if len(first) >= 5:
                ei_class = first[4]
                meta["elf_class"] = "64-bit" if ei_class == 2 else "32-bit"
                result["analysis"].append(f"ELF executable ({meta['elf_class']})")
        elif first.startswith(b"MZ"):
            # PE header: need to read at offset from DOS header e_lfanew
            with open(path, "rb") as f:
                f.seek(0x3c)
                e_lfanew_bytes = f.read(4)
                if len(e_lfanew_bytes) == 4:
                    e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]
                    f.seek(e_lfanew)
                    sig = f.read(4)
                    if sig == b"PE\x00\x00":
                        # machine type
                        machine_bytes = f.read(2)
                        if len(machine_bytes) == 2:
                            machine = struct.unpack("<H", machine_bytes)[0]
                            meta["pe_machine"] = hex(machine)
                            arch = {0x014c: "x86", 0x0200: "Intel Itanium", 0x8664: "x64"}.get(machine, "unknown")
                            meta["pe_arch"] = arch
                            result["analysis"].append(f"PE executable detected (arch={arch})")
    except Exception as e:
        result["analysis"].append(f"Executable analysis error: {e}")
    return meta

# --------------------------
# Archive analysis (tar)
# --------------------------
def analyze_tar(path: str, result: Dict[str, Any]):
    meta = {}
    try:
        if tarfile.is_tarfile(path):
            with tarfile.open(path, 'r:*') as t:
                names = t.getnames()
                meta["entries_count"] = len(names)
                meta["top_entries"] = names[:50]
                result["analysis"].append("Tar archive inspected")
    except Exception as e:
        result["analysis"].append(f"Tarfile analysis error: {e}")
    return meta

# --------------------------
# Text heuristics
# --------------------------
def analyze_text(path: str, result: Dict[str, Any]):
    meta = {}
    sample = safe_text_sample(path, 8192)
    meta["sample"] = sample[:2000]
    # heuristics: look for XML, HTML, JSON, code shebangs
    lowered = sample.lstrip().lower()[:200]
    if lowered.startswith("<!doctype html") or "<html" in lowered:
        meta["subtype_hint"] = "html"
        result["analysis"].append("Text looks like HTML")
    elif lowered.startswith("{") or lowered.startswith("["):
        meta["subtype_hint"] = "json"
        result["analysis"].append("Text looks like JSON")
    elif lowered.startswith("#!") or lowered.startswith("import ") or "def " in sample[:400]:
        result["analysis"].append("Text may be source code or script")
    return meta

# --------------------------
# Main orchestrator
# --------------------------
def analyze_file(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    result: Dict[str, Any] = {
        "file_path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "type": None,
        "subtype": None,
        "mime": None,
        "extension_guess": None,
        "confidence": 0.0,
        "hashes": {},
        "entropy": None,
        "metadata": {},
        "analysis": [],
        "header_hex": None,
    }

    # compute hashes
    try:
        result["hashes"] = compute_hashes(path)
    except Exception as e:
        result["analysis"].append(f"Hashing failed: {e}")

    # read first 16KB for heuristics
    first = read_chunk(path, 16384, 0)
    result["header_hex"] = bytes_to_hex(first, 128)
    result["entropy"] = shannon_entropy(first)

    # try python-magic if available
    magic_desc = None
    if py_magic:
        try:
            ms = py_magic.from_file(path)
            magic_desc = ms
            result["analysis"].append(f"libmagic says: {ms}")
            guessed_ext = guess_extension_from_magic(ms)
            if guessed_ext:
                result["extension_guess"] = guessed_ext
        except Exception as e:
            result["analysis"].append(f"python-magic failed: {e}")

    # fallback to mimetypes based on extension
    ext = os.path.splitext(path)[1].lower()
    if ext:
        mime_ext = mimetypes.guess_type(path)[0]
        if mime_ext:
            result["analysis"].append(f"mimetypes.guess: {mime_ext} (from extension {ext})")
            if not result.get("mime"):
                result["mime"] = mime_ext
        if not result["extension_guess"]:
            result["extension_guess"] = ext

    # identify by magic bytes
    broad, subtype, clues = identify_by_magic_bytes(path, first)
    result["analysis"].extend(clues)
    if broad:
        result["type"] = broad
        result["subtype"] = subtype
        result["confidence"] = max(result["confidence"], 0.9)

    # if python-magic gave mime, set it
    if magic_desc and not result.get("mime"):
        # a crude mapping: sometimes magic_desc contains mime phrase
        result["mime"] = magic_desc

    # deep analysis by determined type or fallback heuristics
    if result["type"] == "image" or (result["mime"] and "image" in str(result["mime"]).lower()):
        result["metadata"].update(analyze_image_common(path, result))
    if result["type"] == "document" and result["subtype"] == "pdf" or (result["mime"] and "pdf" in str(result["mime"]).lower()):
        result["metadata"].update(analyze_pdf(path, result))
    if result["type"] == "audio" or (result["mime"] and "audio" in str(result["mime"]).lower()):
        result["metadata"].update(analyze_audio(path, result))
    # video
    if result["type"] == "video" or (result["mime"] and "video" in str(result["mime"]).lower()):
        result["metadata"].update(analyze_video_ffprobe(path, result))
    # archive/zip/office
    if result["subtype"] == "zip" or (result["mime"] and "zip" in str(result["mime"]).lower()) or (py_magic and "zip" in str(magic_desc).lower() if magic_desc else False):
        # check for office
        result["metadata"].update(analyze_zip_office(path, result))
        # also list zip top entries (already done)
    # tar
    if tarfile.is_tarfile(path):
        result["metadata"].update(analyze_tar(path, result))
    # executables
    if result["type"] == "executable":
        result["metadata"].update(analyze_executable(path, first, result))
    # additional audio/video heuristics: check file extension if not set
    if not result["type"]:
        # use magic_desc text to guess
        if magic_desc:
            md = magic_desc.lower()
            if "pdf" in md:
                result["type"], result["subtype"] = "document", "pdf"
                result["confidence"] = 0.85
                result["metadata"].update(analyze_pdf(path, result))
            elif "jpeg" in md or "jpg" in md:
                result["type"], result["subtype"] = "image", "jpeg"
                result["confidence"] = 0.85
                result["metadata"].update(analyze_image_common(path, result))
            elif "png" in md:
                result["type"], result["subtype"] = "image", "png"
                result["confidence"] = 0.85
                result["metadata"].update(analyze_image_common(path, result))
            elif "mp3" in md or "mpeg" in md:
                result["type"], result["subtype"] = "audio", "mp3"
                result["confidence"] = 0.8
                result["metadata"].update(analyze_audio(path, result))
            elif "xml" in md:
                result["type"], result["subtype"] = "data", "xml"
                result["confidence"] = 0.7
        # last fallback: if text-like
        if not result["type"]:
            text_sample = safe_text_sample(path, 2048)
            printable = sum(1 for c in text_sample.encode("utf-8", errors="ignore") if 32 <= c <= 126 or c in (9,10,13))
            if text_sample and (len(text_sample) == 0 or printable / max(1, len(text_sample)) > 0.5):
                result["type"] = "text"
                result["subtype"] = "plain"
                result["confidence"] = 0.6
                result["metadata"].update(analyze_text(path, result))

    # finalize MIME if not set: try python-magic MIME type
    if not result.get("mime") and py_magic:
        try:
            m = py_magic.from_file(path, mime=True)
            result["mime"] = m
        except Exception:
            pass

    # Some final heuristics for confidence
    if result["type"] and result["confidence"] < 0.5:
        # bump a bit if we have metadata or hashes
        if result["metadata"]:
            result["confidence"] = max(result["confidence"], 0.65)
        else:
            result["confidence"] = max(result["confidence"], 0.5)

    # Useful top-level hints
    if not result["analysis"]:
        result["analysis"].append("No specific analysis clues found")

    return result
