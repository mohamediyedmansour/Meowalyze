import cv2
from PyPDF2 import PdfReader

def extract_video_frame(path: str, max_width: int = 512) -> bytes:
    """Extract the first frame of a video and return it as JPEG bytes"""
    try:
        cap = cv2.VideoCapture(path)
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return None
        # Resize frame if needed
        height, width = frame.shape[:2]
        if width > max_width:
            ratio = max_width / width
            frame = cv2.resize(frame, (int(width * ratio), int(height * ratio)))
        # Encode as JPEG
        ret, buf = cv2.imencode(".jpg", frame)
        return buf.tobytes() if ret else None
    except Exception:
        return None

def sample_pdf_text(path: str, max_pages: int = 2) -> str:
    """Extract text from first few pages of a PDF"""
    try:
        reader = PdfReader(path)
        text = ""
        for i, page in enumerate(reader.pages):
            if i >= max_pages:
                break
            text += page.extract_text() or ""
        return text.strip()
    except Exception:
        return ""

def sample_file_bytes(path: str, max_bytes: int = 1024*1024) -> bytes:
    """Read the first max_bytes of a file"""
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""
