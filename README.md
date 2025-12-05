# Meowlyze 🐱

# 🐾 Meowlyze - Ultimate File Analyzer with Google Gemini AI

![Screenshot Placeholder](https://github.com/mohamediyedmansour/Meowalyze/blob/main/screenshot/screenshot.png?raw=true)

**Website/Blog:** [https://blog.iyed.space](https://blog.iyed.space)

---

## Overview

**Meowlyze** is a **cute, powerful, command-line file analysis tool** built with 🐱 cat vibes! It can analyze files, directories, and archives to extract metadata, summarize content, and provide insights using **Google Gemini AI**.

It works on images, videos, PDFs, text files, and archives (ZIP/TAR), giving you both human-friendly summaries and structured metadata for automation.

---

## Features

- ✅ Analyze any file type: images, videos, PDFs, text, archives.
- ✅ Extract sample content: first few pages of PDFs, first frames of videos, image previews.
- ✅ Compute metadata: file size, type, entropy, hashes.
- ✅ AI-powered summaries using **Google Gemini API**.
- ✅ Parallel processing for multiple files and directories.
- ✅ Cross-platform: Linux, Windows, macOS.
- ✅ Supports archives (ZIP & TAR) for recursive file processing.
- ✅ CLI-friendly, lightweight, cat-themed interface.

---

## Technologies & Libraries

- **Python 3.12+**
- **Google Gemini AI SDK** (`google-genai`)
- **Rich** for colorful terminal output (`rich`)
- **File analysis**:
  - `mimetypes`
  - `zipfile` / `tarfile`
  - Custom `detect_file_type.py`
  - `media_helpers.py` (extract video frames, sample PDF text, sample image bytes)
- **Concurrent futures** for multi-threaded processing
- **Environment variables**: `.env` file with `GEMINI_API_KEY`

---

## Installation

### Linux

```bash
sudo apt update
sudo apt install -y ffmpeg libmagic1 python3-venv python3-pip

# Clone repo
git clone https://github.com/yourusername/Meowlyze.git
cd Meowlyze

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Add as a global command
echo 'meowlyze() {
    ~/path/to/project/.venv/bin/python3 ~/path/to/project/main.py "$@"
}' >> ~/.bashrc
```

### macOS

```bash
brew install ffmpeg libmagic

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Getting Your Google Gemini API Key

1. Go to [AI Studio by Google](https://aistudio.google.com/).
2. Create a project if you don’t have one.
3. Generate an **API key**.
4. Add your key to a `.env` file in the root of the repo:

```env
GEMINI_API_KEY=your_api_key_here
```

---

## Usage

### Basic Command

```bash
python3 main.py /path/to/file_or_directory
```

### Analyze multiple files/directories

```bash
python3 main.py file1.jpg folder1 archive.zip
```

### Save results

- Save as JSON:

```bash
python3 main.py /path/to/files -o results.json
```

- Save as plain text:

```bash
python3 main.py /path/to/files -o results.txt
```

---

## Features in Action

- Summarizes file metadata in a **human-friendly format**.
- Uses **emojis** and **bullet points** for easy reading.
- For images/videos: extracts sample bytes and generates previews.
- For PDFs: extracts first few pages for context.
- Archives: recursively extracts and analyzes contained files.
- Handles errors gracefully and continues processing other files.

---

## Example

```bash
python3 main.py ~/Pictures/MohamedIyedMansour.jpg
```

**Output:**

```
🧠 MohamedIyedMansour.jpg
- Type: image/jpeg
- Size: 2.3 MB
- Entropy: 7.91
- AI Summary: "A portrait of a person, clear lighting, background details minimal..."
```

---

## Running from Anywhere

```bash
cd ~/Downloads
source ~/Projects/Meowlyze/.venv/bin/activate
python3 ~/Projects/Meowlyze/main.py myfile.pdf
```

---

## Contributing

- Fork the repository
- Create a branch for your feature/fix
- Submit a pull request
- Star ⭐ the repo if you enjoy it!

---

## License

MIT License

---

## Contact

**Author:** Iyed Mansour  
**Email:** me@iyed.space  
**Blog:** [https://blog.iyed.space](https://blog.iyed.space)  
**GitHub:** [https://github.com/mohamediyedmansour/Meowlyze](https://github.com/mohamediyedmansour/Meowlyze)

---

### Notes

- Requires **Python 3.12+**
- Requires **Google Gemini API Key**.
- Works with **images, videos, PDFs, text files, ZIP/TAR archives**.
- Handles **bytes safely** for JSON output.
- Includes **parallel processing** for speed.
