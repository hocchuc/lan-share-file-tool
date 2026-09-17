#!/usr/bin/env python3
"""
LAN File Transfer Server
A fast, lightweight, zero-dependency file sharing server for your local network.
Allows phones, tablets, and computers on the same Wi-Fi/LAN to upload and download files.
"""

import os
import sys
import json
import time
import socket
import urllib.parse
import urllib.request
import urllib.error
import mimetypes
from pathlib import Path
from http import HTTPStatus
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
import re
import argparse

# Default configuration
DEFAULT_PORT = 8080
DEFAULT_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

# Shared in-memory notes/messages
SHARED_NOTES = []
PINNED_FILE_NAME = ".pinned.json"
LABELS_FILE_NAME = ".labels.json"
NOTES_FILE_NAME = ".notes.json"

def sanitize_label(label):
    """Normalize label: enforce maximum 50 characters, disallowing spaces between words."""
    if not label:
        return ""
    clean = str(label).strip().lstrip("#").strip()
    clean = clean.replace("/", "").replace("\\", "").replace("\x00", "")
    # Disallow spaces between words by converting whitespace sequences to hyphens
    clean = re.sub(r"\s+", "-", clean)
    return clean[:50]

def get_labels_data(upload_dir):
    """Load labels dictionary {files: {filename: [labels]}, notes: {note_id: [labels]}}."""
    path = os.path.join(upload_dir, LABELS_FILE_NAME)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("files", {})
                    data.setdefault("notes", {})
                    return data
        except Exception:
            pass
    return {"files": {}, "notes": {}}

def save_labels_data(upload_dir, data):
    """Save labels dictionary to disk."""
    path = os.path.join(upload_dir, LABELS_FILE_NAME)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def get_saved_notes(upload_dir):
    """Load notes array from disk."""
    path = os.path.join(upload_dir, NOTES_FILE_NAME)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
    return []

def save_notes_to_disk(upload_dir, notes_list):
    """Save notes array to disk."""
    path = os.path.join(upload_dir, NOTES_FILE_NAME)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(notes_list, f, indent=2)
    except Exception:
        pass

def get_pinned_files(upload_dir):
    """Load list of pinned filenames."""
    pinned_path = os.path.join(upload_dir, PINNED_FILE_NAME)
    if os.path.exists(pinned_path):
        try:
            with open(pinned_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
    return []

def save_pinned_files(upload_dir, pinned_list):
    """Save list of pinned filenames to disk."""
    pinned_path = os.path.join(upload_dir, PINNED_FILE_NAME)
    try:
        with open(pinned_path, "w", encoding="utf-8") as f:
            json.dump(pinned_list, f, indent=2)
    except Exception:
        pass


def get_lan_ips():
    """Detect all active LAN IPv4 addresses."""
    ips = []
    # Check if custom LAN IP is passed via environment variable (useful in Docker containers)
    custom_ip = os.environ.get("LAN_IP") or os.environ.get("HOST_IP")
    if custom_ip and custom_ip.strip() and not custom_ip.strip().startswith("127."):
        ips.append(custom_ip.strip())

    # Primary route IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and not primary.startswith("127.") and primary not in ips:
            ips.append(primary)
    except Exception:
        pass

    # Additional interface IPs
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip not in ips and not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.append(ip)
    except Exception:
        pass

    if not ips:
        ips.append("127.0.0.1")
    return ips


def format_size(size_bytes):
    """Format bytes to human readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def sanitize_filename(filename):
    """Remove unsafe path traversal elements and keep file name safe."""
    # Take basename
    name = os.path.basename(filename).strip()
    # Replace dangerous path characters
    name = name.replace("/", "_").replace("\\", "_").replace("\x00", "")
    if not name or name in ('.', '..'):
        name = f"uploaded_{int(time.time())}"
    return name


def get_unique_path(directory, filename):
    """Generate a unique filepath if the file already exists."""
    dest = os.path.join(directory, filename)
    if not os.path.exists(dest):
        return dest

    base, ext = os.path.splitext(filename)
    counter = 1
    while True:
        candidate = f"{base} ({counter}){ext}"
        dest = os.path.join(directory, candidate)
        if not os.path.exists(dest):
            return dest
        counter += 1


class StreamingMultipartParser:
    """
    Zero-dependency streaming parser for multipart/form-data.
    Streams large files directly to disk in chunks without loading into RAM.
    """

    def __init__(self, rfile, content_length, boundary):
        self.rfile = rfile
        self.content_length = content_length
        self.boundary = boundary
        self.boundary_bytes = boundary.encode("latin1")
        self.delimiter = b"--" + self.boundary_bytes
        self.end_delimiter = b"--" + self.boundary_bytes + b"--"
        self.bytes_read = 0
        self.buffer = bytearray()
        self.chunk_size = 64 * 1024  # 64 KB chunks

    def _read_more(self):
        if self.content_length is not None and self.bytes_read >= self.content_length:
            return False
        to_read = self.chunk_size
        if self.content_length is not None:
            to_read = min(to_read, self.content_length - self.bytes_read)
        if to_read <= 0:
            return False
        data = self.rfile.read(to_read)
        if not data:
            return False
        self.bytes_read += len(data)
        self.buffer.extend(data)
        return True

    def parse_headers(self):
        """Read headers for a part up to CRLF CRLF."""
        while True:
            sep_idx = self.buffer.find(b"\r\n\r\n")
            if sep_idx != -1:
                header_raw = self.buffer[:sep_idx].decode("utf-8", errors="replace")
                del self.buffer[:sep_idx + 4]
                headers = {}
                for line in header_raw.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                return headers
            if not self._read_more():
                return None

    def parse_to_destination(self, upload_dir):
        """
        Parses all parts. Saves files directly to upload_dir.
        Returns list of dicts with uploaded file info.
        """
        uploaded_files = []

        # Find first boundary
        while True:
            idx = self.buffer.find(self.delimiter)
            if idx != -1:
                del self.buffer[:idx + len(self.delimiter)]
                # Check for CRLF right after boundary
                if len(self.buffer) >= 2 and self.buffer[:2] == b"\r\n":
                    del self.buffer[:2]
                break
            if not self._read_more():
                return uploaded_files

        # Iterate over parts
        while True:
            # Check if this was the closing delimiter
            if len(self.buffer) >= 2 and self.buffer[:2] == b"--":
                break

            headers = self.parse_headers()
            if headers is None:
                break

            disp = headers.get("content-disposition", "")
            filename = None
            field_name = ""

            for part in disp.split(";"):
                part = part.strip()
                if part.startswith("filename*="):
                    # RFC 5987 encoded filename
                    try:
                        _, encoded = part.split("=", 1)
                        if "''" in encoded:
                            encoding, val = encoded.split("''", 1)
                            filename = urllib.parse.unquote(val, encoding=encoding)
                    except Exception:
                        pass
                elif part.startswith("filename=") and not filename:
                    val = part.split("=", 1)[1].strip('"\'')
                    filename = val
                elif part.startswith("name="):
                    field_name = part.split("=", 1)[1].strip('"\'')

            if filename:
                safe_name = sanitize_filename(filename)
                target_path = get_unique_path(upload_dir, safe_name)
                actual_name = os.path.basename(target_path)
                bytes_written = 0

                search_delimiter = b"\r\n" + self.delimiter
                with open(target_path, "wb") as out_file:
                    while True:
                        idx = self.buffer.find(search_delimiter)
                        if idx != -1:
                            # Write everything up to the delimiter
                            out_file.write(self.buffer[:idx])
                            bytes_written += idx
                            del self.buffer[:idx + len(search_delimiter)]
                            # Skip optional \r\n after delimiter
                            if len(self.buffer) >= 2 and self.buffer[:2] == b"\r\n":
                                del self.buffer[:2]
                            break
                        else:
                            # Keep buffer safe from cutting delimiter in half
                            safe_len = max(0, len(self.buffer) - len(search_delimiter))
                            if safe_len > 0:
                                out_file.write(self.buffer[:safe_len])
                                bytes_written += safe_len
                                del self.buffer[:safe_len]

                            if not self._read_more():
                                # Stream ended
                                if len(self.buffer) > 0:
                                    out_file.write(self.buffer)
                                    bytes_written += len(self.buffer)
                                    self.buffer.clear()
                                break

                uploaded_files.append({
                    "name": actual_name,
                    "original_name": filename,
                    "size": bytes_written,
                    "size_formatted": format_size(bytes_written),
                    "path": target_path
                })
            else:
                # Regular form field: skip or discard value
                search_delimiter = b"\r\n" + self.delimiter
                while True:
                    idx = self.buffer.find(search_delimiter)
                    if idx != -1:
                        del self.buffer[:idx + len(search_delimiter)]
                        if len(self.buffer) >= 2 and self.buffer[:2] == b"\r\n":
                            del self.buffer[:2]
                        break
                    else:
                        safe_len = max(0, len(self.buffer) - len(search_delimiter))
                        if safe_len > 0:
                            del self.buffer[:safe_len]
                        if not self._read_more():
                            self.buffer.clear()
                            break

            # Check if terminating boundary follows
            if len(self.buffer) >= 2 and self.buffer[:2] == b"--":
                break

        return uploaded_files


class LanFileHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for LAN File Transfer."""

    server_version = "LANFileServer/1.0"

    def send_json(self, data, status=HTTPStatus.OK):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_ui()
        elif path == "/api/files":
            self.serve_files_list()
        elif path == "/api/notes":
            self.serve_notes_list()
        elif path.startswith("/download/"):
            filename = urllib.parse.unquote(path[len("/download/"):])
            self.serve_file_content(filename, as_attachment=True)
        elif path.startswith("/view/"):
            filename = urllib.parse.unquote(path[len("/view/"):])
            self.serve_file_content(filename, as_attachment=False)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/upload":
            self.handle_upload()
        elif path == "/api/delete":
            self.handle_delete()
        elif path == "/api/pin":
            self.handle_toggle_pin()
        elif path == "/api/label":
            self.handle_label_update()
        elif path == "/api/notes":
            self.handle_add_note()
        elif path == "/api/notes/clear":
            self.handle_clear_notes()
        elif path == "/api/note/delete":
            self.handle_delete_note()
        elif path == "/api/proxy":
            self.handle_proxy()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def serve_ui(self):
        """Serve the single-page responsive Web UI."""
        lan_ips = getattr(self.server, "lan_ips", [self.server.primary_ip])
        html = UI_HTML.replace("__PRIMARY_IP__", self.server.primary_ip)
        html = html.replace("__PORT__", str(self.server.server_port))
        html = html.replace("__ALL_IPS_JSON__", json.dumps(lan_ips))
        content = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def serve_files_list(self):
        """Return JSON listing of files in upload directory."""
        upload_dir = self.server.upload_dir
        files_data = []
        pinned_list = get_pinned_files(upload_dir)
        labels_data = get_labels_data(upload_dir)
        file_labels = labels_data.get("files", {})

        all_labels = set()
        for lbl_list in file_labels.values():
            all_labels.update(lbl_list)
        for note in SHARED_NOTES:
            all_labels.update(note.get("labels", []))

        if os.path.exists(upload_dir):
            try:
                entries = sorted(
                    os.scandir(upload_dir),
                    key=lambda e: e.stat().st_mtime,
                    reverse=True
                )
                for entry in entries:
                    if entry.is_file() and not entry.name.startswith("."):
                        stat = entry.stat()
                        mime_type, _ = mimetypes.guess_type(entry.name)
                        mime_type = mime_type or "application/octet-stream"

                        is_image = mime_type.startswith("image/")
                        is_video = mime_type.startswith("video/")
                        is_audio = mime_type.startswith("audio/")
                        file_lbls = file_labels.get(entry.name, [])

                        files_data.append({
                            "name": entry.name,
                            "size": stat.st_size,
                            "size_formatted": format_size(stat.st_size),
                            "mtime": stat.st_mtime,
                            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                            "mime_type": mime_type,
                            "is_image": is_image,
                            "is_video": is_video,
                            "is_audio": is_audio,
                            "is_pinned": entry.name in pinned_list,
                            "labels": file_lbls
                        })
            except Exception as e:
                self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return

        self.send_json({
            "files": files_data,
            "pinned": pinned_list,
            "all_labels": sorted(list(all_labels)),
            "upload_dir": os.path.abspath(upload_dir)
        })

    def serve_notes_list(self):
        upload_dir = self.server.upload_dir
        labels_data = get_labels_data(upload_dir)
        all_labels = set()
        for lbl_list in labels_data.get("files", {}).values():
            all_labels.update(lbl_list)
        for note in SHARED_NOTES:
            all_labels.update(note.get("labels", []))

        self.send_json({
            "notes": SHARED_NOTES,
            "all_labels": sorted(list(all_labels))
        })

    def handle_add_note(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            text = data.get("text", "").strip()
            title = data.get("title", "").strip()[:50]
            raw_labels = data.get("labels", [])
            clean_labels = []

            if isinstance(raw_labels, list):
                for l in raw_labels:
                    c = sanitize_label(l)
                    if c and c not in clean_labels:
                        clean_labels.append(c)
            elif isinstance(raw_labels, str):
                for l in raw_labels.split(","):
                    c = sanitize_label(l)
                    if c and c not in clean_labels:
                        clean_labels.append(c)

            if text:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                note = {
                    "id": int(time.time() * 1000),
                    "title": title,
                    "text": text,
                    "labels": clean_labels,
                    "date": time.strftime("%H:%M:%S"),
                    "full_date": timestamp,
                    "sender": self.client_address[0]
                }
                SHARED_NOTES.insert(0, note)
                if len(SHARED_NOTES) > 100:
                    SHARED_NOTES.pop()

                save_notes_to_disk(self.server.upload_dir, SHARED_NOTES)

                # Print to terminal with clear banner
                lbl_str = f" [Tags: {', '.join(clean_labels)}]" if clean_labels else ""
                title_str = f" - '{title}'" if title else ""
                print("\n" + "─" * 60)
                print(f"💬 [NEW NOTE RECEIVED{title_str}{lbl_str}] from {self.client_address[0]} at {timestamp}:")
                print(f"{text}")
                print("─" * 60 + "\n")

                # Also append to a persistent notes file in uploads/
                try:
                    notes_file = os.path.join(self.server.upload_dir, "clipboard_notes.txt")
                    with open(notes_file, "a", encoding="utf-8") as f:
                        header = f"[{timestamp}] from {self.client_address[0]}"
                        if title: header += f" ({title})"
                        if clean_labels: header += f" [Labels: {', '.join(clean_labels)}]"
                        f.write(f"{header}:\n{text}\n\n")
                except Exception:
                    pass

                self.send_json({"success": True, "note": note})
            else:
                self.send_json({"error": "Empty text"}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_clear_notes(self):
        SHARED_NOTES.clear()
        save_notes_to_disk(self.server.upload_dir, SHARED_NOTES)
        self.send_json({"success": True})

    def handle_delete_note(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            note_id = data.get("id")
            if note_id is not None:
                note_id_val = int(note_id) if str(note_id).isdigit() else note_id
                global SHARED_NOTES
                SHARED_NOTES = [n for n in SHARED_NOTES if n.get("id") != note_id_val]
                save_notes_to_disk(self.server.upload_dir, SHARED_NOTES)
                self.send_json({"success": True, "id": note_id})
            else:
                self.send_json({"error": "Missing note id"}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_label_update(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            target_type = data.get("type", "file")
            item_id = str(data.get("id", "")).strip()
            label = sanitize_label(data.get("label", ""))
            action = data.get("action", "add")

            if not item_id or not label:
                self.send_json({"error": "Missing item ID or label"}, status=HTTPStatus.BAD_REQUEST)
                return

            upload_dir = self.server.upload_dir
            labels_data = get_labels_data(upload_dir)

            if target_type == "note":
                note_id_int = int(item_id) if item_id.isdigit() else item_id
                updated_labels = []
                for note in SHARED_NOTES:
                    if note.get("id") == note_id_int:
                        note.setdefault("labels", [])
                        if action == "add":
                            if label not in note["labels"] and len(label) <= 10:
                                note["labels"].append(label)
                        elif action == "remove":
                            if label in note["labels"]:
                                note["labels"].remove(label)
                        updated_labels = note["labels"]
                        break
                save_notes_to_disk(upload_dir, SHARED_NOTES)
                self.send_json({"success": True, "type": "note", "id": item_id, "labels": updated_labels})
            else:
                safe_name = sanitize_filename(item_id)
                file_map = labels_data.setdefault("files", {})
                current = file_map.setdefault(safe_name, [])
                if action == "add":
                    if label not in current and len(label) <= 10:
                        current.append(label)
                elif action == "remove":
                    if label in current:
                        current.remove(label)
                save_labels_data(upload_dir, labels_data)
                self.send_json({"success": True, "type": "file", "id": safe_name, "labels": current})
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_toggle_pin(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            filename = data.get("filename", "")
            if filename:
                safe_name = sanitize_filename(filename)
                pinned = get_pinned_files(self.server.upload_dir)
                if safe_name in pinned:
                    pinned.remove(safe_name)
                    is_pinned = False
                else:
                    pinned.append(safe_name)
                    is_pinned = True
                save_pinned_files(self.server.upload_dir, pinned)
                self.send_json({"success": True, "filename": safe_name, "is_pinned": is_pinned})
            else:
                self.send_json({"error": "Missing filename"}, status=HTTPStatus.BAD_REQUEST)
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_delete(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            filename = data.get("filename", "")
            safe_name = sanitize_filename(filename)
            target = os.path.join(self.server.upload_dir, safe_name)

            if os.path.exists(target) and os.path.isfile(target):
                os.remove(target)
                # Remove from pinned
                pinned = get_pinned_files(self.server.upload_dir)
                if safe_name in pinned:
                    pinned.remove(safe_name)
                    save_pinned_files(self.server.upload_dir, pinned)
                # Remove from labels
                labels_data = get_labels_data(self.server.upload_dir)
                if safe_name in labels_data.get("files", {}):
                    del labels_data["files"][safe_name]
                    save_labels_data(self.server.upload_dir, labels_data)

                self.send_json({"success": True, "message": f"Deleted {safe_name}"})
            else:
                self.send_json({"error": "File not found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_proxy(self):
        """Proxy HTTP requests to bypass CORS restrictions for OpenAPI tester."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            target_url = data.get("url", "").strip()
            method = data.get("method", "GET").upper()
            headers = data.get("headers", {})
            req_body = data.get("body", None)

            if not target_url:
                self.send_json({"error": "Missing target URL"}, status=HTTPStatus.BAD_REQUEST)
                return

            req_bytes = None
            if req_body is not None:
                if isinstance(req_body, str):
                    req_bytes = req_body.encode("utf-8")
                else:
                    req_bytes = json.dumps(req_body).encode("utf-8")

            # Filter headers to avoid conflicts
            forward_headers = {k: str(v) for k, v in headers.items() if k.lower() not in ("host", "content-length")}
            if req_bytes is not None and not any(k.lower() == "content-type" for k in forward_headers):
                forward_headers["Content-Type"] = "application/json"

            req = urllib.request.Request(target_url, data=req_bytes, headers=forward_headers, method=method)

            start_time = time.time()
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_bytes = resp.read()
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    try:
                        resp_text = resp_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        resp_text = resp_bytes.decode("latin-1", errors="replace")

                    self.send_json({
                        "status": resp.status,
                        "statusText": resp.reason,
                        "headers": dict(resp.headers),
                        "data": resp_text,
                        "elapsedMs": elapsed_ms
                    })
            except urllib.error.HTTPError as he:
                elapsed_ms = int((time.time() - start_time) * 1000)
                err_bytes = he.read()
                try:
                    err_text = err_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    err_text = err_bytes.decode("latin-1", errors="replace")
                self.send_json({
                    "status": he.code,
                    "statusText": he.reason,
                    "headers": dict(he.headers),
                    "data": err_text,
                    "elapsedMs": elapsed_ms
                })
            except urllib.error.URLError as ue:
                elapsed_ms = int((time.time() - start_time) * 1000)
                self.send_json({
                    "error": str(ue.reason),
                    "status": 0,
                    "statusText": "Network Error",
                    "elapsedMs": elapsed_ms
                })
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_upload(self):
        """Handle streaming multipart file upload."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_json({"error": "Expected multipart/form-data"}, status=HTTPStatus.BAD_REQUEST)
            return

        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part.split("=", 1)[1].strip('"\'')
                break

        if not boundary:
            self.send_json({"error": "No boundary in Content-Type"}, status=HTTPStatus.BAD_REQUEST)
            return

        content_length = self.headers.get("Content-Length")
        length = int(content_length) if content_length else None

        try:
            parser = StreamingMultipartParser(self.rfile, length, boundary)
            uploaded = parser.parse_to_destination(self.server.upload_dir)
            print(f"[{time.strftime('%H:%M:%S')}] Received {len(uploaded)} file(s) from {self.client_address[0]}")
            for f in uploaded:
                print(f"  -> {f['name']} ({f['size_formatted']})")
            self.send_json({
                "success": True,
                "count": len(uploaded),
                "files": uploaded
            })
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def serve_file_content(self, filename, as_attachment=True):
        """Serve a file for download or in-browser preview."""
        safe_name = sanitize_filename(filename)
        file_path = os.path.join(self.server.upload_dir, safe_name)

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self.send_error(HTTPStatus.NOT_FOUND, "File Not Found")
            return

        stat = os.stat(file_path)
        file_size = stat.st_size
        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"

        # Check for Range header (supports video streaming and resumed downloads)
        range_header = self.headers.get("Range")
        if range_header and range_header.startswith("bytes="):
            try:
                ranges = range_header[6:].split("-")
                start = int(ranges[0]) if ranges[0] else 0
                end = int(ranges[1]) if ranges[1] else file_size - 1
                if start >= file_size or end >= file_size or start > end:
                    self.send_error(HTTPStatus.RANGE_NOT_SATISFIABLE, "Requested Range Not Satisfiable")
                    return

                chunk_length = end - start + 1
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Type", mime_type)
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(chunk_length))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()

                with open(file_path, "rb") as f:
                    f.seek(start)
                    remaining = chunk_length
                    while remaining > 0:
                        buf = f.read(min(remaining, 64 * 1024))
                        if not buf:
                            break
                        self.wfile.write(buf)
                        remaining -= len(buf)
                return
            except (ConnectionResetError, BrokenPipeError):
                return
            except Exception:
                pass

        # Standard full file delivery
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("Accept-Ranges", "bytes")

            quoted_name = urllib.parse.quote(safe_name)
            disposition = "attachment" if as_attachment else "inline"
            self.send_header(
                "Content-Disposition",
                f'{disposition}; filename="{safe_name}"; filename*=UTF-8\'\'{quoted_name}'
            )
            self.end_headers()

            with open(file_path, "rb") as f:
                while True:
                    buf = f.read(64 * 1024)
                    if not buf:
                        break
                    self.wfile.write(buf)
        except (ConnectionResetError, BrokenPipeError):
            pass


# Embedded Single-Page Responsive Web Application (HTML/CSS/JS)
UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>LAN File Transfer</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/js-yaml@4/dist/js-yaml.min.js"></script>
  <style>
    :root {
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --primary-soft: #eff6ff;
      --success: #10b981;
      --danger: #ef4444;
      --bg: #0f172a;
      --surface: #1e293b;
      --surface-hover: #334155;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --radius: 14px;
    }

    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f8fafc;
        --surface: #ffffff;
        --surface-hover: #f1f5f9;
        --border: #e2e8f0;
        --text: #0f172a;
        --text-muted: #64748b;
        --primary-soft: #eff6ff;
      }
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 16px 12px 32px 12px;
    }

    .container {
      width: 100%;
      max-width: 95%;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 16px;
      box-sizing: border-box;
      transition: padding 0.05s ease, max-width 0.05s ease;
    }

    @media (max-width: 767px) {
      .container {
        max-width: 100% !important;
        padding: 0 4px !important;
      }
    }

    @media (min-width: 768px) {
      .container {
        padding-left: var(--side-space, 0px);
        padding-right: var(--side-space, 0px);
        max-width: min(calc(100% - (var(--side-space, 0px) * 2)), 1760px);
      }
    }

    /* Header */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-icon {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 22px;
    }

    .brand-title h1 {
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .brand-title p {
      font-size: 0.78rem;
      color: var(--text-muted);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .header-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 9999px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .header-btn:hover {
      background: var(--border);
      color: var(--primary);
      transform: translateY(-1px);
    }
    .header-btn.active {
      background: var(--primary-soft);
      border-color: var(--primary);
      color: var(--primary);
    }

    @media (max-width: 640px) {
      .hide-on-mobile {
        display: none !important;
      }
      .header-btn {
        padding: 6px 9px;
      }
      .brand-title p {
        display: none;
      }
    }

    .ip-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 9999px;
      background: var(--primary-soft);
      color: var(--primary);
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .ip-badge:hover {
      opacity: 0.9;
      transform: translateY(-1px);
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 6px;
      background: var(--surface);
      padding: 6px;
      border-radius: var(--radius);
      border: 1px solid var(--border);
      overflow-x: auto;
      white-space: nowrap;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: none;
      -ms-overflow-style: none;
    }
    .tabs::-webkit-scrollbar {
      display: none;
    }

    .tab-btn {
      flex: 1 0 auto;
      padding: 9px 14px;
      border: none;
      border-radius: 10px;
      background: transparent;
      color: var(--text-muted);
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .tab-btn.active {
      background: var(--primary);
      color: white;
      box-shadow: 0 2px 4px rgba(59, 130, 246, 0.3);
    }

    /* Upload Card */
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }

    .drop-zone {
      border: 2px dashed var(--border);
      border-radius: 16px;
      padding: 36px 16px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s ease;
      background: var(--surface-hover);
    }

    .drop-zone.dragover {
      border-color: var(--primary);
      background: var(--primary-soft);
      transform: scale(1.01);
    }

    .drop-icon {
      font-size: 48px;
      margin-bottom: 12px;
      display: inline-block;
      filter: drop-shadow(0 4px 6px rgba(0,0,0,0.1));
    }

    .drop-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 6px;
    }

    .drop-subtitle {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 18px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 12px;
      padding: 12px 24px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn:hover {
      background: var(--primary-hover);
    }

    .btn:active {
      transform: scale(0.98);
    }

    .btn-secondary {
      background: var(--surface-hover);
      color: var(--text);
      border: 1px solid var(--border);
    }

    .btn-sm {
      padding: 6px 12px;
      font-size: 0.8rem;
      border-radius: 8px;
    }

    /* Selected files & progress */
    .selected-files-list {
      margin-top: 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .file-queue-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 12px;
      background: var(--surface-hover);
      border-radius: 10px;
      font-size: 0.85rem;
    }

    .file-info-left {
      display: flex;
      align-items: center;
      gap: 10px;
      overflow: hidden;
    }

    .file-queue-name {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 220px;
      font-weight: 500;
    }

    .file-queue-size {
      color: var(--text-muted);
      font-size: 0.75rem;
    }

    .progress-container {
      margin-top: 16px;
      display: none;
    }

    .progress-bar-bg {
      height: 10px;
      width: 100%;
      background: var(--surface-hover);
      border-radius: 999px;
      overflow: hidden;
    }

    .progress-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #3b82f6, #10b981);
      transition: width 0.15s ease;
    }

    .progress-stats {
      margin-top: 8px;
      display: flex;
      justify-content: space-between;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    /* Files List Section */
    .files-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .files-count-badge {
      background: var(--surface-hover);
      padding: 4px 8px;
      border-radius: 8px;
      font-size: 0.78rem;
      color: var(--text-muted);
    }

    .search-input {
      width: 100%;
      padding: 10px 14px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 10px;
      color: var(--text);
      font-size: 0.88rem;
      margin-bottom: 12px;
      outline: none;
    }

    .search-input:focus {
      border-color: var(--primary);
    }

    .file-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 520px;
      overflow-y: auto;
      padding-right: 4px;
    }

    .file-card {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 14px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 12px;
      transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
      cursor: pointer;
    }

    .file-card:hover {
      border-color: var(--primary);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    .file-details {
      display: flex;
      align-items: center;
      gap: 12px;
      overflow: hidden;
      flex: 1;
    }

    .file-type-icon {
      font-size: 26px;
      min-width: 32px;
      text-align: center;
    }

    .file-meta {
      overflow: hidden;
    }

    .file-name {
      font-size: 0.9rem;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .file-sub {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .file-actions {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-left: 10px;
      cursor: default;
    }

    #liveActivityFeed {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 520px;
      overflow-y: auto;
    }

    .action-btn {
      width: 36px;
      height: 36px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 10px;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      cursor: pointer;
      text-decoration: none;
      transition: background 0.15s;
    }

    .action-btn:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .action-btn.btn-delete:hover {
      background: var(--danger);
      color: white;
      border-color: var(--danger);
    }

    /* Notes / Clipboard sharing */
    .note-input-box {
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 16px;
    }

    .note-textarea {
      width: 100%;
      height: 320px;
      min-height: 260px;
      padding: 14px;
      border-radius: 12px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 0.92rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      line-height: 1.5;
      resize: vertical;
      outline: none;
    }

    .note-textarea:focus {
      border-color: var(--primary);
    }

    .note-item {
      padding: 11px 13px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 3px solid transparent;
      border-radius: 11px;
      position: relative;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: auto;
      min-width: 0;
      flex-shrink: 0;
      box-sizing: border-box;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .note-item:hover {
      border-color: rgba(255, 255, 255, 0.22);
      border-left-color: var(--primary);
      background: var(--surface-hover);
      transform: translateY(-1px);
    }
    .note-item.active-note {
      border-color: rgba(59, 130, 246, 0.5);
      border-left-color: var(--primary);
      background: rgba(59, 130, 246, 0.1);
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.15);
    }

    .note-snippet-container {
      font-size: 0.85rem;
      line-height: 1.5;
      overflow-x: auto;
      margin-bottom: 6px;
      transition: max-height 0.2s ease;
      min-width: 0;
    }
    .note-snippet-container.collapsed {
      max-height: 208px;
      overflow-y: auto;
      scrollbar-width: thin;
    }
    .note-snippet-container.expanded {
      max-height: none !important;
      overflow-y: visible;
    }
    .note-snippet-toggle-btn {
      background: transparent;
      border: none;
      color: var(--primary);
      font-size: 0.73rem;
      font-weight: 600;
      cursor: pointer;
      padding: 2px 0 6px 0;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }
    .note-snippet-toggle-btn:hover {
      text-decoration: underline;
      color: #60a5fa;
    }

    .note-text {
      font-size: 0.9rem;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .note-footer {
      margin-top: auto;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.07);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.72rem;
      color: var(--text-muted);
    }

    /* Pinned Section Styles */
    .pinned-card {
      border: 1px solid rgba(59, 130, 246, 0.45);
      background: linear-gradient(180deg, rgba(59, 130, 246, 0.08), var(--surface));
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.12);
      transition: all 0.2s ease;
    }

    .pinned-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }

    .pinned-count-badge {
      background: var(--primary);
      color: white;
      font-size: 0.7rem;
      font-weight: 700;
      padding: 1px 7px;
      border-radius: 999px;
    }

    .action-btn.is-pinned {
      background: rgba(59, 130, 246, 0.25);
      border-color: var(--primary);
      color: var(--primary);
      box-shadow: 0 0 6px rgba(59, 130, 246, 0.4);
    }

    /* Modal for QR code & Image preview */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.7);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }

    .modal-overlay.active {
      display: flex;
    }

    .modal-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 24px;
      max-width: 360px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
    }

    #qrCodeCanvas {
      margin: 16px auto;
      border-radius: 12px;
      background: white;
      padding: 12px;
    }

    /* Toast */
    .toast {
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: #1e293b;
      color: white;
      border: 1px solid #475569;
      padding: 10px 20px;
      border-radius: 999px;
      font-size: 0.88rem;
      box-shadow: 0 10px 15px -3px rgba(0,0,0,0.4);
      transition: transform 0.3s cubic-bezier(0.18, 0.89, 0.32, 1.28);
      z-index: 2000;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .toast.show {
      transform: translateX(-50%) translateY(0);
    }

    /* Labels & Chips */
    .label-chip {
      display: inline-flex;
      align-items: center;
      gap: 3px;
      padding: 2px 7px;
      border-radius: 6px;
      font-size: 0.72rem;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.15);
      color: var(--primary);
      border: 1px solid rgba(59, 130, 246, 0.3);
      cursor: pointer;
      transition: all 0.15s;
    }

    .label-chip:hover {
      background: rgba(59, 130, 246, 0.25);
    }

    .label-chip .remove-lbl {
      cursor: pointer;
      font-weight: bold;
      opacity: 0.7;
      margin-left: 2px;
    }

    .label-chip .remove-lbl:hover {
      opacity: 1;
      color: var(--danger);
    }

    .label-add-btn {
      display: inline-flex;
      align-items: center;
      gap: 3px;
      padding: 2px 7px;
      border-radius: 6px;
      font-size: 0.72rem;
      font-weight: 600;
      background: var(--surface-hover);
      color: var(--text-muted);
      border: 1px dashed var(--border);
      cursor: pointer;
      transition: all 0.15s;
    }

    .label-add-btn:hover {
      color: var(--text);
      border-color: var(--primary);
    }

    /* Note Tools Toolbar */
    .tools-toolbar {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
      overflow-x: auto;
      white-space: nowrap;
      padding-bottom: 4px;
      scrollbar-width: thin;
      -webkit-overflow-scrolling: touch;
    }
    .tools-toolbar::-webkit-scrollbar {
      height: 4px;
    }
    .tools-toolbar::-webkit-scrollbar-track {
      background: transparent;
    }
    .tools-toolbar::-webkit-scrollbar-thumb {
      background: var(--border);
      border-radius: 2px;
    }
    @media (min-width: 1024px) {
      .tools-toolbar {
        flex-wrap: wrap;
        overflow-x: visible;
        white-space: normal;
      }
    }

    .tool-btn {
      padding: 5px 9px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 0.76rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .tool-btn:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .tool-btn.active {
      background: var(--primary);
      color: white;
    }

    /* Markdown Styling */
    .md-body {
      font-size: 0.88rem;
      line-height: 1.5;
      word-break: break-word;
    }

    .md-body h1, .md-body h2, .md-body h3 {
      margin: 8px 0 4px 0;
      font-weight: 700;
    }
    .md-body h1 { font-size: 1.12rem; color: var(--primary); }
    .md-body h2 { font-size: 1.02rem; }
    .md-body h3 { font-size: 0.94rem; }

    .md-body p { margin-bottom: 6px; }

    .md-body code {
      font-family: monospace;
      background: rgba(0,0,0,0.3);
      padding: 2px 5px;
      border-radius: 4px;
      font-size: 0.82rem;
      color: #38bdf8;
    }

    .md-body pre {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      overflow-x: auto;
      margin: 8px 0;
    }

    .md-body pre code {
      background: transparent;
      padding: 0;
      color: #f1f5f9;
      font-size: 0.82rem;
    }

    .md-body ul, .md-body ol {
      margin: 6px 0 6px 20px;
    }

    .md-body blockquote {
      border-left: 3px solid var(--primary);
      padding-left: 10px;
      margin: 6px 0;
      color: var(--text-muted);
      font-style: italic;
    }

    .md-body hr {
      border: none;
      border-top: 1px solid var(--border);
      margin: 10px 0;
    }

    /* Search & Filter pills */
    .filter-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 12px;
    }

    .filter-pill {
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.76rem;
      font-weight: 600;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.15s;
    }

    .filter-pill:hover, .filter-pill.active {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .type-filter-group {
      display: flex;
      gap: 6px;
      margin-bottom: 12px;
      overflow-x: auto;
      padding-bottom: 4px;
    }

    /* Quick Tag Modal Styles */
    .tag-modal-option {
      padding: 9px 12px;
      border-radius: 9px;
      border: 1.5px dashed var(--border);
      background: var(--surface-hover);
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: all 0.15s ease;
      font-size: 0.84rem;
      user-select: none;
    }
    .tag-modal-option:hover {
      border-color: var(--primary);
      background: rgba(59, 130, 246, 0.1);
    }
    .tag-modal-option.selected {
      border: 2px solid var(--success) !important;
      background: rgba(16, 185, 129, 0.16) !important;
      color: var(--success) !important;
      font-weight: 700;
      box-shadow: 0 0 0 1px var(--success);
    }
    .tag-modal-item {
      padding: 8px 12px;
      border-radius: 8px;
      border: 1.5px solid var(--border);
      background: var(--surface);
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: all 0.15s ease;
      font-size: 0.84rem;
      user-select: none;
    }
    .tag-modal-item:hover {
      background: var(--surface-hover);
      border-color: var(--primary);
    }
    .tag-modal-item.selected {
      border: 2px solid var(--success) !important;
      background: rgba(16, 185, 129, 0.16) !important;
      color: var(--success) !important;
      font-weight: 700;
      box-shadow: 0 0 0 1px var(--success);
    }
    .tag-shortcut-hint {
      font-size: 0.7rem;
      color: var(--text-muted);
      background: var(--surface-hover);
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
    }

    /* Live Activity Stream Note Collapsed / Uniform Height */
    .live-note-content {
      position: relative;
    }
    .live-note-body {
      font-size: 0.84rem;
      line-height: 1.45;
      word-break: break-word;
      transition: max-height 0.2s ease;
    }
    .live-note-body.collapsed {
      max-height: 48px;
      overflow: hidden;
      position: relative;
      mask-image: linear-gradient(180deg, #000 65%, transparent);
      -webkit-mask-image: linear-gradient(180deg, #000 65%, transparent);
    }
    .live-note-body.expanded {
      max-height: none;
      overflow: visible;
      mask-image: none;
      -webkit-mask-image: none;
    }
    .live-note-toggle-btn {
      background: transparent;
      border: none;
      color: var(--primary);
      font-size: 0.73rem;
      font-weight: 600;
      cursor: pointer;
      padding: 3px 0 0 0;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }
    .live-note-toggle-btn:hover {
      text-decoration: underline;
      color: #60a5fa;
    }

    /* Recent Tags Hover Popover */
    .recent-tags-popover {
      position: fixed;
      z-index: 2500;
      background: #090d16;
      border: 1px solid var(--border);
      box-shadow: 0 12px 30px -5px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.08);
      border-radius: 10px;
      padding: 8px 10px;
      display: none;
      flex-direction: column;
      gap: 6px;
      min-width: 180px;
      max-width: 280px;
      pointer-events: auto;
      transform: translate(-50%, -100%);
      margin-top: -8px;
      animation: popoverFadeIn 0.15s ease;
    }
    @keyframes popoverFadeIn {
      from { opacity: 0; transform: translate(-50%, -95%); }
      to { opacity: 1; transform: translate(-50%, -100%); }
    }
    .recent-tags-popover::after {
      content: '';
      position: absolute;
      top: 100%;
      left: 50%;
      transform: translateX(-50%);
      border-width: 6px;
      border-style: solid;
      border-color: #090d16 transparent transparent transparent;
    }
    .popover-title {
      font-size: 0.65rem;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .popover-tags-list {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }
    .popover-tag-chip {
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.74rem;
      font-weight: 600;
      background: var(--surface-hover);
      color: var(--primary);
      border: 1px solid var(--border);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .popover-tag-chip:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
      transform: scale(1.04);
    }

    /* Code Syntax Highlighting */
    .hl-key { color: #38bdf8; font-weight: 600; }
    .hl-string { color: #4ade80; }
    .hl-number { color: #fbbf24; }
    .hl-bool { color: #f472b6; font-weight: 600; }
    .hl-null { color: #94a3b8; font-style: italic; }
    .hl-keyword { color: #c084fc; font-weight: 600; }
    .hl-comment { color: #64748b; font-style: italic; }

    /* Markdown Code Blocks & Code Editor Feel */
    .md-code-block {
      position: relative;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 10px;
      margin: 10px 0;
      max-width: 100%;
      box-sizing: border-box;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
      overflow: hidden;
    }
    .md-code-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 12px;
      background: rgba(255, 255, 255, 0.04);
      border-bottom: 1px solid var(--border);
      font-size: 0.74rem;
      user-select: none;
      gap: 8px;
    }
    .md-code-lang {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.73rem;
      font-weight: 700;
      color: var(--primary);
      letter-spacing: 0.5px;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .md-code-actions {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .md-code-btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 9px;
      font-size: 0.73rem;
      font-weight: 600;
      font-family: inherit;
      color: var(--text-muted);
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      line-height: 1.3;
    }
    .md-code-btn:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.22);
    }
    .md-code-btn:active {
      transform: scale(0.96);
    }
    .md-code-btn.active {
      background: rgba(59, 130, 246, 0.2);
      color: var(--primary);
      border-color: var(--primary);
    }
    .md-code-btn.copied {
      background: rgba(16, 185, 129, 0.25) !important;
      color: var(--success) !important;
      border-color: var(--success) !important;
    }
    .md-code-block pre {
      background: transparent !important;
      border: none !important;
      border-radius: 0 !important;
      margin: 0 !important;
      padding: 12px 14px !important;
      overflow-x: auto !important;
      overflow-y: hidden !important;
      max-width: 100% !important;
      box-sizing: border-box !important;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
      font-size: 0.84rem !important;
      line-height: 1.5 !important;
      color: #f1f5f9 !important;
      white-space: pre !important;
      word-break: normal !important;
      scrollbar-width: thin;
      scrollbar-color: var(--border) transparent;
    }
    .md-code-block pre::-webkit-scrollbar {
      height: 6px;
    }
    .md-code-block pre::-webkit-scrollbar-track {
      background: transparent;
    }
    .md-code-block pre::-webkit-scrollbar-thumb {
      background: var(--border);
      border-radius: 3px;
    }
    .md-code-block pre::-webkit-scrollbar-thumb:hover {
      background: rgba(255, 255, 255, 0.3);
    }
    .md-code-block pre code {
      background: transparent !important;
      padding: 0 !important;
      font-family: inherit !important;
      font-size: inherit !important;
      display: inline-block;
      min-width: 100%;
    }
    .md-code-block pre.is-wrapped {
      white-space: pre-wrap !important;
      word-break: break-all !important;
      overflow-x: hidden !important;
    }
    .md-code-block pre.is-wrapped code {
      white-space: pre-wrap !important;
      word-break: break-all !important;
      min-width: 0 !important;
    }

    .tool-select {
      padding: 4px 8px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 0.76rem;
      font-weight: 600;
      cursor: pointer;
      outline: none;
    }
    .tool-select:focus {
      border-color: var(--primary);
    }

    /* Notes Tab Responsive Mobile Switcher (< 1024px) */
    .notes-mobile-switcher {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      padding: 4px;
      background: #161b22;
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 14px;
      box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.25);
    }
    .notes-mobile-segment {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 9px 12px;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-muted);
      background: transparent;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .notes-mobile-segment:hover {
      color: var(--text);
    }
    .notes-mobile-segment.active {
      background: var(--primary);
      color: #ffffff;
      font-weight: 700;
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.35);
    }
    .notes-mobile-count {
      font-size: 0.72rem;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 10px;
      background: rgba(0, 0, 0, 0.25);
      color: #ffffff;
    }
    .notes-mobile-segment:not(.active) .notes-mobile-count {
      background: var(--surface-hover);
      color: var(--text-muted);
    }

    .notes-saved-col {
      display: flex;
      flex-direction: column;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      overflow: hidden;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.2);
    }
    .notes-saved-header {
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
    }
    .notes-count-pill {
      font-size: 0.72rem;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 10px;
      background: rgba(59, 130, 246, 0.15);
      color: var(--primary);
      border: 1px solid rgba(59, 130, 246, 0.3);
    }
    #notesContainer {
      flex: 1;
      overflow-y: auto;
      max-height: 640px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
      gap: 12px;
      scrollbar-width: thin;
      scrollbar-color: var(--border) transparent;
    }
    #notesContainer::-webkit-scrollbar {
      width: 6px;
    }
    #notesContainer::-webkit-scrollbar-track {
      background: transparent;
    }
    #notesContainer::-webkit-scrollbar-thumb {
      background: var(--border);
      border-radius: 3px;
    }
    #notesContainer::-webkit-scrollbar-thumb:hover {
      background: rgba(255, 255, 255, 0.25);
    }

    .notes-empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 48px 16px;
      color: var(--text-muted);
    }
    .notes-empty-icon {
      font-size: 2.2rem;
      width: 56px;
      height: 56px;
      border-radius: 14px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 12px;
      box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
    }
    .notes-empty-title {
      font-size: 0.92rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 4px;
    }
    .notes-empty-desc {
      font-size: 0.78rem;
      color: var(--text-muted);
      max-width: 260px;
      line-height: 1.4;
    }

    /* Mobile Display Visibility (< 1024px) */
    @media (max-width: 1023px) {
      #tabNotes[data-mobile-segment="editor"] #notesEditorCol {
        display: flex !important;
        flex-direction: column;
      }
      #tabNotes[data-mobile-segment="editor"] #notesSavedCol {
        display: none !important;
      }
      #tabNotes[data-mobile-segment="saved"] #notesEditorCol {
        display: none !important;
      }
      #tabNotes[data-mobile-segment="saved"] #notesSavedCol {
        display: flex !important;
        flex-direction: column;
        width: 100%;
      }
    }

    /* PC Layout / Wide Screen Expansions */
    @media (min-width: 992px) {
      .container {
        max-width: min(calc(96% - (var(--side-space, 0px) * 2)), 1760px);
        padding-left: max(16px, var(--side-space, 16px));
        padding-right: max(16px, var(--side-space, 16px));
      }
      .upload-tab-grid {
        display: grid;
        grid-template-columns: 1fr 1.15fr;
        gap: 20px;
        align-items: start;
      }
      .upload-tab-grid > * {
        min-width: 0;
      }
      .notes-mobile-switcher {
        display: none !important;
      }
      #notesEditorCol,
      #notesSavedCol {
        display: flex !important;
        flex-direction: column;
        min-width: 0;
      }
      .notes-tab-grid {
        display: grid;
        grid-template-columns: 360px 1fr;
        gap: 20px;
        align-items: stretch;
      }
      .notes-tab-grid > * {
        min-width: 0;
      }
      #fileListContainer {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
        gap: 12px;
        max-height: 720px;
      }
      #searchResultsContainer {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
        gap: 12px;
        max-height: 720px;
      }
      #liveActivityFeed {
        max-height: 560px !important;
      }
      .converter-grid-pc {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 22px;
        width: 100%;
        align-items: stretch;
      }
    }

    @media (min-width: 1300px) {
      .container {
        max-width: min(calc(1560px - (var(--side-space, 0px) * 2)), 1560px);
        padding-left: max(20px, var(--side-space, 20px));
        padding-right: max(20px, var(--side-space, 20px));
      }
    }

    @media (min-width: 1700px) {
      .container {
        max-width: min(calc(1760px - (var(--side-space, 0px) * 2)), 1760px);
        padding-left: max(24px, var(--side-space, 24px));
        padding-right: max(24px, var(--side-space, 24px));
      }
    }

    /* Vertical Layout Mode Overrides */
    [data-layout="vertical"] .upload-tab-grid,
    [data-layout="vertical"] .notes-tab-grid,
    [data-layout="vertical"] .converter-grid-pc {
      display: flex !important;
      flex-direction: column !important;
      gap: 22px !important;
    }
    [data-layout="vertical"] .upload-col-left,
    [data-layout="vertical"] .upload-col-right {
      width: 100% !important;
      max-width: 100% !important;
    }

    /* Expansive Tap to Upload File in Vertical Mode */
    [data-layout="vertical"] .drop-zone {
      padding: 56px 24px !important;
      min-height: 230px !important;
      display: flex !important;
      flex-direction: column !important;
      align-items: center !important;
      justify-content: center !important;
      background: var(--surface-hover) !important;
      border: 2px dashed var(--primary) !important;
      border-radius: 18px !important;
      width: 100% !important;
      box-sizing: border-box !important;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1) !important;
    }
    [data-layout="vertical"] .drop-zone .drop-icon {
      font-size: 58px !important;
      margin-bottom: 12px !important;
    }
    [data-layout="vertical"] .drop-zone .drop-title {
      font-size: 1.3rem !important;
      font-weight: 700 !important;
      margin-bottom: 6px !important;
    }
    [data-layout="vertical"] .drop-zone .drop-subtitle {
      font-size: 0.92rem !important;
      margin-bottom: 20px !important;
    }
    [data-layout="vertical"] .drop-zone .btn {
      padding: 11px 28px !important;
      font-size: 0.95rem !important;
      border-radius: 10px !important;
    }

    /* Expansive Live Activity Stream in Vertical Mode */
    [data-layout="vertical"] #liveActivityFeed {
      max-height: none !important;
      overflow-y: visible !important;
      min-height: 320px !important;
      gap: 10px !important;
    }
    [data-layout="vertical"] #liveActivityFeed .file-card {
      padding: 12px 16px !important;
      border-radius: 12px !important;
    }

    [data-layout="vertical"] #fileListContainer,
    [data-layout="vertical"] #searchResultsContainer {
      display: flex !important;
      flex-direction: column !important;
      gap: 10px !important;
    }
    [data-layout="vertical"] #notesContainer {
      max-height: none !important;
    }
    /* Notes Tab in Vertical Layout Mode: segmented tabs like mobile */
    [data-layout="vertical"] .notes-mobile-switcher {
      display: grid !important;
    }
    [data-layout="vertical"] #notesEditorCol {
      display: none !important;
    }
    [data-layout="vertical"] #notesSavedCol {
      display: none !important;
    }
    [data-layout="vertical"] #tabNotes[data-mobile-segment="editor"] #notesEditorCol {
      display: flex !important;
      flex-direction: column !important;
      width: 100% !important;
    }
    [data-layout="vertical"] #tabNotes[data-mobile-segment="editor"] #notesSavedCol {
      display: none !important;
    }
    [data-layout="vertical"] #tabNotes[data-mobile-segment="saved"] #notesEditorCol {
      display: none !important;
    }
    [data-layout="vertical"] #tabNotes[data-mobile-segment="saved"] #notesSavedCol {
      display: flex !important;
      flex-direction: column !important;
      width: 100% !important;
    }

    @media (max-width: 991px) {
      .drop-zone {
        padding: 46px 20px;
        min-height: 200px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
      }
      .drop-zone .drop-icon {
        font-size: 52px;
      }
      .drop-zone .drop-title {
        font-size: 1.2rem;
      }
      #liveActivityFeed {
        max-height: 650px;
      }
    }

    /* Color Theme Definitions */
    [data-theme="midnight"] {
      --bg: #050508;
      --surface: #111116;
      --surface-hover: #1c1c24;
      --border: #252530;
      --text: #fafafa;
      --text-muted: #a1a1aa;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --primary-soft: rgba(56, 189, 248, 0.15);
    }
    [data-theme="emerald"] {
      --bg: #04140e;
      --surface: #0a241c;
      --surface-hover: #103529;
      --border: #174838;
      --text: #ecfdf5;
      --text-muted: #6ee7b7;
      --primary: #10b981;
      --primary-hover: #059669;
      --primary-soft: rgba(16, 185, 129, 0.15);
    }
    [data-theme="cyberpunk"] {
      --bg: #0c071e;
      --surface: #160e33;
      --surface-hover: #23174f;
      --border: #362174;
      --text: #faf5ff;
      --text-muted: #d8b4fe;
      --primary: #a855f7;
      --primary-hover: #9333ea;
      --primary-soft: rgba(168, 85, 247, 0.18);
    }
    [data-theme="sunset"] {
      --bg: #17120e;
      --surface: #241c16;
      --surface-hover: #362922;
      --border: #48382f;
      --text: #fffbeb;
      --text-muted: #fcd34d;
      --primary: #f59e0b;
      --primary-hover: #d97706;
      --primary-soft: rgba(245, 158, 11, 0.15);
    }
    [data-theme="nordic"] {
      --bg: #1f232b;
      --surface: #292e39;
      --surface-hover: #363d4b;
      --border: #454e5f;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #60a5fa;
      --primary-hover: #3b82f6;
      --primary-soft: rgba(96, 165, 250, 0.15);
    }
    [data-theme="light"] {
      --bg: #f1f5f9;
      --surface: #ffffff;
      --surface-hover: #e2e8f0;
      --border: #cbd5e1;
      --text: #0f172a;
      --text-muted: #64748b;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-soft: #dbeafe;
    }
    [data-theme="light"] .converter-textarea {
      background: #f8fafc;
      color: #0f172a;
      border-color: #cbd5e1;
    }
    [data-theme="light"] .note-textarea {
      background: #f8fafc;
      color: #0f172a;
    }
    [data-theme="light"] .md-code-block {
      background: #182234;
      border-color: #cbd5e1;
    }
    [data-theme="light"] .md-code-header {
      background: rgba(0, 0, 0, 0.25);
      border-bottom-color: rgba(255, 255, 255, 0.1);
    }
    [data-theme="light"] .md-code-btn {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.2);
      color: #e2e8f0;
    }
    [data-theme="light"] .md-code-btn:hover {
      background: rgba(255, 255, 255, 0.22);
      color: #ffffff;
    }
    [data-theme="light"] .notes-mobile-switcher {
      background: #e2e8f0;
      border-color: #cbd5e1;
    }
    [data-theme="light"] .notes-mobile-segment {
      color: #64748b;
    }
    [data-theme="light"] .notes-mobile-segment.active {
      background: var(--primary);
      color: #ffffff;
    }
    [data-theme="light"] .notes-saved-col {
      background: #ffffff;
      border-color: #cbd5e1;
    }
    [data-theme="light"] .notes-saved-header {
      background: #ffffff;
      border-bottom-color: #cbd5e1;
    }
    [data-theme="light"] .notes-empty-icon {
      background: #f1f5f9;
      border-color: #cbd5e1;
    }

    /* Settings Modal Components */
    .setting-section {
      margin-bottom: 20px;
    }
    .setting-section-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .setting-option-btn {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 12px 10px;
      background: var(--surface-hover);
      border: 2px solid var(--border);
      border-radius: 12px;
      color: var(--text);
      cursor: pointer;
      transition: all 0.15s ease;
      text-align: center;
    }
    .setting-option-btn:hover {
      border-color: var(--primary);
      background: rgba(59, 130, 246, 0.08);
    }
    .setting-option-btn.active {
      border-color: var(--primary);
      background: var(--primary-soft);
      color: var(--primary);
    }
    .setting-option-btn.active .setting-subtext {
      color: var(--primary);
    }

    /* Theme Cards Grid */
    .theme-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(135px, 1fr));
      gap: 10px;
    }
    .theme-card {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 10px 8px;
      border-radius: 12px;
      background: var(--surface-hover);
      border: 2px solid var(--border);
      cursor: pointer;
      transition: all 0.15s ease;
      text-align: center;
    }
    .theme-card:hover {
      border-color: var(--primary);
      transform: translateY(-2px);
    }
    .theme-card.active {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px var(--primary);
    }
    .theme-swatch-box {
      width: 100%;
      height: 34px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
      margin-bottom: 8px;
      border: 1px solid rgba(255, 255, 255, 0.15);
      position: relative;
      overflow: hidden;
    }
    .theme-swatch-circle {
      width: 13px;
      height: 13px;
      border-radius: 50%;
      border: 1px solid rgba(255, 255, 255, 0.3);
    }
    .theme-name {
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text);
    }
    .theme-desc {
      font-size: 0.68rem;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Range Slider Styling */
    .space-slider-container {
      background: var(--surface-hover);
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .space-slider {
      width: 100%;
      height: 6px;
      border-radius: 4px;
      background: var(--border);
      outline: none;
      accent-color: var(--primary);
      cursor: pointer;
    }

    /* Converter Grids & Expansive Responsive Styling */
    .converter-grid {
      display: flex;
      flex-direction: column;
      gap: 16px;
      width: 100%;
    }
    .converter-panel {
      display: flex;
      flex-direction: column;
      gap: 8px;
      width: 100%;
      min-width: 0; /* Critical: prevents grid items from shrinking */
    }
    .converter-header-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .converter-title {
      font-size: 0.9rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    /* Two-Dropdown Controls Bar */
    .converter-controls-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
      padding: 12px 16px;
      background: var(--surface-hover);
      border: 1px solid var(--border);
      border-radius: 12px;
    }
    .dropdown-pair-container {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      flex: 1;
      min-width: 280px;
    }
    .dropdown-group {
      display: flex;
      align-items: center;
      gap: 8px;
      flex: 1;
      min-width: 200px;
    }
    .dropdown-label {
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
    }
    .converter-select-large {
      flex: 1;
      background: var(--surface);
      border: 1.5px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 0.86rem;
      font-weight: 600;
      padding: 7px 12px;
      outline: none;
      cursor: pointer;
      transition: all 0.15s;
      min-width: 160px;
    }
    .converter-select-large:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    .swap-direction-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--primary);
      font-size: 1.1rem;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.15s;
      flex-shrink: 0;
    }
    .swap-direction-btn:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
      transform: scale(1.06);
    }

    .converter-textarea {
      width: 100%;
      height: 480px;
      min-height: 360px;
      padding: 14px 16px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #090d16;
      color: #f1f5f9;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.88rem;
      line-height: 1.55;
      resize: vertical;
      outline: none;
      box-sizing: border-box;
      tab-size: 2;
      box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
    }
    .converter-textarea:focus {
      border-color: var(--primary);
      box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4), 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    .converter-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }

    /* JSON Invalid Underline & Error Bar */
    .note-textarea.json-invalid {
      border-color: #ef4444 !important;
      box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.3) !important;
      border-bottom: 3px wavy #ef4444 !important;
    }
    .json-error-banner {
      display: none;
      padding: 10px 14px;
      margin: 8px 0;
      border-radius: 10px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.35);
      color: #f87171;
      font-family: ui-monospace, monospace;
      font-size: 0.8rem;
      animation: popoverFadeIn 0.2s ease;
    }
    .json-error-snippet {
      margin-top: 6px;
      padding: 6px 10px;
      background: #090d16;
      border-radius: 6px;
      white-space: pre-wrap;
      word-break: break-all;
      border: 1px solid rgba(239, 68, 68, 0.25);
    }
    /* Markdown Docs Viewer & Diagrams */
    .md-docs-toolbar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      background: var(--surface);
      border-radius: 12px;
      border: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .md-docs-selector-group {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }
    .md-docs-actions {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .md-docs-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    }
    .md-docs-header-meta {
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 20px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .md-docs-title {
      font-size: 1.45rem;
      font-weight: 700;
      color: var(--text);
    }
    .md-docs-info-row {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .md-docs-body {
      color: var(--text);
      line-height: 1.7;
      font-size: 0.95rem;
    }
    .md-docs-body h1 {
      font-size: 1.6rem;
      margin: 20px 0 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
    }
    .md-docs-body h2 {
      font-size: 1.3rem;
      margin: 18px 0 10px;
      padding-bottom: 4px;
      border-bottom: 1px solid var(--border);
    }
    .md-docs-body h3 {
      font-size: 1.1rem;
      margin: 14px 0 8px;
    }
    .md-docs-body p {
      margin-bottom: 12px;
    }
    .md-docs-body ul, .md-docs-body ol {
      margin: 8px 0 14px 24px;
    }
    .md-docs-body li {
      margin-bottom: 4px;
    }
    .md-docs-body blockquote {
      border-left: 4px solid var(--primary);
      padding: 6px 14px;
      margin: 12px 0;
      color: var(--text-muted);
      background: rgba(59, 130, 246, 0.05);
      border-radius: 0 8px 8px 0;
    }

    /* GFM Tables */
    .md-table-wrapper {
      width: 100%;
      overflow-x: auto;
      margin: 16px 0;
      border-radius: 10px;
      border: 1px solid var(--border);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
      -webkit-overflow-scrolling: touch;
    }
    .md-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.86rem;
      text-align: left;
    }
    .md-table th {
      background: var(--surface-hover);
      color: var(--text);
      font-weight: 700;
      padding: 10px 14px;
      border-bottom: 2px solid var(--border);
      white-space: nowrap;
    }
    .md-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      color: var(--text);
    }
    .md-table tbody tr:nth-child(even) {
      background: rgba(255, 255, 255, 0.02);
    }
    .md-table tbody tr:hover {
      background: var(--surface-hover);
    }

    /* Mermaid Diagrams */
    .mermaid-diagram-card {
      margin: 18px 0;
      background: #090d16;
      border: 1px solid #1e293b;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    }
    .mermaid-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 14px;
      background: rgba(30, 41, 59, 0.7);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .mermaid-title {
      font-size: 0.78rem;
      font-weight: 700;
      color: #a78bfa;
      letter-spacing: 0.5px;
    }
    .mermaid-viewport {
      padding: 20px;
      overflow-x: auto;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 120px;
    }
    .mermaid-viewport svg {
      max-width: 100%;
      height: auto;
    }

    /* ASCII Diagrams (Blueprint Monospace View) */
    .ascii-diagram-card {
      margin: 18px 0;
      background: #080c14;
      border: 1px solid #1e293b;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }
    .ascii-diagram-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 14px;
      background: rgba(15, 23, 42, 0.9);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .ascii-diagram-title {
      font-size: 0.78rem;
      font-weight: 700;
      color: #38bdf8;
      letter-spacing: 0.5px;
    }
    .ascii-diagram-body {
      padding: 18px;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }
    .ascii-diagram-pre {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, "Cascadia Code", "Fira Code", Menlo, Monaco, Consolas, monospace !important;
      font-size: 0.85rem !important;
      line-height: 1.25 !important;
      letter-spacing: 0px !important;
      white-space: pre !important;
      color: #38bdf8 !important;
      font-feature-settings: "liga" 0, "calt" 0;
    }

    /* OpenAPI / Swagger Tester Styles */
    .openapi-grid {
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 20px;
      align-items: stretch;
      margin-top: 14px;
    }
    @media (max-width: 1023px) {
      .openapi-grid {
        grid-template-columns: 1fr;
      }
    }
    [data-layout="vertical"] .openapi-grid {
      display: flex !important;
      flex-direction: column !important;
      gap: 20px !important;
    }
    .openapi-sidebar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      max-height: 800px;
    }
    .openapi-sidebar-header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      background: var(--surface-hover);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .openapi-endpoints-list {
      flex: 1;
      overflow-y: auto;
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .openapi-tag-group {
      margin-bottom: 10px;
    }
    .openapi-tag-title {
      font-size: 0.76rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      padding: 4px 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .openapi-endpoint-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: transparent;
      cursor: pointer;
      text-align: left;
      width: 100%;
      color: var(--text);
      font-size: 0.82rem;
      transition: all 0.15s ease;
    }
    .openapi-endpoint-item:hover {
      background: var(--surface-hover);
    }
    .openapi-endpoint-item.active {
      background: rgba(59, 130, 246, 0.15);
      border-color: var(--primary);
    }
    .openapi-endpoint-path {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.78rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      flex: 1;
    }

    /* HTTP Method Badges */
    .method-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-family: ui-monospace, monospace;
      font-size: 0.7rem;
      font-weight: 800;
      padding: 2px 6px;
      border-radius: 5px;
      letter-spacing: 0.5px;
      min-width: 50px;
      text-align: center;
      flex-shrink: 0;
    }
    .method-get {
      background: rgba(16, 185, 129, 0.18);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .method-post {
      background: rgba(59, 130, 246, 0.18);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.35);
    }
    .method-put {
      background: rgba(245, 158, 11, 0.18);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .method-delete {
      background: rgba(239, 68, 68, 0.18);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .method-patch {
      background: rgba(139, 92, 246, 0.18);
      color: #a78bfa;
      border: 1px solid rgba(139, 92, 246, 0.35);
    }

    /* OpenAPI Tester Main Console */
    .openapi-console-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .openapi-console-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--surface-hover);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .openapi-console-body {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }
    .openapi-section-title {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .openapi-param-row {
      display: grid;
      grid-template-columns: 140px 1fr;
      gap: 10px;
      align-items: center;
      margin-bottom: 8px;
    }
    .openapi-param-name {
      font-family: ui-monospace, monospace;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text);
    }
    .openapi-input {
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      font-size: 0.85rem;
      outline: none;
      width: 100%;
      box-sizing: border-box;
      transition: border-color 0.15s;
    }
    .openapi-input:focus {
      border-color: var(--primary);
    }
    .openapi-body-editor {
      width: 100%;
      height: 180px;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #090d16;
      color: #f1f5f9;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.84rem;
      outline: none;
      resize: vertical;
      box-sizing: border-box;
    }
    .openapi-response-card {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      margin-top: 10px;
    }
    .openapi-response-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 14px;
      background: rgba(30, 41, 59, 0.7);
      border-bottom: 1px solid var(--border);
    }
    .openapi-response-badge {
      padding: 3px 8px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.78rem;
      font-family: ui-monospace, monospace;
    }
    .status-2xx {
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .status-4xx {
      background: rgba(245, 158, 11, 0.2);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .status-5xx {
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .openapi-response-pre {
      padding: 14px;
      margin: 0;
      max-height: 400px;
      overflow: auto;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.83rem;
      color: #f8fafc;
      white-space: pre-wrap;
      word-break: break-word;
    }

    /* Light Theme Adjustments */
    [data-theme="light"] .md-table tbody tr:nth-child(even) {
      background: rgba(0, 0, 0, 0.02);
    }
    [data-theme="light"] .mermaid-diagram-card {
      background: #ffffff;
      border-color: #cbd5e1;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
    }
    [data-theme="light"] .mermaid-header {
      background: #f1f5f9;
      border-bottom: 1px solid #cbd5e1;
    }
    [data-theme="light"] .ascii-diagram-card {
      background: #f8fafc;
      border-color: #cbd5e1;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
    }
    [data-theme="light"] .ascii-diagram-header {
      background: #f1f5f9;
      border-bottom: 1px solid #cbd5e1;
    }
    [data-theme="light"] .ascii-diagram-pre {
      color: #0369a1 !important;
    }
    [data-theme="light"] .openapi-body-editor,
    [data-theme="light"] .openapi-response-card {
      background: #ffffff;
      border-color: #cbd5e1;
    }
    [data-theme="light"] .openapi-response-header {
      background: #f1f5f9;
      border-bottom: 1px solid #cbd5e1;
    }
    /* File Detail Page */
    .file-detail-grid {
      display: grid;
      grid-template-columns: 1fr 340px;
      gap: 20px;
      align-items: start;
    }
    @media (max-width: 991px) {
      .file-detail-grid {
        grid-template-columns: 1fr;
      }
    }
    [data-layout="vertical"] .file-detail-grid {
      display: flex !important;
      flex-direction: column !important;
      gap: 20px !important;
    }
    .file-detail-main {
      min-width: 0;
    }
    .file-detail-preview-box {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      min-height: 380px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.3);
    }
    [data-theme="light"] .file-detail-preview-box {
      background: #f8fafc;
      border-color: #cbd5e1;
    }
    .file-detail-sidebar {
      min-width: 0;
    }
    .file-detail-info-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.15);
    }
    .file-detail-meta-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .file-detail-meta-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .file-detail-meta-label {
      font-size: 0.72rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .file-detail-meta-value {
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text);
    }

    /* Hover preview popover */
    .hover-preview-code {
      width: 100%;
      height: 100%;
      max-height: 240px;
      overflow: auto;
      padding: 12px;
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.76rem;
      line-height: 1.45;
      color: var(--text);
      white-space: pre-wrap;
      word-break: break-word;
      background: #090d16;
    }
    [data-theme="light"] .hover-preview-code {
      background: #ffffff;
      color: #0f172a;
    }
  </style>
</head>
<body>

<div class="container">
  <!-- Header -->
  <header>
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div class="brand-title">
        <h1>LAN Transfer</h1>
        <p>Send files between Phone & PC</p>
      </div>
    </div>
    <div class="header-actions">
      <!-- Layout Switcher (Grid vs Vertical) -->
      <button type="button" class="header-btn" id="layoutToggleBtn" onclick="toggleLayoutMode()" title="Switch between Grid and Vertical layout">
        <span id="layoutToggleIcon" style="font-size: 1.05rem;">⊞</span>
        <span id="layoutToggleText" class="hide-on-mobile">Grid</span>
      </button>

      <!-- Settings Button -->
      <button type="button" class="header-btn" id="settingsBtn" onclick="openSettingsModal()" title="Display & Theme Settings">
        <span style="font-size: 0.95rem;">⚙️</span>
        <span class="hide-on-mobile">Settings</span>
      </button>

      <!-- Connection IP & QR -->
      <div class="ip-badge" onclick="openQRModal()" title="Show connection QR Code">
        <span>📱 QR</span>
        <span id="currentIpText">__PRIMARY_IP__:__PORT__</span>
      </div>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="tabs">
    <button class="tab-btn active" id="tabUploadBtn" onclick="switchTab('upload')">
      📤 Upload & Feed
    </button>
    <button class="tab-btn" id="tabFilesBtn" onclick="switchTab('files')">
      📁 Files <span id="filesCountTab"></span>
    </button>
    <button class="tab-btn" id="tabNotesBtn" onclick="switchTab('notes')">
      📝 Notes <span id="notesCountTab"></span>
    </button>
    <button class="tab-btn" id="tabOpenApiBtn" onclick="switchTab('openapi')">
      🌐 OpenAPI Tester
    </button>
    <button class="tab-btn" id="tabMarkdownDocsBtn" onclick="switchTab('markdowndocs')">
      📚 Markdown Docs
    </button>
    <button class="tab-btn" id="tabSearchBtn" onclick="switchTab('search')">
      🔍 Search
    </button>
    <button class="tab-btn" id="tabEnvVarBtn" onclick="switchTab('envvar')">
      ⚙️ Env Vars
    </button>
  </div>

  <!-- PERSISTENT PINNED FILES SECTION (Remains visible on top across all tabs) -->
  <div id="pinnedSection" class="card pinned-card" style="display: none;">
    <div class="pinned-header">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 1.1rem;">📌</span>
        <span style="font-weight: 700; font-size: 0.95rem;">Pinned Files</span>
        <span id="pinnedBadge" class="pinned-count-badge">0</span>
      </div>
      <span style="font-size: 0.75rem; color: var(--text-muted);">Pinned to top of all tabs</span>
    </div>
    <div class="pinned-list" id="pinnedList" style="display: flex; flex-direction: column; gap: 8px;"></div>
  </div>

  <!-- TAB 1: UPLOAD & LIVE FEED -->
  <div id="tabUpload" class="card">
    <div class="upload-tab-grid">
      <div class="upload-col-left">
        <input type="file" id="fileInput" multiple style="display: none;" onchange="handleFilesSelected(this.files)">

        <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
          <div class="drop-icon">📂</div>
          <div class="drop-title">Tap to Choose Files</div>
          <div class="drop-subtitle">Photos, Videos, Documents or Any File</div>
          <button class="btn" type="button" onclick="event.stopPropagation(); document.getElementById('fileInput').click();">
            Select Files
          </button>
        </div>

        <!-- Selected queue -->
        <div id="queueSection" style="display: none; margin-top: 18px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 0.85rem; font-weight: 600;" id="queueSummary">Selected Files</span>
            <button class="btn btn-secondary btn-sm" onclick="clearQueue()">Cancel</button>
          </div>
          <div class="selected-files-list" id="queueList"></div>

          <div style="margin-top: 14px;">
            <button class="btn" style="width: 100%;" id="startUploadBtn" onclick="startUpload()">
              🚀 Send to Computer Now
            </button>
          </div>
        </div>

        <!-- Upload Progress -->
        <div class="progress-container" id="progressContainer">
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" id="progressBar"></div>
          </div>
          <div class="progress-stats">
            <span id="progressPercent">0%</span>
            <span id="progressSpeed">Uploading...</span>
          </div>
        </div>
      </div>

      <div class="upload-col-right">
        <!-- Live Activity Feed (Shows what was uploaded or pasted in real time) -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 0.95rem; font-weight: 700;">📡 Live Activity Stream</span>
            <span style="display: inline-block; width: 8px; height: 8px; background: #10b981; border-radius: 50%; box-shadow: 0 0 6px #10b981;" title="Live Sync Active"></span>
          </div>
          <span style="font-size: 0.75rem; color: var(--text-muted);" id="liveActivityStatus">Auto-updating</span>
        </div>

        <div id="liveActivityFeed">
          <div style="text-align: center; color: var(--text-muted); padding: 18px; font-size: 0.85rem;">
            No activity yet. Upload a file or paste text to see it appear here live!
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: RECEIVED FILES -->
  <div id="tabFiles" class="card" style="display: none;">
    <div class="files-header">
      <h2 style="font-size: 1.05rem; font-weight: 700;">Files on Computer</h2>
      <button class="btn btn-secondary btn-sm" onclick="fetchFilesList()">🔄 Refresh</button>
    </div>
    <input type="text" class="search-input" id="searchFilesInput" placeholder="🔍 Filter files by name or label..." oninput="filterFilesList()">

    <div class="file-list" id="fileListContainer">
      <div style="text-align: center; color: var(--text-muted); padding: 24px;">Loading files...</div>
    </div>
  </div>

  <!-- TAB 3: NOTES & UTILITY TOOLS (Evernote-style split layout) -->
  <div id="tabNotes" class="card" style="display: none;" data-mobile-segment="saved">
    <!-- Mobile-only Segmented View Switcher (< 1024px) -->
    <div class="notes-mobile-switcher" id="notesMobileSwitcher">
      <button type="button" class="notes-mobile-segment active" id="btnNotesSegmentSaved" onclick="setNotesMobileSegment('saved')">
        <span>📋 Notes <span class="notes-mobile-count" id="notesMobileCountBadge">0</span></span>
      </button>
      <button type="button" class="notes-mobile-segment" id="btnNotesSegmentEditor" onclick="setNotesMobileSegment('editor')">
        <span>📝 Note Editor</span>
      </button>
    </div>

    <div class="notes-tab-grid">
      <!-- LEFT COLUMN: SAVED NOTES LIST (Evernote-style Sidebar) -->
      <div class="notes-saved-col" id="notesSavedCol">
        <div class="notes-saved-header">
          <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
            <div style="display: flex; align-items: center; gap: 7px;">
              <span style="font-size: 0.95rem; font-weight: 700; color: var(--text);">📋 Notes</span>
              <span class="notes-count-pill" id="notesSavedCountPill">0</span>
            </div>
            <div style="display: flex; gap: 5px;">
              <button type="button" class="btn btn-secondary btn-sm" onclick="createNewNoteFromList()" title="New blank note" style="padding: 3px 8px; font-size: 0.74rem; font-weight: 600;">➕ New</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="clearAllNotes()" title="Clear history" style="padding: 3px 7px; font-size: 0.74rem; color: var(--danger);">Clear</button>
            </div>
          </div>
          <input type="text" id="notesListSearchInput" class="search-input" style="font-size: 0.78rem; padding: 6px 10px; margin: 0; width: 100%; box-sizing: border-box;" placeholder="🔍 Filter notes..." oninput="filterNotesList(this.value)">
        </div>
        <div id="notesContainer"></div>
      </div>

      <!-- RIGHT COLUMN: NOTE EDITOR & TOOLS (Evernote-style Document View) -->
      <div class="note-input-box" id="notesEditorCol" style="margin-bottom: 0;">
        <!-- Title & Label inputs -->
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <input type="text" id="noteTitleInput" class="search-input" style="flex: 1; min-width: 140px; margin-bottom: 0;" placeholder="📌 Note Title (optional)..." maxlength="50">
          <input type="text" id="noteLabelsInput" class="search-input" style="flex: 1; min-width: 140px; margin-bottom: 0;" placeholder="🏷️ Tags (comma-separated, max 50 chars, no-spaces: work, api-v2)..." maxlength="50" oninput="this.value = this.value.replace(/ /g, '-').slice(0, 50)">
        </div>

        <!-- Utilities Toolbar -->
        <div class="tools-toolbar">
          <button type="button" class="tool-btn" onclick="toggleMdPreview(this)" id="btnMdToggle" title="Toggle Markdown Preview">👁️ MD Preview</button>
          <button type="button" class="tool-btn" onclick="toolJsonBeautify()" title="Format/Prettify JSON with syntax highlight">✨ JSON Format</button>
          <button type="button" class="tool-btn" onclick="toolJsonMinify()" title="Minify/Compact JSON">🗜️ JSON Minify</button>
          <button type="button" class="tool-btn" onclick="toolStringEscape()" title="Escape quotes & newlines">🔤 Escape</button>
          <button type="button" class="tool-btn" onclick="toolStringUnescape()" title="Unescape quotes & newlines">🔓 Unescape</button>
          <button type="button" class="tool-btn" onclick="toolBase64Encode()" title="Encode text to Base64">🔒 Base64 Enc</button>
          <button type="button" class="tool-btn" onclick="toolBase64Decode()" title="Decode text from Base64">🔓 Base64 Dec</button>

          <!-- Code format selector -->
          <select class="tool-select" id="codeFormatSelector" onchange="changeNoteCodeFormat(this.value)" title="Change / highlight code format">
            <option value="">🔣 Code Format...</option>
            <option value="json">✨ JSON</option>
            <option value="js">⚡ JavaScript</option>
            <option value="py">🐍 Python</option>
            <option value="sql">🗄️ SQL</option>
            <option value="sh">💻 Bash / Shell</option>
            <option value="html">🌐 HTML / XML</option>
            <option value="unwrap">📝 Plain (unwrap)</option>
          </select>

          <button type="button" class="tool-btn" onclick="clearNoteInputs()" style="margin-left: auto; color: var(--danger);" title="Clear Input">🧹 Clear</button>
        </div>

        <textarea id="noteInput" class="note-textarea" placeholder="Type or paste Markdown (# Header, - list, `code`), JSON, or code..." oninput="onNoteInputChanged()"></textarea>
        <!-- JSON validation error indicator banner with red underline snippet -->
        <div id="jsonErrorBar" class="json-error-banner"></div>

        <!-- Live Markdown Preview -->
        <div id="noteMdPreview" class="md-body" style="display: none; min-height: 280px; max-height: 520px; overflow-y: auto; overflow-x: hidden; max-width: 100%; box-sizing: border-box; padding: 14px; background: var(--surface-hover); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 8px;"></div>

        <div style="display: flex; gap: 8px; align-items: center;">
          <button class="btn" onclick="sendNote()" style="flex: 1; font-weight: 700;">💾 Save & Send Note to Computer</button>
          <button type="button" class="btn btn-secondary" onclick="createNewNoteFromList()" title="New blank note" style="flex-shrink: 0;">➕ New Note</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: SEARCH & FILTER -->
  <div id="tabSearch" class="card" style="display: none;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
      <h2 style="font-size: 1.05rem; font-weight: 700;">🔍 Search & Label Explorer</h2>
      <button class="btn btn-secondary btn-sm" onclick="clearSearchFilters()">Reset Filters</button>
    </div>

    <!-- Search input -->
    <input type="text" class="search-input" id="globalSearchInput" placeholder="🔍 Search title, filename, text content, or #label..." oninput="runGlobalSearch()">

    <!-- Type filter pills -->
    <div class="type-filter-group" id="searchTypeFilters">
      <button class="filter-pill active" onclick="setSearchType('all', this)">All Items</button>
      <button class="filter-pill" onclick="setSearchType('files', this)">📁 Files</button>
      <button class="filter-pill" onclick="setSearchType('notes', this)">📝 Notes</button>
      <button class="filter-pill" onclick="setSearchType('images', this)">🖼️ Images</button>
      <button class="filter-pill" onclick="setSearchType('videos', this)">🎬 Videos</button>
    </div>

    <!-- Label filter cloud -->
    <div style="margin-bottom: 14px;">
      <div style="font-size: 0.76rem; color: var(--text-muted); font-weight: 600; margin-bottom: 6px;">FILTER BY LABEL:</div>
      <div class="filter-pills" id="labelFilterPills">
        <span style="font-size: 0.78rem; color: var(--text-muted);">No labels yet. Add labels to files or notes!</span>
      </div>
    </div>

    <!-- Results summary & list -->
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 10px;">
      <span id="searchResultsSummary">Showing all items</span>
    </div>
    <div class="file-list" id="searchResultsContainer" style="max-height: 520px; overflow-y: auto;"></div>
  </div>

  <!-- TAB 5: ENV VAR GENERATOR (like env.simplestep.ca) -->
  <div id="tabEnvVar" class="card" style="display: none;">
    <div style="margin-bottom: 12px;">
      <h2 style="font-size: 1.15rem; font-weight: 700; margin: 0 0 4px 0; display: flex; align-items: center; gap: 8px;">
        <span>⚙️ Environment Variable Generator</span>
      </h2>
      <p style="font-size: 0.82rem; color: var(--text-muted); margin: 0;">For Spring Boot apps, Terminal, Docker Compose, & Kubernetes</p>
    </div>

    <!-- Responsive Two-Dropdown Controls Bar -->
    <div class="converter-controls-bar">
      <div class="dropdown-pair-container">
        <div class="dropdown-group">
          <label class="dropdown-label" for="envInputFormat">From:</label>
          <select id="envInputFormat" class="converter-select-large" onchange="runEnvVarConversion()">
            <option value="yaml" selected>Spring Boot YAML (.yml)</option>
            <option value="properties">Spring Boot Properties (.properties)</option>
            <option value="env_terminal">Terminal Environment Variables (FOO=bar)</option>
            <option value="env_multiline">Multi-line Environment Variables</option>
            <option value="docker">Docker Compose Environment</option>
            <option value="k8s">Kubernetes ConfigMap</option>
            <option value="hocon">Application Conf / HOCON (.conf)</option>
          </select>
        </div>

        <button class="swap-direction-btn" onclick="swapEnvVarFormats()" title="Swap From and To formats">⇄</button>

        <div class="dropdown-group">
          <label class="dropdown-label" for="envOutputFormat">To:</label>
          <select id="envOutputFormat" class="converter-select-large" onchange="runEnvVarConversion()">
            <option value="env_terminal" selected>Terminal Environment Variables (FOO=bar)</option>
            <option value="env_multiline">Multi-line Environment Variables</option>
            <option value="shell_export">Shell Export (export FOO="bar")</option>
            <option value="docker">Docker Compose Environment</option>
            <option value="k8s">Kubernetes ConfigMap</option>
            <option value="yaml">Spring Boot YAML (.yml)</option>
            <option value="properties">Spring Boot Properties (.properties)</option>
          </select>
        </div>
      </div>

      <div class="converter-actions">
        <button class="btn btn-secondary btn-sm" onclick="loadEnvVarSample()">📄 Load Sample</button>
        <button class="btn btn-secondary btn-sm" onclick="clearEnvVarInputs()">🧹 Clear</button>
      </div>
    </div>

    <div class="converter-grid-pc converter-grid">
      <!-- Input Panel -->
      <div class="converter-panel">
        <div class="converter-header-row">
          <span class="converter-title">Source Input</span>
          <button class="btn btn-secondary btn-sm" style="padding: 3px 9px; font-size: 0.74rem;" onclick="pasteToEnvInput()">📋 Paste</button>
        </div>

        <textarea id="envInputText" class="converter-textarea" placeholder="Paste Spring Boot YAML, properties, or environment variables here..." oninput="runEnvVarConversion()"></textarea>

        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.74rem; color: var(--text-muted);">
          <span id="envInputStats">0 lines</span>
        </div>
      </div>

      <!-- Output Panel -->
      <div class="converter-panel">
        <div class="converter-header-row">
          <span class="converter-title">Converted Output</span>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-secondary btn-sm" style="padding: 3px 9px; font-size: 0.74rem;" onclick="copyEnvOutput(this)">📋 Copy Output</button>
            <button class="btn btn-secondary btn-sm" style="padding: 3px 9px; font-size: 0.74rem;" onclick="saveEnvOutputToNote()">💬 Send as Note</button>
          </div>
        </div>

        <textarea id="envOutputText" class="converter-textarea" readonly placeholder="Converted output will appear here automatically..."></textarea>

        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.74rem; color: var(--text-muted);">
          <span id="envOutputStats">0 variables</span>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: OPENAPI / SWAGGER TESTER -->
  <div id="tabOpenApi" class="card" style="display: none;">
    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px;">
      <div>
        <h2 style="font-size: 1.25rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 8px;">
          🌐 OpenAPI / Swagger Tester
        </h2>
        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">
          Parse OpenAPI 2.0 / 3.0 specs (JSON & YAML) and test endpoints interactively with CORS bypass proxy
        </p>
      </div>
      <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
        <button type="button" class="btn btn-secondary btn-sm" onclick="toggleOpenApiSpecDrawer()" id="btnToggleOpenApiSpec">
          📝 Edit Spec Source
        </button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="loadSampleOpenApi('lan')" title="Load LAN Transfer Server API spec">
          ⚡ LAN Server API
        </button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="loadSampleOpenApi('petstore')" title="Load Swagger Petstore API demo">
          🐶 Petstore API
        </button>
      </div>
    </div>

    <!-- Collapsible Spec Input Drawer -->
    <div id="openApiSpecDrawer" style="background: var(--surface-hover); border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 16px;">
      <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 10px;">
        <div style="flex: 1; min-width: 240px; display: flex; gap: 6px;">
          <input type="text" id="openApiUrlInput" class="search-input" style="margin-bottom: 0; padding: 7px 10px; font-size: 0.82rem;" placeholder="https://petstore.swagger.io/v2/swagger.json">
          <button type="button" class="btn btn-secondary btn-sm" onclick="fetchOpenApiFromUrl()">Fetch URL</button>
        </div>
        <div style="display: flex; gap: 6px; align-items: center;">
          <select id="openApiUploadedSelect" class="tool-select" style="font-size: 0.82rem; padding: 6px 10px;" onchange="loadOpenApiFromUploadedFile(this.value)">
            <option value="">📂 Select from uploaded files...</option>
          </select>
          <label class="btn btn-secondary btn-sm" style="cursor: pointer; margin: 0; display: inline-flex; align-items: center;">
            📁 Local File <input type="file" id="openApiLocalFileInput" accept=".json,.yaml,.yml" style="display: none;" onchange="handleOpenApiLocalFile(event)">
          </label>
        </div>
      </div>
      <textarea id="openApiRawSpec" class="converter-textarea" style="height: 180px; min-height: 120px; font-size: 0.82rem;" placeholder="Paste OpenAPI/Swagger specification in JSON or YAML format..."></textarea>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px;">
        <span id="openApiParseStatus" style="font-size: 0.78rem; color: var(--text-muted);">Ready to parse spec</span>
        <button type="button" class="btn btn-primary btn-sm" onclick="parseCurrentOpenApiSpec()">⚡ Parse & Load Spec</button>
      </div>
    </div>

    <!-- Spec Explorer & Interactive Tester Grid -->
    <div class="openapi-grid">
      <!-- Left Column: API Info, Base Server & Endpoints List -->
      <div class="openapi-sidebar">
        <div class="openapi-sidebar-header">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 6px;">
            <div>
              <div id="openApiInfoTitle" style="font-weight: 700; font-size: 0.95rem; color: var(--text);">LAN File Transfer API</div>
              <div id="openApiInfoVersion" style="font-size: 0.72rem; color: var(--text-muted);">v1.0.0</div>
            </div>
            <span id="openApiEndpointCount" class="notes-count-pill">0 endpoints</span>
          </div>
          <div>
            <label style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); display: block; margin-bottom: 3px;">TARGET SERVER</label>
            <div style="display: flex; gap: 4px;">
              <select id="openApiServerSelect" class="tool-select" style="font-size: 0.78rem; padding: 5px 8px; flex: 1;" onchange="onOpenApiServerSelected(this.value)">
                <option value="">http://localhost:8080</option>
              </select>
            </div>
            <input type="text" id="openApiCustomServer" class="openapi-input" style="font-size: 0.76rem; padding: 5px 8px; margin-top: 4px; display: none;" placeholder="Custom server URL e.g. http://192.168.1.5:8080">
          </div>
          <input type="text" id="openApiEndpointFilter" class="openapi-input" style="font-size: 0.8rem; padding: 6px 10px;" placeholder="🔍 Filter endpoints or paths..." oninput="filterOpenApiEndpoints(this.value)">
        </div>
        <div class="openapi-endpoints-list" id="openApiEndpointsList">
          <div style="text-align: center; padding: 30px 10px; color: var(--text-muted); font-size: 0.82rem;">
            No endpoints loaded yet. Click "LAN Server API" or paste a spec above.
          </div>
        </div>
      </div>

      <!-- Right Column: Endpoint Tester & Response Panel -->
      <div class="openapi-console-panel">
        <div class="openapi-console-header">
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <span id="activeEndpointMethod" class="method-badge method-get">GET</span>
            <span id="activeEndpointPath" style="font-family: ui-monospace, monospace; font-weight: 700; font-size: 0.95rem; color: var(--text);">/api/files</span>
          </div>
          <div id="activeEndpointSummary" style="font-size: 0.84rem; color: var(--text-muted);">List uploaded files and their metadata</div>
        </div>

        <div class="openapi-console-body">
          <!-- Parameters Section -->
          <div id="openApiParamsContainer">
            <div class="openapi-section-title">📌 Parameters</div>
            <div id="openApiParamsList" style="display: flex; flex-direction: column; gap: 6px;">
              <div style="font-size: 0.8rem; color: var(--text-muted); font-style: italic;">No parameters required for this endpoint.</div>
            </div>
          </div>

          <!-- Headers Section -->
          <div>
            <div class="openapi-section-title">📋 Request Headers</div>
            <div id="openApiHeadersList" style="display: flex; flex-direction: column; gap: 6px;">
              <div class="openapi-param-row">
                <span class="openapi-param-name">Accept</span>
                <input type="text" id="header_accept" class="openapi-input" value="application/json">
              </div>
              <div class="openapi-param-row">
                <span class="openapi-param-name">Authorization</span>
                <input type="text" id="header_authorization" class="openapi-input" placeholder="Bearer <token> (optional)">
              </div>
            </div>
          </div>

          <!-- Request Body Section -->
          <div id="openApiBodyContainer" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <div class="openapi-section-title" style="margin-bottom: 0;">📦 Request Body (JSON)</div>
              <button type="button" class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.72rem;" onclick="formatOpenApiBodyJson()">Format JSON</button>
            </div>
            <textarea id="openApiRequestBody" class="openapi-body-editor" placeholder="{ ... }"></textarea>
          </div>

          <!-- Actions Bar -->
          <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px; padding-top: 10px; border-top: 1px solid var(--border);">
            <label style="display: flex; align-items: center; gap: 6px; font-size: 0.82rem; color: var(--text); cursor: pointer;">
              <input type="checkbox" id="openApiUseProxyCheckbox" checked>
              <span>Proxy via LAN Server (Bypasses CORS restrictions)</span>
            </label>
            <button type="button" class="btn btn-primary" id="btnSendOpenApiRequest" onclick="executeOpenApiRequest()" style="padding: 9px 20px; font-weight: 700;">
              🚀 Send Request
            </button>
          </div>

          <!-- Response Section -->
          <div id="openApiResponseSection" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">
              <div class="openapi-section-title" style="margin-bottom: 0;">📬 Response</div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span id="responseStatusBadge" class="openapi-response-badge status-2xx">200 OK</span>
                <span id="responseTimeBadge" style="font-size: 0.75rem; color: var(--text-muted); font-family: ui-monospace, monospace;">⏱️ 0 ms</span>
                <button type="button" class="btn btn-secondary btn-sm" onclick="copyOpenApiResponse()" style="padding: 3px 8px; font-size: 0.74rem;">📋 Copy</button>
              </div>
            </div>

            <div class="openapi-response-card">
              <div class="openapi-response-header">
                <span style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted);">Response Body</span>
                <span id="responseSizeBadge" style="font-size: 0.72rem; color: var(--text-muted);">0 bytes</span>
              </div>
              <pre class="openapi-response-pre" id="openApiResponseContent"></pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: MARKDOWN DOCUMENT VIEWER WITH TABLES, MERMAID & ASCII -->
  <div id="tabMarkdownDocs" class="card" style="display: none;">
    <!-- Docs Toolbar -->
    <div class="md-docs-toolbar">
      <div class="md-docs-selector-group">
        <span style="font-size: 0.95rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 6px;">
          📚 Markdown Docs
        </span>
        <select id="mdDocsNoteSelect" class="tool-select" style="font-size: 0.84rem; max-width: 260px;" onchange="onMdDocsNoteChange(this.value)">
          <option value="">Select a note to view...</option>
        </select>
        <button type="button" class="btn btn-secondary btn-sm" onclick="refreshMdDocsDropdown()" title="Reload notes list">🔄 Refresh</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="loadSampleRichDoc()" title="Load rich sample with tables, mermaid & ASCII diagrams">✨ Sample Rich Doc</button>
      </div>

      <div class="md-docs-actions">
        <button type="button" class="btn btn-secondary btn-sm" onclick="editCurrentDocInNotes()" title="Edit this document in the Notes tab">
          📝 Edit in Notes
        </button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="copyCurrentMdDocSource()" title="Copy raw markdown text">
          📋 Copy Markdown
        </button>
      </div>
    </div>

    <!-- Document Viewer Card -->
    <div class="md-docs-card">
      <div class="md-docs-header-meta">
        <h1 class="md-docs-title" id="mdDocTitle">Document Preview</h1>
        <div class="md-docs-info-row">
          <span id="mdDocDate">Last updated: -</span>
          <span id="mdDocTags" style="display: flex; gap: 4px;"></span>
        </div>
      </div>
      <div class="md-docs-body" id="mdDocRenderedBody">
        <p style="color: var(--text-muted); font-style: italic;">
          Select a note from the dropdown above or click "✨ Sample Rich Doc" to see interactive GFM Tables, Mermaid diagrams, and ASCII architecture blueprints.
        </p>
      </div>
    </div>
  </div>

  <!-- DETAIL PAGE VIEW (When clicking any file item) -->
  <div id="fileDetailPage" class="card" style="display: none;">
    <!-- Detail Header Navigation Bar -->
    <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid var(--border);">
      <div style="display: flex; align-items: center; gap: 12px;">
        <button type="button" class="btn btn-secondary" onclick="closeFileDetail()" style="display: inline-flex; align-items: center; gap: 6px; font-weight: 700; padding: 8px 16px;">
          <span>←</span> <span>Back</span>
        </button>
        <div style="overflow: hidden;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span id="detailTypeIcon" style="font-size: 1.3rem;">📄</span>
            <h2 id="detailFileName" style="font-size: 1.2rem; font-weight: 700; color: var(--text); margin: 0; word-break: break-all;">File Name</h2>
          </div>
          <div id="detailFileSub" style="font-size: 0.76rem; color: var(--text-muted); margin-top: 2px;">2.4 MB • Uploaded on Sep 16, 2026</div>
        </div>
      </div>

      <!-- Header Actions -->
      <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
        <a id="detailDownloadBtn" href="#" class="btn btn-primary" download style="display: inline-flex; align-items: center; gap: 6px; font-weight: 700; padding: 8px 16px;">
          <span>⬇️</span> <span>Download</span>
        </a>
        <a id="detailOpenTabBtn" href="#" target="_blank" class="btn btn-secondary" style="display: inline-flex; align-items: center; gap: 6px;">
          <span>👁️</span> <span>Open Raw</span>
        </a>
        <button type="button" class="btn btn-secondary" id="detailPinBtn" onclick="togglePinFromDetail()" style="display: inline-flex; align-items: center; gap: 6px;">
          <span>📌</span> <span id="detailPinText">Pin</span>
        </button>
        <button type="button" class="btn btn-secondary" onclick="deleteFileFromDetail()" style="color: var(--danger); display: inline-flex; align-items: center; gap: 6px;">
          <span>🗑️</span> <span>Delete</span>
        </button>
      </div>
    </div>

    <!-- Detail Content Split: Preview Area & Metadata Sidebar -->
    <div class="file-detail-grid">
      <!-- Main Preview Area -->
      <div class="file-detail-main">
        <div class="file-detail-preview-box" id="detailPreviewContainer">
          <!-- Image / Video / Audio / Text / Binary / PDF Preview -->
        </div>
      </div>

      <!-- Metadata & Share Info Sidebar -->
      <div class="file-detail-sidebar">
        <div class="file-detail-info-card">
          <h3 style="font-size: 0.92rem; font-weight: 700; margin-bottom: 12px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 8px;">
            ℹ️ File Information
          </h3>
          <div class="file-detail-meta-list">
            <div class="file-detail-meta-item">
              <span class="file-detail-meta-label">File Name</span>
              <span class="file-detail-meta-value" id="detailMetaFileName" style="word-break: break-all;">-</span>
            </div>
            <div class="file-detail-meta-item">
              <span class="file-detail-meta-label">File Size</span>
              <span class="file-detail-meta-value" id="detailMetaFileSize">-</span>
            </div>
            <div class="file-detail-meta-item">
              <span class="file-detail-meta-label">Upload Date</span>
              <span class="file-detail-meta-value" id="detailMetaFileDate">-</span>
            </div>
            <div class="file-detail-meta-item">
              <span class="file-detail-meta-label">Content Type</span>
              <span class="file-detail-meta-value" id="detailMetaFileType">-</span>
            </div>
          </div>

          <!-- Tags Manager -->
          <div style="margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <span style="font-size: 0.8rem; font-weight: 700; color: var(--text-muted);">🏷️ Tags & Labels</span>
              <button type="button" class="btn btn-secondary btn-sm" onclick="openTagModalForDetail()" style="padding: 2px 7px; font-size: 0.72rem;">+ Add Tag</button>
            </div>
            <div id="detailTagsList" style="display: flex; flex-wrap: wrap; gap: 4px;"></div>
          </div>

          <!-- Direct LAN Download Link & QR -->
          <div style="margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px;">
            <span style="font-size: 0.78rem; font-weight: 700; color: var(--text-muted); display: block; margin-bottom: 8px;">
              📱 Direct LAN Download Link & QR
            </span>
            <div style="display: flex; gap: 6px; margin-bottom: 12px;">
              <input type="text" id="detailDirectUrlInput" class="openapi-input" readonly style="font-size: 0.76rem; font-family: ui-monospace, monospace; padding: 6px 8px;">
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyDetailDirectUrl(this)" style="flex-shrink: 0; padding: 4px 8px;">📋 Copy</button>
            </div>
            <div style="text-align: center; background: white; padding: 10px; border-radius: 12px; width: 140px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,0.15);">
              <canvas id="detailQrCanvas" width="120" height="120" style="display: block; margin: 0 auto;"></canvas>
              <div style="font-size: 0.62rem; color: #333; margin-top: 4px; font-weight: 600;">Scan to download</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Quick Tag Modal -->
<div class="modal-overlay" id="tagModal" onclick="closeTagModal(event)">
  <div class="modal-card" onclick="event.stopPropagation()" style="max-width: 380px; text-align: left; padding: 18px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <h3 style="font-size: 1.1rem; font-weight: 700; margin: 0; display: flex; align-items: center; gap: 6px;">🏷️ Add Tag</h3>
      <button class="btn btn-secondary btn-sm" style="padding: 3px 8px; border-radius: 6px;" onclick="closeTagModal()">✕</button>
    </div>
    <div id="tagModalTargetName" style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"></div>

    <!-- Option on top of text box: Create label option -->
    <div id="tagModalCreateOption" class="tag-modal-option" onclick="confirmTagSelection('create')">
      <div style="display: flex; align-items: center; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        <span style="font-size: 0.95rem;">➕</span>
        <span style="font-size: 0.84rem; font-weight: 600;">Create tag: "<span id="tagModalCreateName" style="color: var(--primary);">...</span>"</span>
      </div>
      <span class="tag-shortcut-hint">Arrow Up ⬆️</span>
    </div>

    <!-- Edit Text Box -->
    <div style="position: relative; margin: 10px 0 10px 0;">
      <input type="text" id="tagModalInput" class="search-input" style="margin-bottom: 0; width: 100%; padding: 9px 12px; font-size: 0.9rem;" placeholder="Type tag (max 50 chars, no spaces)..." maxlength="50" autocomplete="off" oninput="onTagModalInputChanged()" onkeydown="onTagModalKeyDown(event)">
    </div>

    <!-- Nearest match list below edit text box -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <span style="font-size: 0.72rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Existing Tags (Filtered):</span>
      <span style="font-size: 0.7rem; color: var(--text-muted);">Arrow Down ⬇️ to pick</span>
    </div>
    <div id="tagModalList" style="max-height: 190px; overflow-y: auto; display: flex; flex-direction: column; gap: 5px;"></div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 0.72rem; color: var(--text-muted);">
      <span><strong style="color: var(--success);">Enter</strong>: Confirm • <strong style="color: var(--text);">↑/↓</strong>: Move</span>
      <button class="btn btn-secondary btn-sm" onclick="closeTagModal()">Cancel</button>
    </div>
  </div>
</div>

<!-- Recent Tags Popover on Hover -->
<div id="recentTagsPopover" class="recent-tags-popover" onmouseenter="onPopoverEnter()" onmouseleave="onPopoverLeave()">
  <div class="popover-title">⚡ Recent Tags (Click to add)</div>
  <div id="recentTagsList" class="popover-tags-list"></div>
</div>

<!-- Settings Modal (Theme, Layout Mode, and Content Spacing) -->
<div class="modal-overlay" id="settingsModal" onclick="closeSettingsModal(event)">
  <div class="modal-card" onclick="event.stopPropagation()" style="max-width: 520px; text-align: left; padding: 22px; max-height: 90vh; overflow-y: auto;">
    <!-- Modal Header -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">
      <h3 style="font-size: 1.15rem; font-weight: 700; margin: 0; display: flex; align-items: center; gap: 8px;">
        <span>⚙️</span> Appearance & Layout
      </h3>
      <button class="btn btn-secondary btn-sm" style="padding: 4px 9px; border-radius: 6px;" onclick="closeSettingsModal()">✕</button>
    </div>

    <!-- Section 1: Layout Mode (Grid vs Vertical) -->
    <div class="setting-section">
      <div class="setting-section-title">
        <span>Layout Structure</span>
        <span style="font-size: 0.72rem; color: var(--primary); font-weight: 600;">Desktop & Tablet</span>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
        <button type="button" id="settingLayoutGridBtn" class="setting-option-btn active" onclick="setLayoutMode('grid')">
          <div style="font-size: 1.35rem; margin-bottom: 4px;">⊞</div>
          <div style="font-weight: 700; font-size: 0.88rem;">Grid Layout</div>
          <div class="setting-subtext" style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">Side-by-side columns</div>
        </button>
        <button type="button" id="settingLayoutVertBtn" class="setting-option-btn" onclick="setLayoutMode('vertical')">
          <div style="font-size: 1.35rem; margin-bottom: 4px;">☰</div>
          <div style="font-weight: 700; font-size: 0.88rem;">Vertical Layout</div>
          <div class="setting-subtext" style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">Stacked single-column</div>
        </button>
      </div>
    </div>

    <!-- Section 2: Side Spacing / Center Narrowness Slider -->
    <div class="setting-section">
      <div class="setting-section-title">
        <span>Center Content Narrowness</span>
        <span id="sideSpaceValueText" style="font-family: monospace; font-size: 0.82rem; font-weight: 700; color: var(--primary); background: var(--surface-hover); padding: 2px 8px; border-radius: 6px;">0px</span>
      </div>
      <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 10px; line-height: 1.45;">
        Adjust left and right space simultaneously to push content inward for a more focused, narrower center view on wide screens.
      </p>
      <div class="space-slider-container">
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted);">Wide</span>
          <input type="range" id="sideSpaceSlider" class="space-slider" min="0" max="360" step="10" value="0" oninput="onSideSpaceInput(this.value)">
          <span style="font-size: 0.78rem; font-weight: 600; color: var(--text-muted);">Narrow</span>
          <button type="button" class="btn btn-secondary btn-sm" style="padding: 3px 8px; font-size: 0.72rem;" onclick="resetSideSpace()" title="Reset space to default">Reset</button>
        </div>
      </div>
    </div>

    <!-- Section 3: Color Themes -->
    <div class="setting-section" style="margin-bottom: 6px;">
      <div class="setting-section-title">
        <span>Color Theme</span>
        <span style="font-size: 0.72rem; color: var(--text-muted);">7 Palettes</span>
      </div>
      <div class="theme-grid" id="themeGrid">
        <!-- Rendered dynamically -->
      </div>
    </div>
  </div>
</div>

<!-- QR Code Modal -->
<div class="modal-overlay" id="qrModal" onclick="closeQRModal(event)">
  <div class="modal-card" onclick="event.stopPropagation()">
    <h3 style="font-size: 1.15rem; margin-bottom: 4px;">Connect Phone / Device</h3>
    <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 12px;">Scan with your phone's camera on the same Wi-Fi</p>

    <!-- Network interface selector if multiple IPs exist -->
    <div id="ipSelectorContainer" style="display: none; margin-bottom: 10px; text-align: left;">
      <label style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 4px; font-weight: 600;">Computer LAN IP:</label>
      <select id="ipSelect" class="search-input" style="margin-bottom: 0; padding: 7px 10px; font-size: 0.82rem; cursor: pointer; width: 100%;" onchange="onIpSelected(this.value)"></select>
    </div>

    <canvas id="qrCodeCanvas"></canvas>

    <div style="background: var(--surface-hover); padding: 8px 12px; border-radius: 10px; font-family: monospace; font-size: 0.82rem; margin: 12px 0 8px 0; word-break: break-all; border: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 8px;">
      <span id="modalUrl" style="color: var(--primary); font-weight: 600;">http://__PRIMARY_IP__:__PORT__</span>
      <button class="btn btn-secondary btn-sm" style="padding: 4px 8px; font-size: 0.75rem;" onclick="copyModalUrl(this)" title="Copy Link">📋 Copy</button>
    </div>
    <p style="font-size: 0.73rem; color: var(--text-muted); margin-bottom: 14px;">Ensure phone is connected to the same Wi-Fi</p>
    <button class="btn btn-secondary" style="width: 100%;" onclick="closeQRModal()">Close</button>
  </div>
</div>

<!-- File Quick Hover Preview Modal -->
<div class="modal-overlay" id="fileHoverPreviewModal" onclick="closeHoverPreview(event)">
  <div class="modal-card" onclick="event.stopPropagation()" style="max-width: 460px; text-align: left; padding: 20px;">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 12px;">
      <div style="display: flex; align-items: center; gap: 8px; overflow: hidden;">
        <span id="hoverPreviewTypeIcon" style="font-size: 1.5rem; flex-shrink: 0;">📄</span>
        <div style="overflow: hidden;">
          <h3 id="hoverPreviewFileName" style="font-size: 1rem; font-weight: 700; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin: 0;">filename.ext</h3>
          <div id="hoverPreviewFileMeta" style="font-size: 0.74rem; color: var(--text-muted); margin-top: 2px;">1.2 MB • Sep 16, 2026</div>
        </div>
      </div>
      <button class="btn btn-secondary btn-sm" style="padding: 3px 8px; border-radius: 6px;" onclick="closeHoverPreview()">✕</button>
    </div>

    <!-- Media / Content Preview Window -->
    <div id="hoverPreviewBody" style="min-height: 140px; max-height: 280px; overflow: hidden; border-radius: 12px; background: var(--bg); border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; margin-bottom: 12px; position: relative;">
      <!-- Content populated dynamically: image, video, audio, text snippet, or icon -->
    </div>

    <div id="hoverPreviewTags" style="display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px;"></div>

    <!-- Action Buttons -->
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; border-top: 1px solid var(--border); padding-top: 12px;">
      <button type="button" class="btn btn-secondary btn-sm" id="hoverPreviewDetailsBtn" onclick="openDetailFromHover()">
        🔍 Open Details
      </button>
      <div style="display: flex; gap: 6px;">
        <a id="hoverPreviewDownloadBtn" href="#" class="btn btn-primary btn-sm" download>
          ⬇️ Download
        </a>
      </div>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
  let selectedFiles = [];
  let allFiles = [];
  let activeTab = 'upload';
  let currentDetailFile = null;
  let previousTabBeforeDetail = 'upload';
  let fileHoverTimer = null;
  let hoverPreviewTargetFile = null;

  // Setup drag & drop
  const dropZone = document.getElementById('dropZone');
  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); });
  });
  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFilesSelected(e.dataTransfer.files);
    }
  });

  function showToast(msg) {
    const t = document.getElementById('toast');
    t.innerText = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 3000);
  }

  function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const detailPage = document.getElementById('fileDetailPage');
    if (detailPage) detailPage.style.display = 'none';

    document.getElementById('tabUpload').style.display = tab === 'upload' ? 'block' : 'none';
    document.getElementById('tabFiles').style.display = tab === 'files' ? 'block' : 'none';
    document.getElementById('tabNotes').style.display = tab === 'notes' ? 'block' : 'none';
    document.getElementById('tabOpenApi').style.display = tab === 'openapi' ? 'block' : 'none';
    document.getElementById('tabMarkdownDocs').style.display = tab === 'markdowndocs' ? 'block' : 'none';
    document.getElementById('tabSearch').style.display = tab === 'search' ? 'block' : 'none';
    document.getElementById('tabEnvVar').style.display = tab === 'envvar' ? 'block' : 'none';

    if (tab === 'upload') document.getElementById('tabUploadBtn').classList.add('active');
    if (tab === 'files') {
      document.getElementById('tabFilesBtn').classList.add('active');
      fetchFilesList();
    }
    if (tab === 'notes') {
      document.getElementById('tabNotesBtn').classList.add('active');
      fetchNotesList();
    }
    if (tab === 'openapi') {
      document.getElementById('tabOpenApiBtn').classList.add('active');
      initOpenApiTab();
    }
    if (tab === 'markdowndocs') {
      document.getElementById('tabMarkdownDocsBtn').classList.add('active');
      initMarkdownDocsTab();
    }
    if (tab === 'search') {
      document.getElementById('tabSearchBtn').classList.add('active');
      renderLabelFilterPills();
      runGlobalSearch();
    }
    if (tab === 'envvar') {
      document.getElementById('tabEnvVarBtn').classList.add('active');
      initEnvVarTab();
    }
  }

  function handleFilesSelected(files) {
    if (!files || files.length === 0) return;
    selectedFiles = Array.from(files);
    renderQueue();
  }

  function renderQueue() {
    const queueSection = document.getElementById('queueSection');
    const queueList = document.getElementById('queueList');
    const queueSummary = document.getElementById('queueSummary');

    if (selectedFiles.length === 0) {
      queueSection.style.display = 'none';
      return;
    }

    queueSection.style.display = 'block';
    const totalBytes = selectedFiles.reduce((acc, f) => acc + f.size, 0);
    queueSummary.innerText = `${selectedFiles.length} file(s) selected (${formatSize(totalBytes)})`;

    queueList.innerHTML = selectedFiles.map((file, idx) => `
      <div class="file-queue-item">
        <div class="file-info-left">
          <span>${getFileIcon(file.name)}</span>
          <div>
            <div class="file-queue-name">${escapeHtml(file.name)}</div>
            <div class="file-queue-size">${formatSize(file.size)}</div>
          </div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="removeQueueItem(${idx})">✕</button>
      </div>
    `).join('');
  }

  function removeQueueItem(idx) {
    selectedFiles.splice(idx, 1);
    renderQueue();
  }

  function clearQueue() {
    selectedFiles = [];
    document.getElementById('fileInput').value = '';
    renderQueue();
  }

  function startUpload() {
    if (selectedFiles.length === 0) return;

    const formData = new FormData();
    for (let f of selectedFiles) {
      formData.append('files', f);
    }

    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressPercent = document.getElementById('progressPercent');
    const progressSpeed = document.getElementById('progressSpeed');
    const startBtn = document.getElementById('startUploadBtn');

    progressContainer.style.display = 'block';
    startBtn.disabled = true;
    startBtn.innerText = 'Uploading...';

    const startTime = Date.now();
    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 100);
        progressBar.style.width = percent + '%';
        progressPercent.innerText = percent + '%';

        const elapsedSec = (Date.now() - startTime) / 1000;
        if (elapsedSec > 0.5) {
          const speed = e.loaded / elapsedSec; // bytes/sec
          progressSpeed.innerText = `${formatSize(speed)}/s`;
        }
      }
    };

    xhr.onload = () => {
      startBtn.disabled = false;
      startBtn.innerText = '🚀 Send to Computer Now';
      if (xhr.status >= 200 && xhr.status < 300) {
        progressBar.style.width = '100%';
        progressPercent.innerText = '100%';
        progressSpeed.innerText = 'Upload Complete!';
        showToast('✅ Upload completed successfully!');
        clearQueue();
        setTimeout(() => {
          progressContainer.style.display = 'none';
          progressBar.style.width = '0%';
        }, 2000);
        fetchFilesList();
      } else {
        showToast('❌ Upload failed: ' + xhr.responseText);
      }
    };

    xhr.onerror = () => {
      startBtn.disabled = false;
      startBtn.innerText = '🚀 Send to Computer Now';
      showToast('❌ Network error during upload');
    };

    xhr.open('POST', '/upload', true);
    xhr.send(formData);
  }

  let allNotes = [];
  let lastKnownFileCount = 0;
  let lastKnownNoteId = 0;
  let isInitialLoad = true;

  let selectedSearchType = 'all';
  let selectedSearchLabel = '';
  let mdPreviewActive = false;

  // Safe clipboard helper
  function copyTextSafely(btn, text) {
    const orig = btn.innerHTML;
    const showSuccess = () => {
      btn.innerHTML = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.classList.remove('copied');
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showSuccess).catch(() => fallbackCopy(btn, text, orig));
    } else {
      fallbackCopy(btn, text, orig);
    }
  }

  function fallbackCopy(btn, text, orig) {
    if (orig === undefined) orig = btn.innerHTML;
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      btn.innerHTML = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.classList.remove('copied');
      }, 1500);
    } catch (e) {
      showToast('Copy failed');
    }
    document.body.removeChild(ta);
  }

  function copyCodeB64(btn, b64) {
    try {
      const code = decodeURIComponent(escape(atob(b64)));
      copyTextSafely(btn, code);
    } catch (e) {
      showToast('Failed to copy code snippet');
    }
  }

  function toggleCodeWrap(btn) {
    const block = btn.closest('.md-code-block');
    if (!block) return;
    const pre = block.querySelector('pre');
    if (!pre) return;
    const isWrapped = pre.classList.toggle('is-wrapped');
    btn.classList.toggle('active', isWrapped);
    if (isWrapped) {
      btn.innerHTML = '↔ Unwrap';
      btn.title = 'Unwrap lines (enable horizontal scroll)';
    } else {
      btn.innerHTML = '↩ Wrap';
      btn.title = 'Wrap lines to fit width';
    }
  }

  let notesMobileSegment = 'editor';
  const expandedNotesSet = new Set();

  function setNotesMobileSegment(seg) {
    notesMobileSegment = seg;
    const tab = document.getElementById('tabNotes');
    if (tab) tab.setAttribute('data-mobile-segment', seg);

    const btnEd = document.getElementById('btnNotesSegmentEditor');
    const btnSav = document.getElementById('btnNotesSegmentSaved');
    if (btnEd) btnEd.classList.toggle('active', seg === 'editor');
    if (btnSav) btnSav.classList.toggle('active', seg === 'saved');
  }

  function toggleNoteSnippet(id) {
    if (expandedNotesSet.has(id)) {
      expandedNotesSet.delete(id);
    } else {
      expandedNotesSet.add(id);
    }
    const snippetEl = document.getElementById(`noteSnippet_${id}`);
    const toggleBtn = document.getElementById(`noteSnippetToggle_${id}`);
    const isExp = expandedNotesSet.has(id);
    if (snippetEl) {
      snippetEl.classList.toggle('expanded', isExp);
      snippetEl.classList.toggle('collapsed', !isExp);
    }
    if (toggleBtn) {
      toggleBtn.innerText = isExp ? '▲ Collapse snippet' : '▼ Show full snippet';
    }
  }

  let activeEditingNoteId = null;
  let notesFilterQuery = '';

  function loadNoteToEditor(id) {
    activeEditingNoteId = id;
    const note = allNotes.find(n => n.id === id);
    if (!note) return;
    const titleInput = document.getElementById('noteTitleInput');
    const labelsInput = document.getElementById('noteLabelsInput');
    const input = document.getElementById('noteInput');
    if (titleInput) titleInput.value = note.title || '';
    if (labelsInput) labelsInput.value = (note.labels || []).join(', ');
    if (input) input.value = note.text || '';
    onNoteInputChanged();

    document.querySelectorAll('.note-item').forEach(el => el.classList.remove('active-note'));
    const card = document.getElementById(`noteCard_${id}`);
    if (card) card.classList.add('active-note');

    if (window.innerWidth < 1024 || currentLayoutMode === 'vertical') {
      setNotesMobileSegment('editor');
    }
    showToast('📝 Loaded note into editor');
  }

  function createNewNoteFromList() {
    activeEditingNoteId = null;
    clearNoteInputs();
    document.querySelectorAll('.note-item').forEach(el => el.classList.remove('active-note'));
    const input = document.getElementById('noteInput');
    if (input) input.focus();
    if (window.innerWidth < 1024 || currentLayoutMode === 'vertical') {
      setNotesMobileSegment('editor');
    }
    showToast('📝 Started new note');
  }

  function filterNotesList(query) {
    notesFilterQuery = (query || '').toLowerCase().trim();
    if (!notesFilterQuery) {
      renderNotesList(allNotes);
      return;
    }
    const filtered = allNotes.filter(n => {
      const t = (n.title || '').toLowerCase();
      const txt = (n.text || '').toLowerCase();
      const labels = (n.labels || []).join(' ').toLowerCase();
      const sender = (n.sender || '').toLowerCase();
      return t.includes(notesFilterQuery) || txt.includes(notesFilterQuery) || labels.includes(notesFilterQuery) || sender.includes(notesFilterQuery);
    });
    renderNotesList(filtered);
  }

  function copyNoteById(btn, id) {
    const note = allNotes.find(n => n.id === id);
    if (!note) return;
    copyTextSafely(btn, note.text);
  }

  function copyNoteText(btn, text) {
    copyTextSafely(btn, text);
  }

  // Pure JavaScript Syntax Highlighting
  function highlightJson(jsonStr) {
    let escaped = escapeHtml(jsonStr);
    return escaped.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      let cls = 'hl-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'hl-key';
        } else {
          cls = 'hl-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'hl-bool';
      } else if (/null/.test(match)) {
        cls = 'hl-null';
      }
      return `<span class="${cls}">${match}</span>`;
    });
  }

  function highlightCode(code, lang) {
    const l = (lang || '').toLowerCase();
    if (l === 'json') {
      return highlightJson(code);
    }
    let escaped = escapeHtml(code);
    let keywords = [];
    if (l === 'js' || l === 'javascript' || l === 'ts' || l === 'typescript') {
      keywords = ['const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'switch', 'case', 'break', 'new', 'class', 'extends', 'import', 'from', 'export', 'default', 'async', 'await', 'try', 'catch', 'throw', 'this', 'true', 'false', 'null', 'undefined'];
    } else if (l === 'py' || l === 'python') {
      keywords = ['def', 'class', 'import', 'from', 'as', 'return', 'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with', 'lambda', 'yield', 'pass', 'raise', 'in', 'is', 'not', 'and', 'or', 'True', 'False', 'None', 'self'];
    } else if (l === 'sql') {
      keywords = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'UPDATE', 'DELETE', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'GROUP', 'BY', 'ORDER', 'LIMIT', 'OFFSET', 'HAVING', 'AS', 'AND', 'OR', 'NOT', 'NULL', 'TABLE', 'CREATE', 'DROP', 'SET'];
    } else if (l === 'sh' || l === 'bash' || l === 'shell') {
      keywords = ['echo', 'cd', 'ls', 'mkdir', 'rm', 'cp', 'mv', 'chmod', 'chown', 'sudo', 'grep', 'cat', 'curl', 'wget', 'export', 'if', 'then', 'else', 'fi', 'for', 'in', 'do', 'done'];
    }

    // Strings
    escaped = escaped.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"|'(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\'])*')/g, '<span class="hl-string">$1</span>');

    // Comments
    if (l === 'py' || l === 'sh' || l === 'bash' || l === 'shell') {
      escaped = escaped.replace(/(#.*$)/gm, '<span class="hl-comment">$1</span>');
    } else if (l === 'sql') {
      escaped = escaped.replace(/(--.*$)/gm, '<span class="hl-comment">$1</span>');
    } else {
      escaped = escaped.replace(/(\/\/.*$)/gm, '<span class="hl-comment">$1</span>');
    }

    // Keywords
    if (keywords.length > 0) {
      const kwRegex = new RegExp(`\\b(${keywords.join('|')})\\b`, l === 'sql' ? 'gi' : 'g');
      escaped = escaped.replace(kwRegex, '<span class="hl-keyword">$1</span>');
    }

    // Numbers
    escaped = escaped.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="hl-number">$1</span>');

    return escaped;
  }

  function renderMarkdownTables(html) {
    if (!html || !html.includes('|')) return html;
    const lines = html.split('\n');
    const out = [];
    let inTable = false;
    let tableLines = [];

    function flushTable(raw) {
      if (raw.length < 2) return raw.join('\n');
      const headerLine = raw[0].trim();
      const delimLine = raw[1].trim();
      const isDelim = /^\|?\s*:?-+:?\s*(\|(\s*:?-+:?\s*))+\|?$/.test(delimLine);
      if (!isDelim) return raw.join('\n');

      function getCells(row) {
        let r = row.trim();
        if (r.startsWith('|')) r = r.slice(1);
        if (r.endsWith('|')) r = r.slice(0, -1);
        return r.split('|').map(c => c.trim());
      }

      const headers = getCells(headerLine);
      const delims = getCells(delimLine);
      const aligns = delims.map(d => {
        const left = d.startsWith(':');
        const right = d.endsWith(':');
        if (left && right) return 'center';
        if (right) return 'right';
        return 'left';
      });

      let res = '<div class="md-table-wrapper"><table class="md-table"><thead><tr>';
      headers.forEach((h, i) => {
        const al = aligns[i] || 'left';
        res += `<th style="text-align:${al};">${h}</th>`;
      });
      res += '</tr></thead><tbody>';

      for (let i = 2; i < raw.length; i++) {
        if (!raw[i].trim()) continue;
        const cells = getCells(raw[i]);
        res += '<tr>';
        for (let j = 0; j < headers.length; j++) {
          const val = cells[j] !== undefined ? cells[j] : '';
          const al = aligns[j] || 'left';
          res += `<td style="text-align:${al};">${val}</td>`;
        }
        res += '</tr>';
      }
      res += '</tbody></table></div>';
      return res;
    }

    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const trimmed = l.trim();
      if (trimmed.includes('|') && !trimmed.startsWith('&lt;') && !trimmed.startsWith('<div')) {
        inTable = true;
        tableLines.push(l);
      } else {
        if (inTable) {
          out.push(flushTable(tableLines));
          tableLines = [];
          inTable = false;
        }
        out.push(l);
      }
    }
    if (inTable && tableLines.length > 0) {
      out.push(flushTable(tableLines));
    }
    return out.join('\n');
  }

  // Pure JavaScript Markdown Parser with Syntax Highlighting, Tables & Diagrams
  function renderMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Fenced code blocks ```lang\ncode```
    html = html.replace(/```([a-zA-Z0-9_-]*)\r?\n([\s\S]*?)```/g, (match, lang, code) => {
      const rawCode = code
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'");
      let b64 = '';
      try {
        b64 = btoa(unescape(encodeURIComponent(rawCode)));
      } catch (e) {}

      const cleanLang = (lang || '').toLowerCase().trim();

      // Mermaid Diagram block
      if (cleanLang === 'mermaid') {
        return `<div class="mermaid-diagram-card"><div class="mermaid-header"><span class="mermaid-title">📊 Mermaid Diagram</span><button type="button" class="md-code-btn" onclick="copyCodeB64(this, '${b64}')" title="Copy mermaid source">📋 Copy Source</button></div><div class="mermaid-viewport"><div class="mermaid-render-target" data-mermaid-code="${b64}">Loading diagram...</div></div></div>`;
      }

      // ASCII / Architecture Blueprint block
      const hasAsciiChars = /[─│┌┐└┘├┤┬┴┼═║╔╗╚╝╞╡╪╭╮╯╰╱╲▀▄█▌▐░▒▓]|(\+[\-\=]+\+)/.test(rawCode);
      if (cleanLang === 'ascii' || cleanLang === 'box' || cleanLang === 'ditaa' || (cleanLang === 'text' && hasAsciiChars) || hasAsciiChars) {
        return `<div class="ascii-diagram-card"><div class="ascii-diagram-header"><span class="ascii-diagram-title">📐 Architecture / ASCII Blueprint</span><button type="button" class="md-code-btn md-copy-btn" onclick="copyCodeB64(this, '${b64}')" title="Copy ASCII">📋 Copy</button></div><div class="ascii-diagram-body"><pre class="ascii-diagram-pre"><code>${escapeHtml(rawCode)}</code></pre></div></div>`;
      }

      const highlighted = highlightCode(rawCode, lang);
      const displayLang = (lang || 'code').toUpperCase();
      return `<div class="md-code-block"><div class="md-code-header"><span class="md-code-lang">💻 ${displayLang}</span><div class="md-code-actions"><button type="button" class="md-code-btn md-wrap-btn" onclick="toggleCodeWrap(this)" title="Toggle word wrap">↩ Wrap</button><button type="button" class="md-code-btn md-copy-btn" onclick="copyCodeB64(this, '${b64}')" title="Copy code">📋 Copy</button></div></div><pre><code>${highlighted}</code></pre></div>`;
    });

    // Inline code `code`
    html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>');

    // Headings (#, ##, ###)
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Blockquotes > quote
    html = html.replace(/^&gt; (.*$)/gim, '<blockquote>$1</blockquote>');

    // Bold & Italic
    html = html.replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Strikethrough ~~strike~~
    html = html.replace(/~~([^~]+)~~/g, '<del>$1</del>');

    // Markdown links [text](url)
    html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s\)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    // GFM Tables
    html = renderMarkdownTables(html);

    // Unordered lists - or *
    html = html.replace(/(?:^|\n)[-*] (.*)/g, (m, item) => `\n<li>${item}</li>`);
    html = html.replace(/(<li>[\s\S]*?<\/li>)+/g, '<ul>$&</ul>');

    // Autolink plain URLs & preserve linebreaks outside cards/code/tables
    const parts = html.split(/(<div class="(?:md-code-block|ascii-diagram-card|mermaid-diagram-card|md-table-wrapper)"[\s\S]*?<\/div>)/g);
    for (let i = 0; i < parts.length; i += 2) {
      parts[i] = parts[i].replace(/(^|[^"])((https?:\/\/[^\s<]+))/g, '$1<a href="$2" target="_blank" rel="noopener noreferrer">$2</a>');
      parts[i] = parts[i].replace(/\n/g, '<br>');
    }
    return parts.join('');
  }

  // Note Tools & Utilities
  function toggleMdPreview(btn) {
    mdPreviewActive = !mdPreviewActive;
    const preview = document.getElementById('noteMdPreview');
    const input = document.getElementById('noteInput');
    if (!btn) btn = document.getElementById('btnMdToggle');

    if (mdPreviewActive) {
      if (btn) {
        btn.classList.add('active');
        btn.innerText = '✏️ Edit View';
      }
      if (preview) {
        preview.style.display = 'block';
        preview.innerHTML = renderMarkdown(input.value) || '<i style="color:var(--text-muted);">Preview will appear here when you type...</i>';
      }
    } else {
      if (btn) {
        btn.classList.remove('active');
        btn.innerText = '👁️ MD Preview';
      }
      if (preview) preview.style.display = 'none';
    }
  }

  // JSON Validation & Lenient JSONC Parser
  let jsonErrorTimeout = null;

  function clearJsonError() {
    clearTimeout(jsonErrorTimeout);
    const input = document.getElementById('noteInput');
    const banner = document.getElementById('jsonErrorBar');
    if (input) input.classList.remove('json-invalid');
    if (banner) {
      banner.style.display = 'none';
      banner.innerHTML = '';
    }
  }

  function parseJsonLocation(err, text) {
    let line = 1, col = 1, pos = -1;
    const msg = err ? (err.message || '') : '';
    const posMatch = msg.match(/at position (\d+)/i) || msg.match(/position (\d+)/i) || msg.match(/char (\d+)/i);
    const lineColMatch = msg.match(/line (\d+) column (\d+)/i);

    if (lineColMatch) {
      line = parseInt(lineColMatch[1], 10);
      col = parseInt(lineColMatch[2], 10);
    } else if (posMatch) {
      pos = parseInt(posMatch[1], 10);
      const sub = text.slice(0, Math.min(pos, text.length));
      const lines = sub.split('\n');
      line = lines.length;
      col = lines[lines.length - 1].length + 1;
    }
    return { line, col, pos };
  }

  function parseLenientJsonc(rawText) {
    if (!rawText || !rawText.trim()) throw new Error('Empty JSON input');

    // 1. Strip comments (// and /* */) while preserving exact line breaks and column spacing
    let cleaned = '';
    let inString = false;
    let stringChar = '';
    let i = 0;
    const len = rawText.length;

    while (i < len) {
      const ch = rawText[i];
      const next = rawText[i + 1];

      if (inString) {
        cleaned += ch;
        if (ch === '\\' && i + 1 < len) {
          cleaned += next;
          i += 2;
          continue;
        }
        if (ch === stringChar) {
          inString = false;
        }
        i++;
        continue;
      }

      if (ch === '"' || ch === "'") {
        inString = true;
        stringChar = ch;
        cleaned += '"'; // normalize to double quote
        i++;
        continue;
      }

      // Single-line comment //
      if (ch === '/' && next === '/') {
        while (i < len && rawText[i] !== '\n') {
          cleaned += ' ';
          i++;
        }
        continue;
      }

      // Multi-line comment /* ... */
      if (ch === '/' && next === '*') {
        cleaned += '  ';
        i += 2;
        while (i < len && !(rawText[i] === '*' && rawText[i + 1] === '/')) {
          if (rawText[i] === '\n') cleaned += '\n';
          else cleaned += ' ';
          i++;
        }
        if (i < len) {
          cleaned += '  ';
          i += 2;
        }
        continue;
      }

      cleaned += ch;
      i++;
    }

    // 2. Relaxed JSON: remove trailing commas before } or ]
    let relaxed = cleaned.replace(/,\s*([\}\]])/g, '$1');

    // 3. Relaxed JSON: wrap unquoted keys: { foo: "bar" } -> { "foo": "bar" }
    let unquotedFixed = relaxed.replace(/([{,]\s*)([a-zA-Z0-9_$-]+)\s*:/g, '$1"$2":');

    try {
      return { data: JSON.parse(relaxed), cleanText: relaxed };
    } catch (e1) {
      try {
        return { data: JSON.parse(unquotedFixed), cleanText: unquotedFixed };
      } catch (e2) {
        throw e1;
      }
    }
  }

  function showJsonError(err, text) {
    const input = document.getElementById('noteInput');
    const banner = document.getElementById('jsonErrorBar');
    if (!input) return;

    // Apply temporary red wavy underline class
    input.classList.add('json-invalid');

    // Find position of invalid syntax
    const loc = parseJsonLocation(err, text);
    const lines = text.split('\n');
    const lineIdx = Math.min(Math.max(0, loc.line - 1), lines.length - 1);
    const errLine = lines[lineIdx] || '';
    const col = Math.max(1, Math.min(loc.col, errLine.length + 1));

    const before = escapeHtml(errLine.slice(0, col - 1));
    const badChar = escapeHtml(errLine.slice(col - 1, col) || ' ');
    const after = escapeHtml(errLine.slice(col));

    if (banner) {
      banner.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
          <div style="font-weight: 700; display: flex; align-items: center; gap: 6px;">
            <span>⚠️ Invalid JSON at Line ${loc.line}, Col ${col}:</span>
            <span style="font-weight: normal; opacity: 0.9;">${escapeHtml(err.message)}</span>
          </div>
          <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 0.7rem;" onclick="clearJsonError()">✕</button>
        </div>
        <div class="json-error-snippet">${before}<mark>${badChar}</mark>${after}</div>
      `;
      banner.style.display = 'block';
    }

    let cursorChar = 0;
    for (let l = 0; l < lineIdx; l++) {
      cursorChar += lines[l].length + 1;
    }
    cursorChar += (col - 1);

    input.focus();
    input.setSelectionRange(cursorChar, Math.min(text.length, cursorChar + 1));

    showToast(`⚠️ Invalid JSON at line ${loc.line}, col ${col}`);

    // Automatically clear temporary red underline after 5 seconds
    clearTimeout(jsonErrorTimeout);
    jsonErrorTimeout = setTimeout(() => {
      clearJsonError();
    }, 5000);
  }

  function onNoteInputChanged() {
    clearJsonError();
    if (mdPreviewActive) {
      const preview = document.getElementById('noteMdPreview');
      const input = document.getElementById('noteInput');
      if (preview && input) {
        preview.innerHTML = renderMarkdown(input.value) || '<i style="color:var(--text-muted);">Preview will appear here when you type...</i>';
      }
    }
  }

  function clearNoteInputs() {
    clearJsonError();
    const title = document.getElementById('noteTitleInput');
    const labels = document.getElementById('noteLabelsInput');
    const input = document.getElementById('noteInput');
    if (title) title.value = '';
    if (labels) labels.value = '';
    if (input) input.value = '';
    if (mdPreviewActive) {
      toggleMdPreview(document.getElementById('btnMdToggle'));
    }
  }

  function toolJsonBeautify() {
    const input = document.getElementById('noteInput');
    let text = input.value.trim();
    if (!text) {
      showToast('⚠️ Note content is empty');
      return;
    }
    const codeBlockMatch = text.match(/^```(?:json|jsonc)?\r?\n([\s\S]*?)\r?\n```$/i);
    let innerText = codeBlockMatch ? codeBlockMatch[1].trim() : text;

    try {
      clearJsonError();
      const res = parseLenientJsonc(innerText);
      const formatted = JSON.stringify(res.data, null, 2);
      input.value = "```json\n" + formatted + "\n```";
      showToast('✨ JSON formatted (JSONC & lenient supported)');
      if (!mdPreviewActive) {
        toggleMdPreview(document.getElementById('btnMdToggle'));
      } else {
        onNoteInputChanged();
      }
    } catch (err) {
      showJsonError(err, innerText);
    }
  }

  function toolJsonMinify() {
    const input = document.getElementById('noteInput');
    let text = input.value.trim();
    if (!text) {
      showToast('⚠️ Note content is empty');
      return;
    }
    const codeBlockMatch = text.match(/^```(?:json|jsonc)?\r?\n([\s\S]*?)\r?\n```$/i);
    let innerText = codeBlockMatch ? codeBlockMatch[1].trim() : text;

    try {
      clearJsonError();
      const res = parseLenientJsonc(innerText);
      input.value = JSON.stringify(res.data);
      showToast('🗜️ JSON minified');
      onNoteInputChanged();
    } catch (err) {
      showJsonError(err, innerText);
    }
  }

  function changeNoteCodeFormat(lang) {
    if (!lang) return;
    const input = document.getElementById('noteInput');
    let text = input.value.trim();
    const selector = document.getElementById('codeFormatSelector');

    if (lang === 'unwrap') {
      const codeBlockMatch = text.match(/^```[a-zA-Z0-9_-]*\r?\n([\s\S]*?)\r?\n```$/);
      if (codeBlockMatch) {
        input.value = codeBlockMatch[1].trim();
      }
      showToast('📝 Unwrapped code block to plain text');
    } else {
      const codeBlockMatch = text.match(/^```[a-zA-Z0-9_-]*\r?\n([\s\S]*?)\r?\n```$/);
      if (codeBlockMatch) {
        input.value = `\`\`\`${lang}\n${codeBlockMatch[1].trim()}\n\`\`\``;
      } else {
        input.value = `\`\`\`${lang}\n${text}\n\`\`\``;
      }
      showToast(`🔣 Formatted code block as ${lang.toUpperCase()}`);
    }

    if (selector) selector.value = '';
    if (!mdPreviewActive) {
      toggleMdPreview(document.getElementById('btnMdToggle'));
    } else {
      onNoteInputChanged();
    }
  }

  function toolStringEscape() {
    const input = document.getElementById('noteInput');
    const text = input.value;
    if (!text) return;
    const escaped = JSON.stringify(text).slice(1, -1);
    input.value = escaped;
    showToast('🔤 String escaped');
    onNoteInputChanged();
  }

  function toolStringUnescape() {
    const input = document.getElementById('noteInput');
    const text = input.value;
    if (!text) return;
    try {
      const unescaped = JSON.parse('"' + text.replace(/"/g, '\\"') + '"');
      input.value = unescaped;
      showToast('🔓 String unescaped');
      onNoteInputChanged();
    } catch (e) {
      const unescaped = text
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t')
        .replace(/\\"/g, '"')
        .replace(/\\'/g, "'")
        .replace(/\\\\/g, '\\');
      input.value = unescaped;
      showToast('🔓 String unescaped');
      onNoteInputChanged();
    }
  }

  function toolBase64Encode() {
    const input = document.getElementById('noteInput');
    const text = input.value;
    if (!text) return;
    try {
      const encoded = btoa(unescape(encodeURIComponent(text)));
      input.value = encoded;
      showToast('🔒 Encoded to Base64');
      onNoteInputChanged();
    } catch (err) {
      showToast('❌ Encoding error: ' + err.message);
    }
  }

  function toolBase64Decode() {
    const input = document.getElementById('noteInput');
    const text = input.value.trim();
    if (!text) return;
    try {
      const decoded = decodeURIComponent(escape(atob(text)));
      input.value = decoded;
      showToast('🔓 Decoded from Base64');
      onNoteInputChanged();
    } catch (err) {
      showToast('❌ Invalid Base64 data');
    }
  }

  // Quick Tag Modal & Label Management (Max 10 Characters)
  let currentTagModalTarget = null;
  let tagModalFilteredItems = [];
  let tagModalSelectedIndex = 0; // -1 for create option on top; 0, 1, 2... for match list items

  function openTagModal(type, id) {
    currentTagModalTarget = { type, id };
    const modal = document.getElementById('tagModal');
    const targetLabel = document.getElementById('tagModalTargetName');
    const input = document.getElementById('tagModalInput');

    let targetName = String(id);
    let existingItemLabels = [];
    if (type === 'file') {
      const f = allFiles.find(x => x.name === id);
      if (f) {
        targetName = '📁 File: ' + f.name;
        existingItemLabels = (f.labels || []).map(l => l.toLowerCase());
      }
    } else {
      const n = allNotes.find(x => x.id === id);
      if (n) {
        targetName = '📝 Note: ' + (n.title || n.text.slice(0, 30));
        existingItemLabels = (n.labels || []).map(l => l.toLowerCase());
      }
    }
    currentTagModalTarget.existingLabels = existingItemLabels;

    if (targetLabel) targetLabel.innerText = targetName;
    if (input) input.value = '';

    modal.classList.add('active');
    setTimeout(() => {
      if (input) input.focus();
    }, 80);

    renderTagModalCandidates('');
  }

  function closeTagModal(e) {
    if (!e || e.target.id === 'tagModal' || e.type === 'click' || e.key === 'Escape') {
      const modal = document.getElementById('tagModal');
      if (modal) modal.classList.remove('active');
      currentTagModalTarget = null;
    }
  }

  function promptAddLabel(type, id) {
    openTagModal(type, id);
  }

  function getTagMatchScore(query, tag) {
    const q = query.toLowerCase();
    const t = tag.toLowerCase();
    if (t === q) return 10000;
    if (t.startsWith(q)) return 8000 - (t.length - q.length) * 10;
    const idx = t.indexOf(q);
    if (idx !== -1) return 5000 - idx * 20 - (t.length - q.length) * 10;
    // Subsequence match (characters appear in order)
    let qi = 0;
    for (let i = 0; i < t.length && qi < q.length; i++) {
      if (t[i] === q[qi]) qi++;
    }
    if (qi === q.length) return 3000 - (t.length - q.length) * 10;
    // Overlapping characters
    let common = 0;
    for (let ch of q) {
      if (t.includes(ch)) common++;
    }
    if (common >= Math.ceil(q.length * 0.6)) return 1000 + common * 50;
    return 0;
  }

  function renderTagModalCandidates(rawQuery) {
    const query = (rawQuery || '').trim().toLowerCase().replace(/^#/, '');
    const createName = document.getElementById('tagModalCreateName');
    const allLabels = getAllLabels();
    const existingOnItem = (currentTagModalTarget && currentTagModalTarget.existingLabels) || [];

    // Filter out tags already applied to this specific item
    const candidates = allLabels.filter(lbl => !existingOnItem.includes(lbl.toLowerCase()));

    if (createName) {
      createName.innerText = query ? query : '(type to name)';
    }

    if (!query) {
      tagModalFilteredItems = candidates.map(tag => ({ tag, score: 0 }));
      tagModalSelectedIndex = tagModalFilteredItems.length > 0 ? 0 : -1;
    } else {
      const scored = [];
      for (let tag of candidates) {
        const score = getTagMatchScore(query, tag);
        if (score > 0) {
          scored.push({ tag, score });
        }
      }
      // Sort nearest matches near the top (closest to the edit text box)
      scored.sort((a, b) => b.score - a.score);
      tagModalFilteredItems = scored;

      // If near match found, default to nearest item (index 0) with green highlight
      // If no match found, default to create option (-1) with green highlight
      if (tagModalFilteredItems.length > 0) {
        tagModalSelectedIndex = 0;
      } else {
        tagModalSelectedIndex = -1;
      }
    }

    renderTagModalListDom();
  }

  function renderTagModalListDom() {
    const listContainer = document.getElementById('tagModalList');
    const createOption = document.getElementById('tagModalCreateOption');
    if (!listContainer) return;

    if (createOption) {
      if (tagModalSelectedIndex === -1) {
        createOption.classList.add('selected');
      } else {
        createOption.classList.remove('selected');
      }
    }

    if (tagModalFilteredItems.length === 0) {
      const typed = document.getElementById('tagModalInput')?.value.trim().replace(/^#/, '') || '';
      listContainer.innerHTML = `
        <div style="padding: 12px; text-align: center; color: var(--text-muted); font-size: 0.8rem; background: var(--surface); border-radius: 8px; border: 1px dashed var(--border);">
          ${typed ? `No matching tags found. Press <strong style="color:var(--success);">Enter</strong> to create "<span style="color:var(--primary); font-weight:600;">${escapeHtml(typed)}</span>"` : 'No existing tags to choose from. Type a tag name to create one!'}
        </div>
      `;
      return;
    }

    listContainer.innerHTML = tagModalFilteredItems.map((item, idx) => {
      const isSel = (tagModalSelectedIndex === idx);
      return `
        <div class="tag-modal-item ${isSel ? 'selected' : ''}" onclick="confirmTagSelection(${idx})" id="tagModalItem_${idx}">
          <div style="display: flex; align-items: center; gap: 6px;">
            <span style="font-weight: 700;">#${escapeHtml(item.tag)}</span>
            ${idx === 0 && tagModalSelectedIndex === 0 ? '<span style="font-size:0.68rem; background: rgba(16,185,129,0.2); color: var(--success); padding: 1px 6px; border-radius: 4px; font-weight:700;">Nearest match</span>' : ''}
          </div>
          <span style="font-size: 0.72rem; color: var(--text-muted);">${isSel ? '↵ Select' : 'Pick'}</span>
        </div>
      `;
    }).join('');

    if (tagModalSelectedIndex >= 0) {
      const el = document.getElementById(`tagModalItem_${tagModalSelectedIndex}`);
      if (el && listContainer) {
        el.scrollIntoView({ block: 'nearest' });
      }
    }
  }

  function onTagModalKeyDown(e) {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (tagModalSelectedIndex > 0) {
        tagModalSelectedIndex--;
      } else if (tagModalSelectedIndex === 0) {
        // Move to "Create tag" option on top of text box
        tagModalSelectedIndex = -1;
      }
      renderTagModalListDom();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (tagModalSelectedIndex === -1) {
        if (tagModalFilteredItems.length > 0) {
          tagModalSelectedIndex = 0;
        }
      } else if (tagModalSelectedIndex < tagModalFilteredItems.length - 1) {
        tagModalSelectedIndex++;
      }
      renderTagModalListDom();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      confirmTagSelection(tagModalSelectedIndex);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      closeTagModal();
    }
  }

  function onTagModalInputChanged() {
    const input = document.getElementById('tagModalInput');
    if (input) {
      input.value = input.value.replace(/\s+/g, '-').slice(0, 50);
    }
    renderTagModalCandidates(input ? input.value : '');
  }

  function confirmTagSelection(choice) {
    if (!currentTagModalTarget) return;

    let chosenTag = '';
    const input = document.getElementById('tagModalInput');
    const typedText = input ? input.value.trim().replace(/^#/, '').replace(/\s+/g, '-') : '';

    if (choice === 'create' || choice === -1) {
      if (!typedText) {
        showToast('⚠️ Please type a tag name to create');
        if (input) input.focus();
        return;
      }
      chosenTag = typedText;
    } else if (typeof choice === 'number' && choice >= 0 && choice < tagModalFilteredItems.length) {
      chosenTag = tagModalFilteredItems[choice].tag;
    } else {
      if (typedText) chosenTag = typedText;
      else return;
    }

    chosenTag = chosenTag.replace(/\s+/g, '-').slice(0, 50);
    if (chosenTag.length > 50) {
      showToast('⚠️ Tag cannot exceed 50 characters');
      return;
    }

    const { type, id } = currentTagModalTarget;
    closeTagModal();
    recordRecentTag(chosenTag);
    updateItemLabel(type, id, chosenTag, 'add');
  }

  // Recent Tags Memory & Hover Popover
  let popoverTarget = null;
  let popoverHideTimeout = null;

  function getRecentTags() {
    try {
      const stored = JSON.parse(localStorage.getItem('recent_lan_tags') || '[]');
      if (Array.isArray(stored) && stored.length > 0) return stored;
    } catch (e) {}
    return getAllLabels().slice(0, 6);
  }

  function recordRecentTag(tag) {
    if (!tag) return;
    try {
      let recents = getRecentTags().filter(t => t.toLowerCase() !== tag.toLowerCase());
      recents.unshift(tag);
      if (recents.length > 8) recents = recents.slice(0, 8);
      localStorage.setItem('recent_lan_tags', JSON.stringify(recents));
    } catch (e) {}
  }

  function onTagBtnHover(btn, type, id) {
    clearTimeout(popoverHideTimeout);
    popoverTarget = { type, id };
    const popover = document.getElementById('recentTagsPopover');
    const list = document.getElementById('recentTagsList');
    if (!popover || !list) return;

    const recents = getRecentTags();
    let currentItemTags = [];
    if (type === 'file') {
      const f = allFiles.find(x => x.name === id);
      if (f) currentItemTags = (f.labels || []).map(l => l.toLowerCase());
    } else {
      const n = allNotes.find(x => x.id === id);
      if (n) currentItemTags = (n.labels || []).map(l => l.toLowerCase());
    }
    const availableRecents = recents.filter(t => !currentItemTags.includes(t.toLowerCase()));

    if (availableRecents.length === 0) {
      list.innerHTML = `<span style="font-size:0.72rem; color:var(--text-muted); font-style:italic;">No recently used tags yet</span>`;
    } else {
      list.innerHTML = availableRecents.map(tag => `
        <span class="popover-tag-chip" onclick="applyRecentTag('${escapeHtml(tag)}')">#${escapeHtml(tag)}</span>
      `).join('');
    }

    const rect = btn.getBoundingClientRect();
    popover.style.left = `${rect.left + rect.width / 2}px`;
    popover.style.top = `${rect.top}px`;
    popover.style.display = 'flex';
  }

  function onTagBtnLeave() {
    popoverHideTimeout = setTimeout(() => {
      const popover = document.getElementById('recentTagsPopover');
      if (popover) popover.style.display = 'none';
      popoverTarget = null;
    }, 280);
  }

  function onPopoverEnter() {
    clearTimeout(popoverHideTimeout);
  }

  function onPopoverLeave() {
    onTagBtnLeave();
  }

  function applyRecentTag(tag) {
    if (!popoverTarget) return;
    const { type, id } = popoverTarget;
    const popover = document.getElementById('recentTagsPopover');
    if (popover) popover.style.display = 'none';
    popoverTarget = null;
    recordRecentTag(tag);
    updateItemLabel(type, id, tag, 'add');
  }

  function updateItemLabel(type, id, label, action) {
    fetch('/api/label', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, id, label, action })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        if (action === 'add') recordRecentTag(label);
        showToast(action === 'add' ? `🏷️ Added label #${label}` : `Removed label #${label}`);
        if (type === 'file') {
          fetchFilesList();
          if (currentDetailFile && currentDetailFile.name === id) {
            if (action === 'add') {
              if (!currentDetailFile.labels) currentDetailFile.labels = [];
              if (!currentDetailFile.labels.includes(label)) currentDetailFile.labels.push(label);
            } else if (action === 'remove') {
              if (currentDetailFile.labels) {
                currentDetailFile.labels = currentDetailFile.labels.filter(l => l !== label);
              }
            }
            renderDetailTags(currentDetailFile);
          }
        } else {
          fetchNotesList();
        }
      } else {
        showToast('❌ ' + (data.error || 'Label update failed'));
      }
    })
    .catch(() => showToast('❌ Network error updating label'));
  }

  function renderLabelBadges(type, id, labels) {
    const list = labels || [];
    const chipsHtml = list.map(lbl => `
      <span class="label-chip" title="Filter by #${escapeHtml(lbl)}" onclick="event.stopPropagation(); filterByLabel('${escapeHtml(lbl)}')">
        #${escapeHtml(lbl)}
        <span class="label-remove" onclick="event.stopPropagation(); updateItemLabel('${type}', '${escapeHtml(String(id))}', '${escapeHtml(lbl)}', 'remove')" title="Remove label">×</span>
      </span>
    `).join('');

    return `
      <div style="display: flex; align-items: center; gap: 4px; flex-wrap: wrap; margin-top: 5px;">
        ${chipsHtml}
        <button type="button" class="label-add-btn" onmouseenter="onTagBtnHover(this, '${type}', '${escapeHtml(String(id))}')" onmouseleave="onTagBtnLeave()" onclick="event.stopPropagation(); promptAddLabel('${type}', '${escapeHtml(String(id))}')" title="Add tag (max 50 chars, hover for recent tags)">+ Tag</button>
      </div>
    `;
  }

  function getAllLabels() {
    const set = new Set();
    for (let f of allFiles) {
      if (f.labels && Array.isArray(f.labels)) {
        f.labels.forEach(l => set.add(l));
      }
    }
    for (let n of allNotes) {
      if (n.labels && Array.isArray(n.labels)) {
        n.labels.forEach(l => set.add(l));
      }
    }
    return Array.from(set).sort();
  }

  function renderLabelFilterPills() {
    const container = document.getElementById('labelFilterPills');
    if (!container) return;
    const labels = getAllLabels();
    if (labels.length === 0) {
      container.innerHTML = '<span style="font-size: 0.78rem; color: var(--text-muted);">No labels yet. Add tags (+ Tag) to any file or note!</span>';
      return;
    }

    container.innerHTML = labels.map(lbl => {
      const isSel = (selectedSearchLabel.toLowerCase() === lbl.toLowerCase());
      return `<button class="filter-pill ${isSel ? 'active' : ''}" onclick="filterByLabel('${escapeHtml(lbl)}')">#${escapeHtml(lbl)}</button>`;
    }).join('');
  }

  // Search & Filter Operations
  function filterByLabel(label) {
    if (activeTab !== 'search') {
      switchTab('search');
    }
    selectedSearchLabel = (selectedSearchLabel.toLowerCase() === label.toLowerCase()) ? '' : label;
    renderLabelFilterPills();
    runGlobalSearch();
  }

  function setSearchType(type, btn) {
    selectedSearchType = type;
    document.querySelectorAll('#searchTypeFilters .filter-pill').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    runGlobalSearch();
  }

  function clearSearchFilters() {
    selectedSearchType = 'all';
    selectedSearchLabel = '';
    const input = document.getElementById('globalSearchInput');
    if (input) input.value = '';
    document.querySelectorAll('#searchTypeFilters .filter-pill').forEach((b, idx) => {
      if (idx === 0) b.classList.add('active');
      else b.classList.remove('active');
    });
    renderLabelFilterPills();
    runGlobalSearch();
  }

  function runGlobalSearch() {
    const query = (document.getElementById('globalSearchInput')?.value || '').trim().toLowerCase();
    const summary = document.getElementById('searchResultsSummary');
    const container = document.getElementById('searchResultsContainer');
    if (!container) return;

    let labelQuery = selectedSearchLabel.toLowerCase();
    let textQuery = query;

    if (textQuery.startsWith('#')) {
      labelQuery = textQuery.slice(1);
      textQuery = '';
    }

    const results = [];

    // Filter files
    if (selectedSearchType === 'all' || selectedSearchType === 'files' || selectedSearchType === 'images' || selectedSearchType === 'videos') {
      for (let f of allFiles) {
        if (selectedSearchType === 'images' && !f.is_image) continue;
        if (selectedSearchType === 'videos' && !f.is_video) continue;

        const fLabels = (f.labels || []).map(l => l.toLowerCase());
        if (labelQuery && !fLabels.includes(labelQuery)) continue;

        if (textQuery) {
          const nameMatch = f.name.toLowerCase().includes(textQuery);
          const labelMatch = fLabels.some(l => l.includes(textQuery));
          if (!nameMatch && !labelMatch) continue;
        }

        results.push({ type: 'file', data: f, time: f.mtime * 1000 });
      }
    }

    // Filter notes
    if (selectedSearchType === 'all' || selectedSearchType === 'notes') {
      for (let n of allNotes) {
        const nLabels = (n.labels || []).map(l => l.toLowerCase());
        if (labelQuery && !nLabels.includes(labelQuery)) continue;

        if (textQuery) {
          const titleMatch = (n.title || '').toLowerCase().includes(textQuery);
          const textMatch = (n.text || '').toLowerCase().includes(textQuery);
          const senderMatch = (n.sender || '').toLowerCase().includes(textQuery);
          const labelMatch = nLabels.some(l => l.includes(textQuery));
          if (!titleMatch && !textMatch && !senderMatch && !labelMatch) continue;
        }

        results.push({ type: 'note', data: n, time: n.id });
      }
    }

    // Sort: pinned files first, then newest
    results.sort((a, b) => {
      const aPin = (a.type === 'file' && a.data.is_pinned) ? 1 : 0;
      const bPin = (b.type === 'file' && b.data.is_pinned) ? 1 : 0;
      if (aPin !== bPin) return bPin - aPin;
      return b.time - a.time;
    });

    if (summary) {
      let desc = `${results.length} item(s) found`;
      if (selectedSearchType !== 'all') desc += ` in ${selectedSearchType}`;
      if (selectedSearchLabel) desc += ` with #${selectedSearchLabel}`;
      if (textQuery) desc += ` matching "${textQuery}"`;
      summary.innerText = desc;
    }

    if (results.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 36px 16px;">
          <div style="font-size: 2rem; margin-bottom: 8px;">🔍</div>
          <div>No matching items found</div>
          <div style="font-size: 0.78rem; margin-top: 4px;">Try different keywords, click on another label, or reset filters</div>
        </div>
      `;
      return;
    }

    container.innerHTML = results.map(item => {
      if (item.type === 'file') {
        const file = item.data;
        const iconOrThumb = file.is_image
          ? `<img src="/view/${encodeURIComponent(file.name)}" loading="lazy" style="width:40px; height:40px; object-fit:cover; border-radius:8px; border:1px solid var(--border);">`
          : `<div class="file-type-icon">${getFileIcon(file.name)}</div>`;

        return `
          <div class="file-card" onclick="openFileDetail('${escapeHtml(file.name)}')">
            <div class="file-details">
              ${iconOrThumb}
              <div class="file-meta">
                <div class="file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
                <div class="file-sub">${file.size_formatted} • ${file.date}</div>
                ${renderLabelBadges('file', file.name, file.labels)}
              </div>
            </div>
            <div class="file-actions" onclick="event.stopPropagation()">
              ${(file.is_image || file.is_video || file.is_audio) ? `
                <a href="/view/${encodeURIComponent(file.name)}" target="_blank" class="action-btn" title="Preview / Play">👁️</a>
              ` : ''}
              <a href="/download/${encodeURIComponent(file.name)}" class="action-btn" title="Download">⬇️</a>
              <button class="action-btn ${file.is_pinned ? 'is-pinned' : ''}" onclick="togglePin('${escapeHtml(file.name)}')" title="${file.is_pinned ? 'Unpin from top' : 'Pin to top of all tabs'}">📌</button>
              <button class="action-btn btn-delete" onclick="deleteFile('${escapeHtml(file.name)}')" title="Delete">🗑️</button>
            </div>
          </div>
        `;
      } else {
        const note = item.data;
        return `
          <div class="note-item" style="border: 1px solid var(--border); border-radius: 12px; padding: 12px; margin-bottom: 10px; background: var(--surface);">
            <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 6px;">
              <span style="background: rgba(16, 185, 129, 0.15); color: var(--success); font-size: 0.68rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;">NOTE</span>
              ${note.title ? `<strong style="font-size: 0.92rem; color: var(--primary);">📌 ${escapeHtml(note.title)}</strong>` : ''}
            </div>
            <div class="md-body" style="font-size: 0.85rem; max-height: 200px; overflow-y: auto; margin-bottom: 8px;">${renderMarkdown(note.text)}</div>
            ${renderLabelBadges('note', note.id, note.labels)}
            <div class="note-footer" style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 0.72rem; color: var(--text-muted);">From ${escapeHtml(note.sender)} • ${note.date}</span>
              <div style="display: flex; gap: 6px;">
                <button class="btn btn-secondary btn-sm" onclick="copyNoteById(this, ${note.id})">📋 Copy</button>
                <button class="btn btn-secondary btn-sm" style="color: var(--danger);" onclick="deleteNote(${note.id})" title="Delete Note">🗑️</button>
              </div>
            </div>
          </div>
        `;
      }
    }).join('');
  }

  // Live Activity Feed Collapsing State
  const expandedLiveNotes = new Set();

  function toggleLiveNoteExpand(id) {
    if (expandedLiveNotes.has(id)) {
      expandedLiveNotes.delete(id);
    } else {
      expandedLiveNotes.add(id);
    }
    const elem = document.getElementById(`liveNote_${id}`);
    const btn = document.getElementById(`liveNoteToggle_${id}`);
    if (elem) {
      if (expandedLiveNotes.has(id)) {
        elem.classList.remove('collapsed');
        elem.classList.add('expanded');
        if (btn) btn.innerText = '▲ Collapse';
      } else {
        elem.classList.remove('expanded');
        elem.classList.add('collapsed');
        if (btn) btn.innerText = '▼ Show more';
      }
    }
  }

  // Live Activity Feed
  function renderLiveActivity() {
    const feed = document.getElementById('liveActivityFeed');
    const statusText = document.getElementById('liveActivityStatus');
    if (!feed) return;

    const activities = [];
    for (let f of allFiles) {
      activities.push({
        type: 'file',
        time: f.mtime * 1000,
        date: f.date,
        data: f
      });
    }

    for (let n of allNotes) {
      activities.push({
        type: 'note',
        time: n.id,
        date: n.date,
        data: n
      });
    }

    activities.sort((a, b) => b.time - a.time);

    if (statusText) {
      statusText.innerText = `${allFiles.length} file(s), ${allNotes.length} note(s)`;
    }

    if (activities.length === 0) {
      feed.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 18px; font-size: 0.85rem;">
          No activity yet. Upload a file or paste text to see it appear here live!
        </div>
      `;
      return;
    }

    const maxItems = (currentLayoutMode === 'vertical') ? 35 : 15;
    const recent = activities.slice(0, maxItems);
    feed.innerHTML = recent.map(item => {
      if (item.type === 'file') {
        const file = item.data;
        const iconOrThumb = file.is_image
          ? `<img src="/view/${encodeURIComponent(file.name)}" loading="lazy" style="width:38px; height:38px; object-fit:cover; border-radius:8px; border:1px solid var(--border);">`
          : `<span style="font-size: 24px;">${getFileIcon(file.name)}</span>`;

        return `
          <div class="file-card" style="padding: 10px 12px;" onclick="openFileDetail('${escapeHtml(file.name)}')">
            <div class="file-details">
              <div style="min-width: 38px; display: flex; align-items: center; justify-content: center;">
                ${iconOrThumb}
              </div>
              <div class="file-meta">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="background: rgba(59, 130, 246, 0.15); color: var(--primary); font-size: 0.68rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;">FILE</span>
                  <div class="file-name" style="font-size: 0.88rem;" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
                </div>
                <div class="file-sub" style="font-size: 0.74rem;">${file.size_formatted} • ${file.date}</div>
                ${renderLabelBadges('file', file.name, file.labels)}
              </div>
            </div>
            <div class="file-actions" onclick="event.stopPropagation()">
              ${(file.is_image || file.is_video || file.is_audio) ? `
                <a href="/view/${encodeURIComponent(file.name)}" target="_blank" class="action-btn" style="width:34px; height:34px;" title="Preview">👁️</a>
              ` : ''}
              <a href="/download/${encodeURIComponent(file.name)}" class="action-btn" style="width:34px; height:34px;" title="Download">⬇️</a>
              <button class="action-btn ${file.is_pinned ? 'is-pinned' : ''}" style="width:34px; height:34px;" onclick="togglePin('${escapeHtml(file.name)}')" title="${file.is_pinned ? 'Unpin from top' : 'Pin to top of all tabs'}">📌</button>
              <button class="action-btn btn-delete" style="width:34px; height:34px;" onclick="deleteFile('${escapeHtml(file.name)}')" title="Delete">🗑️</button>
            </div>
          </div>
        `;
      } else {
        const note = item.data;
        const isExp = expandedLiveNotes.has(note.id);
        const rendered = renderMarkdown(note.text);
        const isLong = (note.text && (note.text.length > 90 || note.text.includes('\n')));
        return `
          <div class="file-card" style="padding: 10px 12px; background: var(--surface);">
            <div class="file-details" style="align-items: flex-start;">
              <div style="min-width: 38px; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                💬
              </div>
              <div class="file-meta live-note-content" style="flex: 1;">
                <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                  <span style="background: rgba(16, 185, 129, 0.15); color: var(--success); font-size: 0.68rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;">NOTE</span>
                  ${note.title ? `<strong style="font-size: 0.82rem; color: var(--primary);">📌 ${escapeHtml(note.title)}</strong> • ` : ''}
                  <span style="font-size: 0.72rem; color: var(--text-muted);">From ${escapeHtml(note.sender)} • ${note.date}</span>
                </div>
                <div class="live-note-body md-body ${isExp ? 'expanded' : 'collapsed'}" id="liveNote_${note.id}">${rendered}</div>
                ${isLong ? `<button id="liveNoteToggle_${note.id}" class="live-note-toggle-btn" onclick="toggleLiveNoteExpand(${note.id})">${isExp ? '▲ Collapse' : '▼ Show more'}</button>` : ''}
                ${renderLabelBadges('note', note.id, note.labels)}
              </div>
            </div>
            <div class="file-actions">
              <button class="action-btn" style="width:34px; height:34px;" onclick="copyNoteById(this, ${note.id})" title="Copy Text">📋</button>
              <button class="action-btn btn-delete" style="width:34px; height:34px;" onclick="deleteNote(${note.id})" title="Delete Note">🗑️</button>
            </div>
          </div>
        `;
      }
    }).join('');
  }

  // Pinned Section
  function renderPinnedSection() {
    const section = document.getElementById('pinnedSection');
    const list = document.getElementById('pinnedList');
    const badge = document.getElementById('pinnedBadge');
    if (!section || !list) return;

    const pinnedFiles = allFiles.filter(f => f.is_pinned);
    if (badge) badge.innerText = pinnedFiles.length;

    if (pinnedFiles.length === 0) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    list.innerHTML = pinnedFiles.map(file => {
      const iconOrThumb = file.is_image
        ? `<img src="/view/${encodeURIComponent(file.name)}" loading="lazy" style="width:38px; height:38px; object-fit:cover; border-radius:8px; border:1px solid var(--border);">`
        : `<span style="font-size: 24px;">${getFileIcon(file.name)}</span>`;

      return `
        <div class="file-card" style="padding: 10px 12px; border-color: rgba(59, 130, 246, 0.45); background: var(--surface);" onclick="openFileDetail('${escapeHtml(file.name)}')">
          <div class="file-details">
            <div style="min-width: 38px; display: flex; align-items: center; justify-content: center;">
              ${iconOrThumb}
            </div>
            <div class="file-meta">
              <div style="display: flex; align-items: center; gap: 6px;">
                <span style="background: rgba(59, 130, 246, 0.2); color: var(--primary); font-size: 0.68rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;">PINNED</span>
                <div class="file-name" style="font-size: 0.88rem;" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
              </div>
              <div class="file-sub" style="font-size: 0.74rem;">${file.size_formatted} • ${file.date}</div>
              ${renderLabelBadges('file', file.name, file.labels)}
            </div>
          </div>
          <div class="file-actions" onclick="event.stopPropagation()">
            ${(file.is_image || file.is_video || file.is_audio) ? `
              <a href="/view/${encodeURIComponent(file.name)}" target="_blank" class="action-btn" style="width:34px; height:34px;" title="Preview">👁️</a>
            ` : ''}
            <a href="/download/${encodeURIComponent(file.name)}" class="action-btn" style="width:34px; height:34px;" title="Download">⬇️</a>
            <button class="action-btn is-pinned" style="width:34px; height:34px;" onclick="togglePin('${escapeHtml(file.name)}')" title="Unpin from top">📌</button>
          </div>
        </div>
      `;
    }).join('');
  }

  function togglePin(filename) {
    const file = allFiles.find(f => f.name === filename);
    if (file) {
      file.is_pinned = !file.is_pinned;
      renderPinnedSection();
      renderFilesList(allFiles);
      renderLiveActivity();
    }

    fetch('/api/pin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showToast(data.is_pinned ? `📌 Pinned "${filename}" to top` : `📍 Unpinned "${filename}"`);
        fetchFilesList();
      } else {
        showToast('❌ ' + (data.error || 'Failed to update pin'));
        fetchFilesList();
      }
    })
    .catch(() => {
      fetchFilesList();
    });
  }

  // Files List Operations
  function fetchFilesList() {
    return fetch('/api/files')
      .then(res => res.json())
      .then(data => {
        const newFiles = data.files || [];
        if (!isInitialLoad && newFiles.length > lastKnownFileCount) {
          const added = newFiles.length - lastKnownFileCount;
          showToast(`📥 ${added} new file(s) received from mobile!`);
        }
        allFiles = newFiles;
        lastKnownFileCount = allFiles.length;
        if (currentDetailFile) {
          const updated = allFiles.find(f => f.name === currentDetailFile.name);
          if (updated) {
            currentDetailFile = updated;
            renderDetailTags(currentDetailFile);
          }
        }
        renderPinnedSection();
        renderFilesList(allFiles);
        const countSpan = document.getElementById('filesCountTab');
        if (countSpan) countSpan.innerText = allFiles.length > 0 ? `(${allFiles.length})` : '';
        renderLiveActivity();
        if (activeTab === 'search') {
          renderLabelFilterPills();
          runGlobalSearch();
        }
      })
      .catch(() => {});
  }

  function renderFilesList(files) {
    const container = document.getElementById('fileListContainer');
    if (!container) return;
    if (files.length === 0) {
      container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 32px;">No files uploaded yet</div>';
      return;
    }

    container.innerHTML = files.map(file => {
      const iconOrThumb = file.is_image
        ? `<img src="/view/${encodeURIComponent(file.name)}" loading="lazy" style="width:40px; height:40px; object-fit:cover; border-radius:8px; border:1px solid var(--border);">`
        : `<div class="file-type-icon">${getFileIcon(file.name)}</div>`;

      return `
        <div class="file-card" onclick="openFileDetail('${escapeHtml(file.name)}')">
          <div class="file-details">
            ${iconOrThumb}
            <div class="file-meta">
              <div class="file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
              <div class="file-sub">${file.size_formatted} • ${file.date}</div>
              ${renderLabelBadges('file', file.name, file.labels)}
            </div>
          </div>
          <div class="file-actions" onclick="event.stopPropagation()">
            ${(file.is_image || file.is_video || file.is_audio) ? `
              <a href="/view/${encodeURIComponent(file.name)}" target="_blank" class="action-btn" title="Preview / Play">👁️</a>
            ` : ''}
            <a href="/download/${encodeURIComponent(file.name)}" class="action-btn" title="Download">⬇️</a>
            <button class="action-btn ${file.is_pinned ? 'is-pinned' : ''}" onclick="togglePin('${escapeHtml(file.name)}')" title="${file.is_pinned ? 'Unpin from top' : 'Pin to top of all tabs'}">📌</button>
            <button class="action-btn btn-delete" onclick="deleteFile('${escapeHtml(file.name)}')" title="Delete">🗑️</button>
          </div>
        </div>
      `;
    }).join('');
  }

  function filterFilesList() {
    const q = document.getElementById('searchFilesInput').value.toLowerCase();
    const filtered = allFiles.filter(f => f.name.toLowerCase().includes(q));
    renderFilesList(filtered);
  }

  function deleteFile(filename) {
    if (!confirm(`Delete "${filename}"?`)) return;
    fetch('/api/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showToast('🗑️ File deleted');
        fetchFilesList();
      } else {
        showToast('❌ ' + (data.error || 'Failed to delete'));
      }
    });
  }

  // Notes & Clipboard Operations
  function fetchNotesList() {
    return fetch('/api/notes')
      .then(res => res.json())
      .then(data => {
        const newNotes = data.notes || [];
        if (!isInitialLoad && newNotes.length > 0 && newNotes[0].id !== lastKnownNoteId) {
          if (lastKnownNoteId !== 0) {
            showToast(`💬 New text from ${newNotes[0].sender}!`);
          }
        }
        allNotes = newNotes;
        if (allNotes.length > 0) lastKnownNoteId = allNotes[0].id;

        renderNotesList(allNotes);
        const countSpan = document.getElementById('notesCountTab');
        if (countSpan) countSpan.innerText = allNotes.length > 0 ? `(${allNotes.length})` : '';
        const mobBadge = document.getElementById('notesMobileCountBadge');
        if (mobBadge) mobBadge.innerText = allNotes.length;
        const pillBadge = document.getElementById('notesSavedCountPill');
        if (pillBadge) pillBadge.innerText = allNotes.length;
        renderLiveActivity();
        if (activeTab === 'search') {
          renderLabelFilterPills();
          runGlobalSearch();
        }
        if (activeTab === 'markdowndocs') {
          refreshMdDocsDropdown();
        }
      })
      .catch(() => {});
  }

  function renderNotesList(notes) {
    const container = document.getElementById('notesContainer');
    if (!container) return;
    if (notes.length === 0) {
      container.innerHTML = `
        <div class="notes-empty-state">
          <div class="notes-empty-icon">📝</div>
          <div class="notes-empty-title">No saved notes yet</div>
          <div class="notes-empty-desc">Items you copy or save will appear here for easy reference and sharing.</div>
        </div>`;
      return;
    }
    container.innerHTML = notes.map(n => {
      const isExp = expandedNotesSet.has(n.id);
      const isLongText = (n.text && (n.text.length > 200 || n.text.split('\n').length > 5));
      const isActive = (activeEditingNoteId === n.id);
      return `
        <div class="note-item ${isActive ? 'active-note' : ''}" id="noteCard_${n.id}" onclick="loadNoteToEditor(${n.id})">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 5px;">
            <div style="display: flex; align-items: center; gap: 5px; overflow: hidden;">
              <span style="background: rgba(16, 185, 129, 0.15); color: var(--success); font-size: 0.65rem; font-weight: 700; padding: 1px 5px; border-radius: 4px; flex-shrink: 0;">NOTE</span>
              <strong style="font-size: 0.9rem; color: var(--primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">📌 ${escapeHtml(n.title || 'Untitled Note')}</strong>
            </div>
            <span style="font-size: 0.70rem; color: var(--text-muted); flex-shrink: 0;">${n.date || ''}</span>
          </div>
          <div class="note-snippet-container md-body ${isExp ? 'expanded' : 'collapsed'}" id="noteSnippet_${n.id}">${renderMarkdown(n.text)}</div>
          ${isLongText ? `<button type="button" class="note-snippet-toggle-btn" id="noteSnippetToggle_${n.id}" onclick="event.stopPropagation(); toggleNoteSnippet(${n.id})">${isExp ? '▲ Collapse snippet' : '▼ Show full snippet'}</button>` : ''}
          ${renderLabelBadges('note', n.id, n.labels)}
          <div class="note-footer" onclick="event.stopPropagation();">
            <span style="font-size: 0.70rem; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">From ${escapeHtml(n.sender)}</span>
            <div style="display: flex; gap: 4px; flex-shrink: 0;">
              <button class="btn btn-secondary btn-sm" style="padding: 2px 7px; font-size: 0.72rem;" onclick="event.stopPropagation(); copyNoteById(this, ${n.id})">📋 Copy</button>
              <button class="btn btn-secondary btn-sm" style="padding: 2px 7px; font-size: 0.72rem; color: var(--danger);" onclick="event.stopPropagation(); deleteNote(${n.id})" title="Delete Note">🗑️</button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  function sendNote() {
    const titleInput = document.getElementById('noteTitleInput');
    const labelsInput = document.getElementById('noteLabelsInput');
    const input = document.getElementById('noteInput');
    const text = input.value.trim();
    const title = titleInput ? titleInput.value.trim() : '';
    const rawLabels = labelsInput ? labelsInput.value.split(',') : [];
    const labels = rawLabels.map(s => s.trim().replace(/^#/, '').replace(/\s+/g, '-')).filter(Boolean);

    for (let lbl of labels) {
      if (lbl.length > 50) {
        showToast(`⚠️ Tag "${lbl}" is too long (max 50 chars)`);
        return;
      }
      recordRecentTag(lbl);
    }

    if (!text) {
      showToast('⚠️ Note text is empty');
      return;
    }

    fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, title, labels })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        clearNoteInputs();
        showToast('💬 Note saved and sent to computer!');
        fetchNotesList();
        if (window.innerWidth < 1024 || currentLayoutMode === 'vertical') {
          setNotesMobileSegment('saved');
        }
      } else {
        showToast('❌ ' + (data.error || 'Failed to send note'));
      }
    })
    .catch(() => showToast('❌ Network error'));
  }

  function deleteNote(id) {
    if (!confirm('Delete this note?')) return;
    fetch('/api/note/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showToast('🗑️ Note deleted');
        fetchNotesList();
      } else {
        showToast('❌ ' + (data.error || 'Failed to delete note'));
      }
    })
    .catch(() => showToast('❌ Network error'));
  }

  function clearAllNotes() {
    if (!confirm('Clear all notes?')) return;
    fetch('/api/notes/clear', { method: 'POST' })
      .then(() => fetchNotesList());
  }

  // Helpers
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  function getFileIcon(name) {
    const ext = name.split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'svg'].includes(ext)) return '🖼️';
    if (['mp4', 'mov', 'avi', 'mkv', 'webm'].includes(ext)) return '🎬';
    if (['mp3', 'wav', 'flac', 'm4a', 'aac'].includes(ext)) return '🎵';
    if (['pdf'].includes(ext)) return '📕';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '📦';
    if (['doc', 'docx', 'txt', 'md'].includes(ext)) return '📄';
    return '📁';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    })[m]);
  }

  // LAN Configuration injected by server
  const PRIMARY_LAN_IP = "__PRIMARY_IP__";
  const SERVER_PORT = "__PORT__";
  const ALL_LAN_IPS = __ALL_IPS_JSON__;
  let activeLanIp = PRIMARY_LAN_IP;

  function initIpSelector() {
    const container = document.getElementById('ipSelectorContainer');
    const select = document.getElementById('ipSelect');
    if (container && select && ALL_LAN_IPS && ALL_LAN_IPS.length > 1) {
      container.style.display = 'block';
      select.innerHTML = ALL_LAN_IPS.map(ip => `
        <option value="${ip}" ${ip === PRIMARY_LAN_IP ? 'selected' : ''}>${ip} ${ip === PRIMARY_LAN_IP ? '(Primary LAN)' : ''}</option>
      `).join('');
    }
  }

  function onIpSelected(ip) {
    activeLanIp = ip;
    updateModalUrlAndQR();
    const badge = document.getElementById('currentIpText');
    if (badge) badge.innerText = `${activeLanIp}:${SERVER_PORT}`;
  }

  function getLanUrl() {
    // If the page was opened on another device via a real LAN hostname or IP (not localhost/127.0.0.1)
    const host = window.location.hostname;
    let targetIp = activeLanIp;
    if (host && host !== 'localhost' && host !== '127.0.0.1' && host !== '0.0.0.0') {
      targetIp = host;
    }
    const port = window.location.port || SERVER_PORT;
    return `http://${targetIp}:${port}`;
  }

  function openQRModal() {
    const modal = document.getElementById('qrModal');
    updateModalUrlAndQR();
    modal.classList.add('active');
  }

  function updateModalUrlAndQR() {
    const url = getLanUrl();
    const modalUrl = document.getElementById('modalUrl');
    if (modalUrl) modalUrl.innerText = url;
    generateQRCode(url, document.getElementById('qrCodeCanvas'));
  }

  function copyModalUrl(btn) {
    const url = document.getElementById('modalUrl').innerText;
    navigator.clipboard.writeText(url).then(() => {
      const orig = btn.innerText;
      btn.innerText = '✓ Copied';
      setTimeout(() => btn.innerText = orig, 1500);
    });
  }

  function closeQRModal(e) {
    if (!e || e.target.id === 'qrModal' || e.type === 'click') {
      document.getElementById('qrModal').classList.remove('active');
    }
  }

  /* Compact pure-JS QR code renderer using quick URL matrix */
  function generateQRCode(text, canvas) {
    const qrImg = new Image();
    const ctx = canvas.getContext('2d');
    canvas.width = 200;
    canvas.height = 200;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, 200, 200);

    qrImg.crossOrigin = "Anonymous";
    qrImg.onload = () => {
      ctx.drawImage(qrImg, 0, 0, 200, 200);
    };
    qrImg.onerror = () => {
      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 12px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Open in phone browser:', 100, 70);
      ctx.fillStyle = '#2563eb';
      ctx.font = 'bold 13px monospace';
      ctx.fillText(text, 100, 110);
    };
    qrImg.src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(text);
  }

  // =========================================================================
  // TAB 5: CONVERTER SUITE (Environment Variables Generator)
  // =========================================================================

  const SAMPLE_ENV_YAML = `foo-bar:
  baz:
    - value1
    - value2
  enabled: true
abcDef: value3`;

  // Universal Parsers & Formatters
  function flattenObjToProperties(obj, prefix = '') {
    const list = [];
    if (obj === null || obj === undefined) return list;

    if (Array.isArray(obj)) {
      obj.forEach((val, idx) => {
        const fullKey = `${prefix}[${idx}]`;
        if (typeof val === 'object' && val !== null) {
          list.push(...flattenObjToProperties(val, fullKey));
        } else {
          list.push({ key: fullKey, value: val });
        }
      });
    } else if (typeof obj === 'object') {
      for (const [k, v] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${k}` : k;
        if (typeof v === 'object' && v !== null) {
          list.push(...flattenObjToProperties(v, fullKey));
        } else {
          list.push({ key: fullKey, value: v });
        }
      }
    } else {
      list.push({ key: prefix, value: obj });
    }
    return list;
  }

  function unflattenPropertiesToObj(propsList) {
    const root = {};
    for (const item of propsList) {
      if (!item || !item.key) continue;
      const regex = /([^.[\]]+)|\[(\d+)\]/g;
      const parts = [];
      let match;
      while ((match = regex.exec(item.key)) !== null) {
        if (match[1] !== undefined) parts.push({ type: 'key', val: match[1] });
        else if (match[2] !== undefined) parts.push({ type: 'idx', val: parseInt(match[2], 10) });
      }

      let curr = root;
      for (let i = 0; i < parts.length - 1; i++) {
        const p = parts[i];
        const nextP = parts[i + 1];

        if (p.type === 'key') {
          if (!curr[p.val] || typeof curr[p.val] !== 'object') {
            curr[p.val] = (nextP.type === 'idx') ? [] : {};
          }
          curr = curr[p.val];
        } else {
          if (!curr[p.val] || typeof curr[p.val] !== 'object') {
            curr[p.val] = (nextP.type === 'idx') ? [] : {};
          }
          curr = curr[p.val];
        }
      }

      const lastP = parts[parts.length - 1];
      if (lastP) {
        curr[lastP.val] = item.value;
      }
    }
    return root;
  }

  function objToYaml(obj, indent = 0) {
    const sp = ' '.repeat(indent);
    if (obj === null || obj === undefined) return 'null';
    if (typeof obj !== 'object') {
      const s = String(obj);
      if (typeof obj === 'string') {
        if (s.startsWith('${') && s.endsWith('}')) return s;
        if (/[:#{}[\]]/.test(s) || s === '' || s === 'true' || s === 'false' || !isNaN(Number(s))) {
          return `"${s.replace(/"/g, '\\"')}"`;
        }
      }
      return s;
    }

    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]';
      return obj.map(item => {
        if (typeof item === 'object' && item !== null) {
          const sub = objToYaml(item, indent + 2).trim();
          return `${sp}- ${sub}`;
        }
        return `${sp}- ${objToYaml(item, 0)}`;
      }).join('\n');
    }

    const lines = [];
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'object' && v !== null) {
        if (Array.isArray(v)) {
          if (v.length === 0) {
            lines.push(`${sp}${k}: []`);
          } else {
            lines.push(`${sp}${k}:\n${objToYaml(v, indent + 2)}`);
          }
        } else if (Object.keys(v).length === 0) {
          lines.push(`${sp}${k}: {}`);
        } else {
          lines.push(`${sp}${k}:\n${objToYaml(v, indent + 2)}`);
        }
      } else {
        lines.push(`${sp}${k}: ${objToYaml(v, 0)}`);
      }
    }
    return lines.join('\n');
  }

  function objToHocon(obj, indent = 0) {
    const sp = ' '.repeat(indent);
    if (obj === null || obj === undefined) return 'null';
    if (typeof obj !== 'object') {
      const s = String(obj);
      if (typeof obj === 'string') {
        if (/[\s#{}[\]:=]/.test(s) || s === '') return `"${s.replace(/"/g, '\\"')}"`;
        return s;
      }
      return s;
    }
    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]';
      return '[\n' + obj.map(it => `${sp}  ${objToHocon(it, indent + 2)}`).join(',\n') + `\n${sp}]`;
    }

    const lines = [];
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
        lines.push(`${sp}${k} {\n${objToHocon(v, indent + 2)}\n${sp}}`);
      } else if (Array.isArray(v)) {
        lines.push(`${sp}${k} = ${objToHocon(v, indent)}`);
      } else {
        let valStr = String(v);
        if (typeof v === 'string') {
          if (/[\s#{}[\]:=]/.test(valStr) || valStr === '') valStr = `"${valStr.replace(/"/g, '\\"')}"`;
        }
        lines.push(`${sp}${k} = ${valStr}`);
      }
    }
    return lines.join('\n');
  }

  function parseYamlScalar(s) {
    if (!s) return '';
    if (s === 'true') return true;
    if (s === 'false') return false;
    if (s === 'null' || s === '~') return null;
    if (/^["'].*["']$/.test(s)) return s.slice(1, -1);
    if (!isNaN(Number(s)) && !s.includes(':')) return Number(s);
    return s;
  }

  function parseYamlLines(text) {
    const lines = text.split('\n');
    const root = {};
    const stack = [{ indent: -1, container: root, key: null }];

    for (let rawLine of lines) {
      const commentIdx = rawLine.indexOf('#');
      let line = commentIdx >= 0 ? rawLine.slice(0, commentIdx) : rawLine;
      if (!line.trim()) continue;

      const indent = line.search(/\S/);
      const trimmed = line.trim();

      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }
      const parent = stack[stack.length - 1].container;

      if (trimmed.startsWith('-')) {
        const itemContent = trimmed.slice(1).trim();
        let targetArr;
        if (Array.isArray(parent)) {
          targetArr = parent;
        } else {
          const lastKey = stack[stack.length - 1].key;
          if (lastKey && Array.isArray(parent[lastKey])) {
            targetArr = parent[lastKey];
          } else {
            targetArr = [];
            if (lastKey) parent[lastKey] = targetArr;
          }
        }

        if (itemContent === '') {
          const newObj = {};
          targetArr.push(newObj);
          stack.push({ indent, container: newObj, key: null });
        } else if (itemContent.includes(':')) {
          const colonPos = itemContent.indexOf(':');
          const k = itemContent.slice(0, colonPos).trim();
          const v = parseYamlScalar(itemContent.slice(colonPos + 1).trim());
          const newObj = { [k]: v };
          targetArr.push(newObj);
          stack.push({ indent, container: newObj, key: k });
        } else {
          targetArr.push(parseYamlScalar(itemContent));
        }
        continue;
      }

      const colonIdx = trimmed.indexOf(':');
      if (colonIdx > 0) {
        const k = trimmed.slice(0, colonIdx).trim().replace(/^["']|["']$/g, '');
        const valStr = trimmed.slice(colonIdx + 1).trim();

        if (valStr === '' || valStr === '[]' || valStr === '{}') {
          const newObj = (valStr === '[]') ? [] : {};
          if (Array.isArray(parent)) {
            parent.push({ [k]: newObj });
          } else {
            parent[k] = newObj;
          }
          stack.push({ indent, container: newObj, key: k });
        } else {
          const parsedVal = parseYamlScalar(valStr);
          if (Array.isArray(parent)) {
            parent.push({ [k]: parsedVal });
          } else {
            parent[k] = parsedVal;
          }
        }
      }
    }
    return root;
  }

  function parsePropertiesText(text) {
    const list = [];
    const lines = text.split('\n');
    for (let rawLine of lines) {
      let line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('!')) continue;
      let sepIdx = line.indexOf('=');
      if (sepIdx < 0) sepIdx = line.indexOf(':');
      if (sepIdx > 0) {
        const k = line.slice(0, sepIdx).trim();
        const v = parseYamlScalar(line.slice(sepIdx + 1).trim());
        list.push({ key: k, value: v });
      }
    }
    return list;
  }

  // HOCON Tokenizer & Parser
  function tokenizeHocon(src) {
    const tokens = [];
    let i = 0;
    const len = src.length;

    while (i < len) {
      const ch = src[i];

      if (ch === ' ' || ch === '\t' || ch === '\r') {
        i++;
        continue;
      }
      if (ch === '\n') {
        tokens.push({ type: 'newline', val: '\n' });
        i++;
        continue;
      }

      if (ch === '#' || (ch === '/' && src[i + 1] === '/')) {
        while (i < len && src[i] !== '\n') i++;
        continue;
      }
      if (ch === '/' && src[i + 1] === '*') {
        i += 2;
        while (i < len && !(src[i] === '*' && src[i + 1] === '/')) i++;
        if (i < len) i += 2;
        continue;
      }

      if (ch === '{' || ch === '}' || ch === '[' || ch === ']' || ch === '=' || ch === ':' || ch === ',') {
        tokens.push({ type: ch, val: ch });
        i++;
        continue;
      }

      if (ch === '"' || ch === "'") {
        const quote = ch;
        let str = '';
        i++;
        while (i < len && src[i] !== quote) {
          if (src[i] === '\\' && i + 1 < len) {
            str += src[i + 1];
            i += 2;
          } else {
            str += src[i];
            i++;
          }
        }
        if (i < len) i++;
        tokens.push({ type: 'string', val: str });
        continue;
      }

      let val = '';
      while (i < len && !/[\s{}[\]=:,#"'/]/.test(src[i])) {
        val += src[i];
        i++;
      }
      if (val) {
        tokens.push({ type: 'ident', val: val });
      } else {
        i++;
      }
    }
    return tokens;
  }

  function parseHoconTokens(tokens) {
    let pos = 0;

    function skipNewlines() {
      while (pos < tokens.length && (tokens[pos].type === 'newline' || tokens[pos].type === ',')) {
        pos++;
      }
    }

    function setDeep(target, pathParts, value) {
      let curr = target;
      for (let k = 0; k < pathParts.length - 1; k++) {
        const p = pathParts[k];
        if (!curr[p] || typeof curr[p] !== 'object' || Array.isArray(curr[p])) {
          curr[p] = {};
        }
        curr = curr[p];
      }
      const last = pathParts[pathParts.length - 1];
      if (typeof value === 'object' && value !== null && !Array.isArray(value) && typeof curr[last] === 'object' && curr[last] !== null && !Array.isArray(curr[last])) {
        Object.assign(curr[last], value);
      } else {
        curr[last] = value;
      }
    }

    function parseObject() {
      const obj = {};
      while (pos < tokens.length) {
        skipNewlines();
        if (pos >= tokens.length || tokens[pos].type === '}') break;

        let key = tokens[pos].val;
        pos++;

        skipNewlines();
        if (pos >= tokens.length) break;

        if (tokens[pos].type === '=' || tokens[pos].type === ':') {
          pos++;
          skipNewlines();
        }

        if (pos < tokens.length && tokens[pos].type === '{') {
          pos++;
          const childObj = parseObject();
          if (pos < tokens.length && tokens[pos].type === '}') pos++;
          const parts = key.split('.');
          setDeep(obj, parts, childObj);
        } else if (pos < tokens.length && tokens[pos].type === '[') {
          pos++;
          const arr = parseArray();
          if (pos < tokens.length && tokens[pos].type === ']') pos++;
          const parts = key.split('.');
          setDeep(obj, parts, arr);
        } else if (pos < tokens.length && tokens[pos].type !== '}') {
          let rawVal = tokens[pos].val;
          pos++;
          let parsedVal = rawVal;
          if (rawVal === 'true') parsedVal = true;
          else if (rawVal === 'false') parsedVal = false;
          else if (rawVal === 'null') parsedVal = null;
          else if (!isNaN(Number(rawVal)) && rawVal.trim() !== '') parsedVal = Number(rawVal);
          const parts = key.split('.');
          setDeep(obj, parts, parsedVal);
        }
      }
      return obj;
    }

    function parseArray() {
      const arr = [];
      while (pos < tokens.length) {
        skipNewlines();
        if (pos >= tokens.length || tokens[pos].type === ']') break;
        if (tokens[pos].type === '{') {
          pos++;
          arr.push(parseObject());
          if (pos < tokens.length && tokens[pos].type === '}') pos++;
        } else if (tokens[pos].type === '[') {
          pos++;
          arr.push(parseArray());
          if (pos < tokens.length && tokens[pos].type === ']') pos++;
        } else {
          let v = tokens[pos].val;
          pos++;
          if (v === 'true') v = true;
          else if (v === 'false') v = false;
          else if (!isNaN(Number(v)) && v.trim() !== '') v = Number(v);
          arr.push(v);
        }
      }
      return arr;
    }

    return parseObject();
  }

  function parseHoconText(hoconText) {
    const tokens = tokenizeHocon(hoconText);
    return parseHoconTokens(tokens);
  }

  // Spring Boot Relaxed Environment Variables Converter (like env.simplestep.ca)
  function propertyKeyToSpringEnv(key) {
    let k = key.replace(/\[(\d+)\]/g, '._$1_');
    const parts = k.split('.');
    const transformed = parts.map(p => {
      if (/^_\d+_$/.test(p)) return p;
      return p.replace(/-/g, '').toUpperCase();
    });
    let envKey = transformed.join('_');
    envKey = envKey.replace(/_+/g, '_');
    if (/_\d+$/.test(envKey)) envKey += '_';
    return envKey;
  }

  function springEnvVarsToProperties(text) {
    const list = [];
    const regex = /([A-Za-z0-9_]+)\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s\n]+))/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const rawKey = match[1];
      const val = match[2] !== undefined ? match[2] : (match[3] !== undefined ? match[3] : match[4]);

      // Convert FOOBAR_BAZ_0_ -> foo-bar.baz[0]
      let parts = rawKey.split('_').filter(Boolean);
      let propParts = [];
      for (let i = 0; i < parts.length; i++) {
        const seg = parts[i];
        if (/^\d+$/.test(seg)) {
          if (propParts.length > 0) {
            propParts[propParts.length - 1] += `[${seg}]`;
          } else {
            propParts.push(`[${seg}]`);
          }
        } else {
          propParts.push(seg.toLowerCase());
        }
      }
      list.push({ key: propParts.join('.'), value: parseYamlScalar(val) });
    }
    return list;
  }

  // TAB 5 Controllers
  function initEnvVarTab() {
    const input = document.getElementById('envInputText');
    if (input && !input.value.trim()) {
      input.value = SAMPLE_ENV_YAML;
      runEnvVarConversion();
    }
  }

  function loadEnvVarSample() {
    const input = document.getElementById('envInputText');
    const inFmt = document.getElementById('envInputFormat');
    if (!input) return;
    inFmt.value = 'yaml';
    input.value = SAMPLE_ENV_YAML;
    runEnvVarConversion();
    showToast('📄 Loaded sample YAML from env.simplestep.ca');
  }

  function clearEnvVarInputs() {
    const input = document.getElementById('envInputText');
    const output = document.getElementById('envOutputText');
    if (input) input.value = '';
    if (output) output.value = '';
    const inStats = document.getElementById('envInputStats');
    const outStats = document.getElementById('envOutputStats');
    if (inStats) inStats.innerText = '0 lines';
    if (outStats) outStats.innerText = '0 variables';
  }

  function swapEnvVarFormats() {
    const inFmt = document.getElementById('envInputFormat');
    const outFmt = document.getElementById('envOutputFormat');
    const inText = document.getElementById('envInputText');
    const outText = document.getElementById('envOutputText');
    if (!inFmt || !outFmt || !inText || !outText) return;

    const oldInFmt = inFmt.value;
    const oldOutFmt = outFmt.value;
    const oldOutText = outText.value;

    const validInFormats = ['yaml', 'properties', 'env_terminal', 'env_multiline', 'docker', 'k8s', 'hocon'];
    const validOutFormats = ['env_terminal', 'env_multiline', 'shell_export', 'docker', 'k8s', 'yaml', 'properties'];

    if (validInFormats.includes(oldOutFmt)) {
      inFmt.value = oldOutFmt;
    }
    if (validOutFormats.includes(oldInFmt)) {
      outFmt.value = oldInFmt;
    }
    if (oldOutText.trim()) {
      inText.value = oldOutText;
    }
    runEnvVarConversion();
    showToast('⇄ Formats swapped');
  }

  function pasteToEnvInput() {
    navigator.clipboard.readText().then(clipText => {
      const input = document.getElementById('envInputText');
      if (input && clipText) {
        input.value = clipText;
        runEnvVarConversion();
        showToast('📋 Pasted from clipboard');
      }
    }).catch(() => {
      showToast('⚠️ Please paste manually with Ctrl+V');
    });
  }

  function copyEnvOutput(btn) {
    const output = document.getElementById('envOutputText');
    if (!output || !output.value) {
      showToast('⚠️ Output is empty');
      return;
    }
    navigator.clipboard.writeText(output.value).then(() => {
      if (btn) {
        const orig = btn.innerText;
        btn.innerText = '✅ Copied!';
        setTimeout(() => btn.innerText = orig, 1800);
      }
      showToast('📋 Copied converted variables to clipboard');
    }).catch(() => {
      output.select();
      document.execCommand('copy');
      showToast('📋 Copied to clipboard');
    });
  }

  function saveEnvOutputToNote() {
    const output = document.getElementById('envOutputText');
    const outFmt = document.getElementById('envOutputFormat').value;
    if (!output || !output.value.trim()) {
      showToast('⚠️ Output is empty');
      return;
    }
    const noteInput = document.getElementById('noteInput');
    const noteTitle = document.getElementById('noteTitleInput');
    const noteLabels = document.getElementById('noteLabelsInput');
    if (noteInput) {
      let lang = (outFmt === 'yaml' || outFmt === 'docker' || outFmt === 'k8s') ? 'yaml' : (outFmt === 'properties' ? 'properties' : 'sh');
      noteInput.value = `\`\`\`${lang}\n${output.value}\n\`\`\``;
    }
    if (noteTitle) noteTitle.value = `Env Vars (${outFmt})`;
    if (noteLabels) noteLabels.value = 'env,spring-boot,config';
    switchTab('notes');
    showToast('📝 Sent output to Note Editor');
  }

  function runEnvVarConversion() {
    const inFmt = document.getElementById('envInputFormat').value;
    const outFmt = document.getElementById('envOutputFormat').value;
    const inText = document.getElementById('envInputText').value;
    const outElem = document.getElementById('envOutputText');
    const inStats = document.getElementById('envInputStats');
    const outStats = document.getElementById('envOutputStats');

    if (!inText.trim()) {
      if (outElem) outElem.value = '';
      if (inStats) inStats.innerText = '0 lines';
      if (outStats) outStats.innerText = '0 variables';
      return;
    }

    const linesCount = inText.split('\n').length;
    if (inStats) inStats.innerText = `${linesCount} line(s)`;

    let props = [];
    try {
      if (inFmt === 'yaml') {
        const obj = parseYamlLines(inText);
        props = flattenObjToProperties(obj);
      } else if (inFmt === 'properties') {
        props = parsePropertiesText(inText);
      } else if (inFmt === 'env_terminal' || inFmt === 'env_multiline' || inFmt === 'docker') {
        props = springEnvVarsToProperties(inText);
      } else if (inFmt === 'hocon') {
        const obj = parseHoconText(inText);
        props = flattenObjToProperties(obj);
      } else if (inFmt === 'k8s') {
        const obj = parseYamlLines(inText);
        const data = obj.data || obj;
        props = flattenObjToProperties(data);
      }
    } catch (err) {
      if (outElem) outElem.value = `Error parsing input: ${err.message}`;
      return;
    }

    if (props.length === 0) {
      if (outElem) outElem.value = '';
      if (outStats) outStats.innerText = '0 variables';
      return;
    }

    if (outStats) outStats.innerText = `${props.length} variable(s)`;

    // Convert props to Target Output Format
    let outputText = '';
    if (outFmt === 'env_terminal') {
      // Exactly matching the screenshot single-line space separated format
      const items = props.map(p => `${propertyKeyToSpringEnv(p.key)}=${p.value}`);
      outputText = items.join(' ');
    } else if (outFmt === 'env_multiline') {
      const items = props.map(p => `${propertyKeyToSpringEnv(p.key)}=${p.value}`);
      outputText = items.join('\n');
    } else if (outFmt === 'shell_export') {
      const items = props.map(p => `export ${propertyKeyToSpringEnv(p.key)}="${String(p.value).replace(/"/g, '\\"')}"`);
      outputText = items.join('\n');
    } else if (outFmt === 'docker') {
      outputText = 'environment:\n' + props.map(p => `  - ${propertyKeyToSpringEnv(p.key)}=${p.value}`).join('\n');
    } else if (outFmt === 'k8s') {
      outputText = `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
` + props.map(p => `  ${propertyKeyToSpringEnv(p.key)}: "${String(p.value).replace(/"/g, '\\"')}"`).join('\n');
    } else if (outFmt === 'yaml') {
      const obj = unflattenPropertiesToObj(props);
      outputText = objToYaml(obj);
    } else if (outFmt === 'properties') {
      outputText = props.map(p => `${p.key}=${p.value}`).join('\n');
    }

    if (outElem) outElem.value = outputText;
  }

  // =========================================================================
  // DISPLAY, THEME & LAYOUT SETTINGS
  // =========================================================================

  const THEMES = [
    { id: 'default', name: 'Dark Slate', desc: 'Default Dark', bg: '#0f172a', primary: '#3b82f6' },
    { id: 'midnight', name: 'Midnight OLED', desc: 'Pure Deep Black', bg: '#050508', primary: '#38bdf8' },
    { id: 'emerald', name: 'Forest Emerald', desc: 'Deep Dark Green', bg: '#04140e', primary: '#10b981' },
    { id: 'cyberpunk', name: 'Cyber Neon', desc: 'Violet & Fuchsia', bg: '#0c071e', primary: '#a855f7' },
    { id: 'sunset', name: 'Warm Amber', desc: 'Espresso & Orange', bg: '#17120e', primary: '#f59e0b' },
    { id: 'nordic', name: 'Nordic Frost', desc: 'Cool Slate Grey', bg: '#1f232b', primary: '#60a5fa' },
    { id: 'light', name: 'Clean Light', desc: 'Crisp Daylight', bg: '#f1f5f9', primary: '#2563eb' }
  ];

  let currentLayoutMode = 'grid';
  let currentTheme = 'default';

  function initSettings() {
    // 1. Layout Mode
    const savedLayout = localStorage.getItem('lan_layout_mode') || 'grid';
    setLayoutMode(savedLayout, false);

    // 2. Theme
    const savedTheme = localStorage.getItem('lan_theme') || 'default';
    setTheme(savedTheme, false);

    // 3. Side Spacing
    const savedSideSpace = parseInt(localStorage.getItem('lan_side_space'), 10) || 0;
    onSideSpaceInput(savedSideSpace, false);
  }

  function setLayoutMode(mode, showFeedback = true) {
    currentLayoutMode = (mode === 'vertical') ? 'vertical' : 'grid';
    document.documentElement.setAttribute('data-layout', currentLayoutMode);
    localStorage.setItem('lan_layout_mode', currentLayoutMode);

    // Update Header Button
    const icon = document.getElementById('layoutToggleIcon');
    const text = document.getElementById('layoutToggleText');
    const btn = document.getElementById('layoutToggleBtn');
    if (icon) icon.innerText = currentLayoutMode === 'vertical' ? '☰' : '⊞';
    if (text) text.innerText = currentLayoutMode === 'vertical' ? 'Vertical' : 'Grid';
    if (btn) {
      btn.title = currentLayoutMode === 'vertical'
        ? 'Current: Vertical Layout (Click to switch to Grid)'
        : 'Current: Grid Layout (Click to switch to Vertical)';
    }

    // Update Settings Modal options if open
    const gridBtn = document.getElementById('settingLayoutGridBtn');
    const vertBtn = document.getElementById('settingLayoutVertBtn');
    if (gridBtn) gridBtn.classList.toggle('active', currentLayoutMode === 'grid');
    if (vertBtn) vertBtn.classList.toggle('active', currentLayoutMode === 'vertical');

    // Refresh activity feed with updated layout item count & sizing
    renderLiveActivity();

    if (showFeedback) {
      showToast(currentLayoutMode === 'vertical' ? '☰ Switched to Vertical Layout' : '⊞ Switched to Grid Layout');
    }
  }

  function toggleLayoutMode() {
    const nextMode = currentLayoutMode === 'grid' ? 'vertical' : 'grid';
    setLayoutMode(nextMode, true);
  }

  function setTheme(themeId, showFeedback = true) {
    if (!THEMES.some(t => t.id === themeId)) themeId = 'default';
    currentTheme = themeId;
    if (themeId === 'default') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', themeId);
    }
    localStorage.setItem('lan_theme', themeId);

    // Update active state on theme cards
    document.querySelectorAll('.theme-card').forEach(card => {
      card.classList.toggle('active', card.dataset.themeId === themeId);
    });

    if (showFeedback) {
      const found = THEMES.find(t => t.id === themeId);
      showToast(`🎨 Theme set to ${found ? found.name : themeId}`);
    }
  }

  function renderThemeGrid() {
    const container = document.getElementById('themeGrid');
    if (!container) return;
    container.innerHTML = THEMES.map(t => {
      const isActive = t.id === currentTheme;
      return `
        <div class="theme-card ${isActive ? 'active' : ''}" data-theme-id="${t.id}" onclick="setTheme('${t.id}')">
          <div class="theme-swatch-box" style="background: ${t.bg};">
            <span class="theme-swatch-circle" style="background: ${t.primary};"></span>
          </div>
          <div class="theme-name">${t.name}</div>
          <div class="theme-desc">${t.desc}</div>
        </div>
      `;
    }).join('');
  }

  function onSideSpaceInput(val, showFeedback = false) {
    const num = Math.max(0, parseInt(val, 10) || 0);
    document.documentElement.style.setProperty('--side-space', num + 'px');
    const badge = document.getElementById('sideSpaceValueText');
    if (badge) {
      badge.innerText = num > 0 ? `+${num}px left/right` : '0px (Full width)';
    }
    const slider = document.getElementById('sideSpaceSlider');
    if (slider && parseInt(slider.value, 10) !== num) {
      slider.value = num;
    }
    localStorage.setItem('lan_side_space', num);
  }

  function resetSideSpace() {
    onSideSpaceInput(0);
    showToast('↔️ Side space reset to default');
  }

  function openSettingsModal() {
    renderThemeGrid();
    const gridBtn = document.getElementById('settingLayoutGridBtn');
    const vertBtn = document.getElementById('settingLayoutVertBtn');
    if (gridBtn) gridBtn.classList.toggle('active', currentLayoutMode === 'grid');
    if (vertBtn) vertBtn.classList.toggle('active', currentLayoutMode === 'vertical');

    const slider = document.getElementById('sideSpaceSlider');
    const savedSideSpace = parseInt(localStorage.getItem('lan_side_space'), 10) || 0;
    if (slider) slider.value = savedSideSpace;
    const badge = document.getElementById('sideSpaceValueText');
    if (badge) badge.innerText = savedSideSpace > 0 ? `+${savedSideSpace}px left/right` : '0px (Full width)';

    const modal = document.getElementById('settingsModal');
    if (modal) modal.classList.add('active');
  }

  function closeSettingsModal(e) {
    if (!e || e.target.id === 'settingsModal' || e.type === 'click') {
      const modal = document.getElementById('settingsModal');
      if (modal) modal.classList.remove('active');
    }
  }

  // Global escape key handler to close active modals
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeSettingsModal();
      closeQRModal();
      closeTagModal();
      closeHoverPreview();
    }
  });

  /* =========================================================================
     MARKDOWN DOCS TAB (GFM Tables, Mermaid Diagrams, ASCII Blueprints)
     ========================================================================= */
  let currentMdDocText = '';
  let currentMdDocNoteId = null;

  async function triggerMermaidRender(containerEl) {
    if (!window.mermaid) return;
    try {
      mermaid.initialize({
        startOnLoad: false,
        theme: document.documentElement.getAttribute('data-theme') === 'light' ? 'default' : 'dark',
        securityLevel: 'loose'
      });
    } catch (e) {}

    const targets = (containerEl || document).querySelectorAll('.mermaid-render-target');
    for (let i = 0; i < targets.length; i++) {
      const el = targets[i];
      if (el.getAttribute('data-rendered') === 'true') continue;
      const b64 = el.getAttribute('data-mermaid-code');
      if (!b64) continue;
      try {
        const code = decodeURIComponent(escape(atob(b64)));
        const id = 'mermaid_' + Math.random().toString(36).substring(2, 9) + '_' + i;
        const result = await mermaid.render(id, code);
        el.innerHTML = result.svg;
        el.setAttribute('data-rendered', 'true');
      } catch (err) {
        console.warn('Mermaid rendering failed', err);
        const raw = decodeURIComponent(escape(atob(b64)));
        el.innerHTML = `<div style="color:var(--text-muted);font-size:0.8rem;text-align:left;padding:8px;"><span style="color:var(--danger);font-weight:600;">⚠️ Mermaid diagram syntax:</span><pre class="ascii-diagram-pre" style="margin-top:6px;color:var(--text-muted);">${escapeHtml(raw)}</pre></div>`;
        el.setAttribute('data-rendered', 'true');
      }
    }
  }

  function initMarkdownDocsTab() {
    refreshMdDocsDropdown();
    if (!currentMdDocText && allNotes.length > 0) {
      onMdDocsNoteChange(allNotes[0].id);
    } else if (!currentMdDocText) {
      loadSampleRichDoc();
    }
  }

  function refreshMdDocsDropdown() {
    const select = document.getElementById('mdDocsNoteSelect');
    if (!select) return;
    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Select note from history --</option>' +
      allNotes.map(n => {
        const title = n.title || 'Untitled Note';
        const dateStr = n.created_at ? new Date(n.created_at).toLocaleDateString() : '';
        const preview = (n.text || '').substring(0, 30).replace(/\n/g, ' ');
        return `<option value="${n.id}">${escapeHtml(title)} ${dateStr ? '(' + dateStr + ')' : ''} - ${escapeHtml(preview)}...</option>`;
      }).join('');
    if (currentVal && allNotes.some(n => String(n.id) === String(currentVal))) {
      select.value = currentVal;
    }
  }

  function onMdDocsNoteChange(id) {
    if (!id) return;
    const note = allNotes.find(n => String(n.id) === String(id));
    if (!note) return;
    currentMdDocNoteId = note.id;
    currentMdDocText = note.text || '';

    const titleEl = document.getElementById('mdDocTitle');
    const dateEl = document.getElementById('mdDocDate');
    const tagsEl = document.getElementById('mdDocTags');
    const bodyEl = document.getElementById('mdDocRenderedBody');

    if (titleEl) titleEl.innerText = note.title || 'Untitled Note';
    if (dateEl) {
      const dt = note.created_at ? new Date(note.created_at).toLocaleString() : 'Recently';
      dateEl.innerText = `Last updated: ${dt}`;
    }
    if (tagsEl) {
      tagsEl.innerHTML = (note.labels || []).map(l => `<span class="note-label-pill" style="font-size:0.7rem;padding:1px 6px;">#${escapeHtml(l)}</span>`).join('');
    }
    if (bodyEl) {
      bodyEl.innerHTML = renderMarkdown(currentMdDocText) || '<i style="color:var(--text-muted);">Note is empty.</i>';
      triggerMermaidRender(bodyEl);
    }

    const select = document.getElementById('mdDocsNoteSelect');
    if (select && select.value !== String(id)) {
      select.value = String(id);
    }
  }

  const SAMPLE_RICH_MARKDOWN = `# System Architecture & API Specification

> Enterprise LAN transfer system designed for high-throughput zero-dependency file and data synchronisation between mobile devices and desktop computers.

## Feature & Performance Matrix

| Feature | Protocol | Status | Latency | Mobile Support |
| :--- | :---: | :---: | :---: | ---: |
| File Streaming | HTTP/1.1 Chunked | Active | 12ms | Full Touch UI |
| Shared Notes | REST JSON | Active | 4ms | Responsive Split |
| OpenAPI Testing | CORS Proxy | Active | 24ms | Schema Inspector |
| Mermaid Diagrams | SVG Vector | Active | 8ms | Client Rendered |
| ASCII Blueprints | Monospace 1.25 | Active | <1ms | Crisp Scaling |

## Network Flow Diagram

\`\`\`mermaid
flowchart TD
    Client[📱 Mobile or Browser] -->|HTTP Request| Server[⚡ LAN Transfer Server]
    Server -->|Direct Streaming| FS[(📁 Local Storage)]
    Server -->|In-Memory Cache| Notes[📝 Shared Notes]
    Server -->|Proxy Request| ExternalAPI[🌐 External / Localhost API]
    ExternalAPI -->|CORS Bypass Response| Server
    Server -->|JSON / Status| Client
\`\`\`

## System Topology & Microservices

\`\`\`ascii
┌─────────────────────────────────────────────────────────────┐
│                    LAN APPLICATION GATEWAY                  │
├──────────────────────────────┬──────────────────────────────┤
│         HTTP ENGINE          │       INTERNAL PROXY         │
│  ┌────────────────────────┐  │  ┌────────────────────────┐  │
│  │ Port 8080 (0.0.0.0)    │  │  │ /api/proxy             │  │
│  │ Single-Thread Core     │──┼─>│ urllib.request Engine  │  │
│  └────────────────────────┘  │  └────────────────────────┘  │
└──────────────┬───────────────┴──────────────┬───────────────┘
               │                              │
               ▼                              ▼
      ┌─────────────────┐            ┌─────────────────┐
      │  UPLOAD FOLDER  │            │ IN-MEMORY STORE │
      │  ./uploads/     │            │ .notes.json     │
      └─────────────────┘            └─────────────────┘
\`\`\`

## Authentication & Protocol Handshake

\`\`\`mermaid
sequenceDiagram
    autonumber
    actor User as 👤 Developer
    participant UI as 🖥️ Web UI (Browser)
    participant Server as ⚡ LAN Server
    participant Ext as 🌐 Target API

    User->>UI: Select OpenAPI Endpoint (POST /upload)
    UI->>Server: POST /api/proxy { url, method, body }
    Note over Server: Server bypasses browser CORS
    Server->>Ext: Forward HTTP Request with custom headers
    Ext-->>Server: HTTP 200 OK + JSON Response Body
    Server-->>UI: Proxy Response { status: 200, elapsedMs: 18 }
    UI->>User: Render formatted JSON & Status Badge
\`\`\`
`;

  function loadSampleRichDoc() {
    currentMdDocNoteId = null;
    currentMdDocText = SAMPLE_RICH_MARKDOWN;

    const titleEl = document.getElementById('mdDocTitle');
    const dateEl = document.getElementById('mdDocDate');
    const tagsEl = document.getElementById('mdDocTags');
    const bodyEl = document.getElementById('mdDocRenderedBody');

    if (titleEl) titleEl.innerText = '✨ Rich Markdown Documentation Sample';
    if (dateEl) dateEl.innerText = 'Last updated: Sample Document';
    if (tagsEl) {
      tagsEl.innerHTML = '<span class="note-label-pill" style="font-size:0.7rem;padding:1px 6px;">#documentation</span><span class="note-label-pill" style="font-size:0.7rem;padding:1px 6px;">#mermaid</span><span class="note-label-pill" style="font-size:0.7rem;padding:1px 6px;">#ascii</span>';
    }
    if (bodyEl) {
      bodyEl.innerHTML = renderMarkdown(SAMPLE_RICH_MARKDOWN);
      triggerMermaidRender(bodyEl);
    }
    const select = document.getElementById('mdDocsNoteSelect');
    if (select) select.value = '';
    showToast('✨ Loaded rich documentation sample');
  }

  function editCurrentDocInNotes() {
    if (currentMdDocNoteId) {
      switchTab('notes');
      loadNoteToEditor(currentMdDocNoteId);
    } else if (currentMdDocText) {
      switchTab('notes');
      createNewNoteFromList();
      const titleInput = document.getElementById('noteTitleInput');
      const input = document.getElementById('noteInput');
      if (titleInput) titleInput.value = 'Rich Document Draft';
      if (input) input.value = currentMdDocText;
      onNoteInputChanged();
      showToast('📝 Transferred markdown to Notes editor');
    } else {
      switchTab('notes');
    }
  }

  function copyCurrentMdDocSource() {
    if (!currentMdDocText) {
      showToast('⚠️ No document content to copy');
      return;
    }
    navigator.clipboard.writeText(currentMdDocText).then(() => {
      showToast('📋 Copied markdown source to clipboard');
    }).catch(() => {
      showToast('❌ Failed to copy to clipboard');
    });
  }

  /* =========================================================================
     OPENAPI / SWAGGER TESTER
     ========================================================================= */
  let currentOpenApiSpec = null;
  let parsedOpenApiEndpoints = [];
  let selectedOpenApiEndpoint = null;
  let openApiSpecDrawerOpen = false;

  function toggleOpenApiSpecDrawer() {
    openApiSpecDrawerOpen = !openApiSpecDrawerOpen;
    const drawer = document.getElementById('openApiSpecDrawer');
    const btn = document.getElementById('btnToggleOpenApiSpec');
    if (drawer) drawer.style.display = openApiSpecDrawerOpen ? 'block' : 'none';
    if (btn) btn.classList.toggle('active', openApiSpecDrawerOpen);
  }

  function initOpenApiTab() {
    populateOpenApiUploadedSelect();
    if (!currentOpenApiSpec) {
      loadSampleOpenApi('lan');
    }
  }

  function populateOpenApiUploadedSelect() {
    const select = document.getElementById('openApiUploadedSelect');
    if (!select) return;
    const specFiles = (allFiles || []).filter(f => /\.(json|ya?ml)$/i.test(f.name));
    select.innerHTML = '<option value="">📂 Select from uploaded files...</option>' +
      specFiles.map(f => `<option value="${escapeHtml(f.name)}">${escapeHtml(f.name)} (${formatBytes(f.size)})</option>`).join('');
  }

  function getLanApiSpecJson() {
    const host = window.location.origin || 'http://localhost:8080';
    return {
      openapi: '3.0.0',
      info: {
        title: 'LAN File Transfer & Sharing API',
        version: '1.0.0',
        description: 'Zero-dependency local network file sharing server API with persistent pinned items, tags, and rich note management.'
      },
      servers: [
        { url: host, description: 'Current LAN Transfer Server' },
        { url: 'http://localhost:8080', description: 'Localhost (Default port 8080)' }
      ],
      paths: {
        '/api/files': {
          get: {
            tags: ['Files'],
            summary: 'List all uploaded files',
            description: 'Returns list of files stored in the server upload folder including size, upload time, pinned state, and tags.',
            responses: { '200': { description: 'Success' } }
          }
        },
        '/api/notes': {
          get: {
            tags: ['Notes'],
            summary: 'Get all shared notes',
            description: 'Returns list of shared notes stored in memory and persisted to disk.',
            responses: { '200': { description: 'Success' } }
          },
          post: {
            tags: ['Notes'],
            summary: 'Create a new note',
            description: 'Add a new text note with optional title and tags.',
            requestBody: {
              content: {
                'application/json': {
                  example: {
                    title: 'Meeting Notes',
                    text: 'Discussion on system architecture and responsive UI improvements.',
                    labels: ['work', 'architecture']
                  }
                }
              }
            },
            responses: { '200': { description: 'Note created' } }
          }
        },
        '/api/notes/clear': {
          post: {
            tags: ['Notes'],
            summary: 'Clear all notes',
            description: 'Wipes all notes from memory and updates storage on disk.',
            responses: { '200': { description: 'Notes cleared' } }
          }
        },
        '/api/note/delete': {
          post: {
            tags: ['Notes'],
            summary: 'Delete note by ID',
            description: 'Removes a specific note by passing its numeric ID.',
            requestBody: {
              content: {
                'application/json': {
                  example: { id: 1 }
                }
              }
            },
            responses: { '200': { description: 'Note deleted' } }
          }
        },
        '/api/pin': {
          post: {
            tags: ['Files'],
            summary: 'Toggle pinned file',
            description: 'Pin or unpin a file so it stays prominently visible at the top of all views.',
            requestBody: {
              content: {
                'application/json': {
                  example: { filename: 'document.pdf' }
                }
              }
            },
            responses: { '200': { description: 'Pin status toggled' } }
          }
        },
        '/api/label': {
          post: {
            tags: ['Tags'],
            summary: 'Add or remove tag',
            description: 'Tag or untag a file or note.',
            requestBody: {
              content: {
                'application/json': {
                  example: { type: 'file', id: 'document.pdf', label: 'project', action: 'add' }
                }
              }
            },
            responses: { '200': { description: 'Tag updated' } }
          }
        },
        '/api/proxy': {
          post: {
            tags: ['Utility'],
            summary: 'HTTP CORS Proxy',
            description: 'Proxy outgoing HTTP requests to any external host or localhost port to bypass browser CORS policies.',
            requestBody: {
              content: {
                'application/json': {
                  example: {
                    url: 'https://httpbin.org/get',
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
                  }
                }
              }
            },
            responses: { '200': { description: 'Proxied response data' } }
          }
        }
      }
    };
  }

  function getPetstoreSampleSpec() {
    return {
      openapi: '3.0.2',
      info: {
        title: 'Swagger Petstore - OpenAPI 3.0',
        version: '1.0.11',
        description: 'A sample Pet Store Server based on the OpenAPI 3.0 specification.'
      },
      servers: [
        { url: 'https://petstore.swagger.io/v2', description: 'Swagger Petstore V2' },
        { url: 'https://httpbin.org', description: 'HTTPBin Test API' }
      ],
      paths: {
        '/pet/findByStatus': {
          get: {
            tags: ['pet'],
            summary: 'Finds Pets by status',
            parameters: [
              { name: 'status', in: 'query', description: 'Status values that need to be considered for filter', required: false, schema: { type: 'string', default: 'available' } }
            ],
            responses: { '200': { description: 'successful operation' } }
          }
        },
        '/pet/{petId}': {
          get: {
            tags: ['pet'],
            summary: 'Find pet by ID',
            parameters: [
              { name: 'petId', in: 'path', description: 'ID of pet to return', required: true, schema: { type: 'integer', default: 1 } }
            ],
            responses: { '200': { description: 'successful operation' } }
          }
        },
        '/pet': {
          post: {
            tags: ['pet'],
            summary: 'Add a new pet to the store',
            requestBody: {
              content: {
                'application/json': {
                  example: {
                    id: 10,
                    name: 'doggie',
                    status: 'available',
                    tags: [{ id: 1, name: 'friendly' }]
                  }
                }
              }
            },
            responses: { '200': { description: 'Successful operation' } }
          }
        },
        '/store/inventory': {
          get: {
            tags: ['store'],
            summary: 'Returns pet inventories by status',
            responses: { '200': { description: 'successful operation' } }
          }
        }
      }
    };
  }

  function loadSampleOpenApi(type) {
    const rawSpecArea = document.getElementById('openApiRawSpec');
    let specObj = null;
    if (type === 'lan') {
      specObj = getLanApiSpecJson();
    } else {
      specObj = getPetstoreSampleSpec();
    }
    if (rawSpecArea) {
      rawSpecArea.value = JSON.stringify(specObj, null, 2);
    }
    parseCurrentOpenApiSpec();
    showToast(`⚡ Loaded ${type === 'lan' ? 'LAN Server' : 'Petstore'} API spec`);
  }

  function fetchOpenApiFromUrl() {
    const urlInput = document.getElementById('openApiUrlInput');
    const url = (urlInput ? urlInput.value : '').trim();
    if (!url) {
      showToast('⚠️ Please enter a spec URL');
      return;
    }
    showToast('⏳ Fetching spec...');
    fetch('/api/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, method: 'GET', headers: { 'Accept': 'application/json, text/yaml, */*' } })
    })
    .then(res => res.json())
    .then(resData => {
      if (resData.status >= 200 && resData.status < 300 && resData.data) {
        document.getElementById('openApiRawSpec').value = resData.data;
        parseCurrentOpenApiSpec();
        showToast('✓ Spec fetched and parsed successfully');
      } else {
        showToast('❌ Failed to fetch spec: ' + (resData.error || ('Status ' + resData.status)));
      }
    })
    .catch(err => showToast('❌ Network error fetching spec'));
  }

  function loadOpenApiFromUploadedFile(filename) {
    if (!filename) return;
    showToast('⏳ Loading file spec...');
    fetch(`/view/${encodeURIComponent(filename)}`)
    .then(r => r.text())
    .then(text => {
      document.getElementById('openApiRawSpec').value = text;
      parseCurrentOpenApiSpec();
      showToast('✓ Uploaded spec loaded');
    })
    .catch(err => showToast('❌ Error loading uploaded spec'));
  }

  function handleOpenApiLocalFile(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(evt) {
      document.getElementById('openApiRawSpec').value = evt.target.result;
      parseCurrentOpenApiSpec();
      showToast('✓ Local file spec loaded');
    };
    reader.readAsText(file);
  }

  function parseCurrentOpenApiSpec() {
    const rawSpecArea = document.getElementById('openApiRawSpec');
    const statusEl = document.getElementById('openApiParseStatus');
    const text = (rawSpecArea ? rawSpecArea.value : '').trim();
    if (!text) {
      if (statusEl) statusEl.innerText = 'No spec content to parse';
      return;
    }

    let spec = null;
    try {
      spec = JSON.parse(text);
    } catch (jsonErr) {
      try {
        if (window.jsyaml) {
          spec = jsyaml.load(text);
        }
      } catch (yamlErr) {
        console.warn('YAML parsing error:', yamlErr);
      }
    }

    if (!spec || typeof spec !== 'object' || !spec.paths) {
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--danger);">❌ Invalid OpenAPI/Swagger spec (missing paths)</span>';
      showToast('❌ Failed to parse OpenAPI specification');
      return;
    }

    currentOpenApiSpec = spec;
    renderOpenApiSpecUI(spec);
    if (statusEl) statusEl.innerHTML = '<span style="color:var(--success);">✓ Spec parsed successfully</span>';
    const drawer = document.getElementById('openApiSpecDrawer');
    if (drawer && openApiSpecDrawerOpen) {
      toggleOpenApiSpecDrawer();
    }
  }

  function renderOpenApiSpecUI(spec) {
    const info = spec.info || {};
    const titleEl = document.getElementById('openApiInfoTitle');
    const verEl = document.getElementById('openApiInfoVersion');
    if (titleEl) titleEl.innerText = info.title || 'API Specification';
    if (verEl) verEl.innerText = `v${info.version || '1.0.0'}`;

    const serverSelect = document.getElementById('openApiServerSelect');
    let servers = [];
    if (Array.isArray(spec.servers) && spec.servers.length > 0) {
      servers = spec.servers.map(s => typeof s === 'string' ? s : (s.url || ''));
    } else if (spec.host) {
      const scheme = (spec.schemes && spec.schemes[0]) || window.location.protocol.replace(':', '');
      servers = [`${scheme}://${spec.host}${spec.basePath || ''}`];
    } else {
      servers = [window.location.origin];
    }

    if (serverSelect) {
      serverSelect.innerHTML = servers.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('') +
        '<option value="__custom__">⚙️ Custom URL...</option>';
      serverSelect.value = servers[0] || window.location.origin;
    }

    parsedOpenApiEndpoints = [];
    const paths = spec.paths || {};
    const methods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];

    for (const [pathStr, pathObj] of Object.entries(paths)) {
      if (!pathObj || typeof pathObj !== 'object') continue;
      const commonParams = pathObj.parameters || [];
      for (const m of methods) {
        if (pathObj[m]) {
          const op = pathObj[m];
          const allParams = [...commonParams, ...(op.parameters || [])];
          parsedOpenApiEndpoints.push({
            method: m.toUpperCase(),
            path: pathStr,
            tag: (op.tags && op.tags[0]) || 'General',
            summary: op.summary || '',
            description: op.description || '',
            parameters: allParams,
            requestBody: op.requestBody || null,
            responses: op.responses || {}
          });
        }
      }
    }

    const countEl = document.getElementById('openApiEndpointCount');
    if (countEl) countEl.innerText = `${parsedOpenApiEndpoints.length} endpoints`;

    renderOpenApiEndpointsList(parsedOpenApiEndpoints);

    if (parsedOpenApiEndpoints.length > 0) {
      selectOpenApiEndpoint(parsedOpenApiEndpoints[0]);
    }
  }

  function renderOpenApiEndpointsList(endpoints) {
    const listEl = document.getElementById('openApiEndpointsList');
    if (!listEl) return;
    if (endpoints.length === 0) {
      listEl.innerHTML = '<div style="text-align: center; padding: 24px 10px; color: var(--text-muted); font-size: 0.8rem;">No matching endpoints found.</div>';
      return;
    }

    const groups = {};
    endpoints.forEach(ep => {
      const tag = ep.tag || 'General';
      if (!groups[tag]) groups[tag] = [];
      groups[tag].push(ep);
    });

    let html = '';
    for (const [tag, eps] of Object.entries(groups)) {
      html += `<div class="openapi-tag-group"><div class="openapi-tag-title">📂 ${escapeHtml(tag)} (${eps.length})</div>`;
      eps.forEach(ep => {
        const m = ep.method.toLowerCase();
        const isActive = selectedOpenApiEndpoint && selectedOpenApiEndpoint.method === ep.method && selectedOpenApiEndpoint.path === ep.path;
        html += `
          <button type="button" class="openapi-endpoint-item ${isActive ? 'active' : ''}" onclick="onEndpointItemClicked('${escapeHtml(ep.method)}', '${escapeHtml(ep.path)}')">
            <span class="method-badge method-${m}">${ep.method}</span>
            <span class="openapi-endpoint-path" title="${escapeHtml(ep.path)}">${escapeHtml(ep.path)}</span>
          </button>
        `;
      });
      html += `</div>`;
    }
    listEl.innerHTML = html;
  }

  function filterOpenApiEndpoints(query) {
    const q = (query || '').toLowerCase().trim();
    if (!q) {
      renderOpenApiEndpointsList(parsedOpenApiEndpoints);
      return;
    }
    const filtered = parsedOpenApiEndpoints.filter(ep =>
      ep.path.toLowerCase().includes(q) ||
      ep.method.toLowerCase().includes(q) ||
      ep.tag.toLowerCase().includes(q) ||
      ep.summary.toLowerCase().includes(q)
    );
    renderOpenApiEndpointsList(filtered);
  }

  function onEndpointItemClicked(method, path) {
    const ep = parsedOpenApiEndpoints.find(e => e.method === method && e.path === path);
    if (ep) {
      selectOpenApiEndpoint(ep);
    }
  }

  function onOpenApiServerSelected(val) {
    const customInput = document.getElementById('openApiCustomServer');
    if (customInput) {
      customInput.style.display = val === '__custom__' ? 'block' : 'none';
      if (val === '__custom__') customInput.focus();
    }
  }

  function selectOpenApiEndpoint(ep) {
    selectedOpenApiEndpoint = ep;

    document.querySelectorAll('.openapi-endpoint-item').forEach(b => b.classList.remove('active'));
    const matchedBtn = Array.from(document.querySelectorAll('.openapi-endpoint-item')).find(b =>
      b.innerText.includes(ep.method) && b.innerText.includes(ep.path)
    );
    if (matchedBtn) matchedBtn.classList.add('active');

    const methodBadge = document.getElementById('activeEndpointMethod');
    const pathEl = document.getElementById('activeEndpointPath');
    const sumEl = document.getElementById('activeEndpointSummary');
    if (methodBadge) {
      methodBadge.className = `method-badge method-${ep.method.toLowerCase()}`;
      methodBadge.innerText = ep.method;
    }
    if (pathEl) pathEl.innerText = ep.path;
    if (sumEl) sumEl.innerText = ep.summary || ep.description || 'No description provided';

    const paramsListEl = document.getElementById('openApiParamsList');
    if (paramsListEl) {
      if (!ep.parameters || ep.parameters.length === 0) {
        paramsListEl.innerHTML = '<div style="font-size:0.8rem;color:var(--text-muted);font-style:italic;">No parameters required for this endpoint.</div>';
      } else {
        paramsListEl.innerHTML = ep.parameters.map((p) => {
          const isReq = p.required ? '<span style="color:var(--danger);font-weight:bold;">*</span>' : '';
          const defVal = (p.schema && p.schema.default !== undefined) ? p.schema.default : (p.example !== undefined ? p.example : '');
          return `
            <div class="openapi-param-row">
              <span class="openapi-param-name" title="${p.in}: ${p.name}">
                ${escapeHtml(p.name)} ${isReq}
                <small style="font-weight:normal;color:var(--text-muted);font-size:0.7rem;display:block;">${p.in}</small>
              </span>
              <input type="text" class="openapi-input openapi-param-input" data-param-name="${escapeHtml(p.name)}" data-param-in="${escapeHtml(p.in)}" value="${escapeHtml(String(defVal))}" placeholder="${p.description || p.name}">
            </div>
          `;
        }).join('');
      }
    }

    const bodyContainer = document.getElementById('openApiBodyContainer');
    const bodyEditor = document.getElementById('openApiRequestBody');
    const hasBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(ep.method);
    if (bodyContainer) bodyContainer.style.display = hasBody ? 'block' : 'none';
    if (bodyEditor && hasBody) {
      let sampleBody = '';
      if (ep.requestBody && ep.requestBody.content) {
        const jsonContent = ep.requestBody.content['application/json'];
        if (jsonContent && jsonContent.example) {
          sampleBody = JSON.stringify(jsonContent.example, null, 2);
        } else if (jsonContent && jsonContent.schema && jsonContent.schema.example) {
          sampleBody = JSON.stringify(jsonContent.schema.example, null, 2);
        }
      }
      if (!sampleBody && hasBody) {
        sampleBody = '{\n  \n}';
      }
      bodyEditor.value = sampleBody;
    }

    const respSec = document.getElementById('openApiResponseSection');
    if (respSec) respSec.style.display = 'none';
  }

  function formatOpenApiBodyJson() {
    const editor = document.getElementById('openApiRequestBody');
    if (!editor) return;
    try {
      const parsed = JSON.parse(editor.value);
      editor.value = JSON.stringify(parsed, null, 2);
      showToast('✓ JSON formatted');
    } catch (e) {
      showToast('❌ Invalid JSON in body');
    }
  }

  function executeOpenApiRequest() {
    if (!selectedOpenApiEndpoint) {
      showToast('⚠️ No endpoint selected');
      return;
    }

    const serverSelect = document.getElementById('openApiServerSelect');
    let baseUrl = serverSelect ? serverSelect.value : window.location.origin;
    if (baseUrl === '__custom__') {
      const customInput = document.getElementById('openApiCustomServer');
      baseUrl = (customInput ? customInput.value : '').trim() || window.location.origin;
    }
    if (baseUrl.endsWith('/')) baseUrl = baseUrl.slice(0, -1);

    let resolvedPath = selectedOpenApiEndpoint.path;
    const queryParams = new URLSearchParams();

    document.querySelectorAll('.openapi-param-input').forEach(inp => {
      const pName = inp.getAttribute('data-param-name');
      const pIn = inp.getAttribute('data-param-in');
      const pVal = inp.value.trim();
      if (!pVal) return;

      if (pIn === 'path') {
        resolvedPath = resolvedPath.replace(`{${pName}}`, encodeURIComponent(pVal));
      } else if (pIn === 'query') {
        queryParams.append(pName, pVal);
      }
    });

    const queryString = queryParams.toString();
    const fullUrl = `${baseUrl}${resolvedPath}${queryString ? '?' + queryString : ''}`;

    const headers = {};
    const acceptInp = document.getElementById('header_accept');
    const authInp = document.getElementById('header_authorization');
    if (acceptInp && acceptInp.value) headers['Accept'] = acceptInp.value.trim();
    if (authInp && authInp.value) headers['Authorization'] = authInp.value.trim();

    let reqBody = null;
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(selectedOpenApiEndpoint.method)) {
      const bodyEditor = document.getElementById('openApiRequestBody');
      const rawText = bodyEditor ? bodyEditor.value.trim() : '';
      if (rawText) {
        reqBody = rawText;
        headers['Content-Type'] = 'application/json';
      }
    }

    const useProxy = document.getElementById('openApiUseProxyCheckbox').checked;
    const sendBtn = document.getElementById('btnSendOpenApiRequest');
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.innerText = '⏳ Sending...';
    }

    const startTime = Date.now();

    const handleResult = (status, statusText, data, elapsedMs) => {
      if (sendBtn) {
        sendBtn.disabled = false;
        sendBtn.innerText = '🚀 Send Request';
      }

      const respSec = document.getElementById('openApiResponseSection');
      if (respSec) respSec.style.display = 'block';

      const statusBadge = document.getElementById('responseStatusBadge');
      if (statusBadge) {
        statusBadge.innerText = `${status} ${statusText || ''}`.trim();
        statusBadge.className = 'openapi-response-badge';
        if (status >= 200 && status < 300) statusBadge.classList.add('status-2xx');
        else if (status >= 400 && status < 500) statusBadge.classList.add('status-4xx');
        else statusBadge.classList.add('status-5xx');
      }

      const timeBadge = document.getElementById('responseTimeBadge');
      if (timeBadge) timeBadge.innerText = `⏱️ ${elapsedMs} ms`;

      const sizeBadge = document.getElementById('responseSizeBadge');
      const sizeBytes = typeof data === 'string' ? new Blob([data]).size : JSON.stringify(data).length;
      if (sizeBadge) sizeBadge.innerText = formatBytes(sizeBytes);

      const contentEl = document.getElementById('openApiResponseContent');
      if (contentEl) {
        let displayContent = data;
        if (typeof data === 'string') {
          try {
            const p = JSON.parse(data);
            displayContent = JSON.stringify(p, null, 2);
          } catch (e) {}
        } else if (typeof data === 'object') {
          displayContent = JSON.stringify(data, null, 2);
        }
        contentEl.innerText = displayContent || '(Empty response body)';
      }
    };

    if (useProxy) {
      fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: fullUrl,
          method: selectedOpenApiEndpoint.method,
          headers: headers,
          body: reqBody
        })
      })
      .then(res => res.json())
      .then(resData => {
        handleResult(resData.status || 0, resData.statusText || '', resData.data || resData.error || '', resData.elapsedMs || (Date.now() - startTime));
      })
      .catch(err => {
        handleResult(0, 'Network Error', err.message || String(err), Date.now() - startTime);
      });
    } else {
      fetch(fullUrl, {
        method: selectedOpenApiEndpoint.method,
        headers: headers,
        body: reqBody
      })
      .then(async res => {
        const elapsed = Date.now() - startTime;
        const text = await res.text();
        handleResult(res.status, res.statusText, text, elapsed);
      })
      .catch(err => {
        handleResult(0, 'CORS / Network Error', 'Browser fetch failed: ' + err.message + '. Try enabling the "Proxy via LAN Server" checkbox to bypass CORS restrictions.', Date.now() - startTime);
      });
    }
  }

  function copyOpenApiResponse() {
    const contentEl = document.getElementById('openApiResponseContent');
    const text = contentEl ? contentEl.innerText : '';
    if (!text) {
      showToast('⚠️ No response content to copy');
      return;
    }
    navigator.clipboard.writeText(text).then(() => {
      showToast('📋 Copied response body to clipboard');
    }).catch(() => showToast('❌ Failed to copy response'));
  }

  /* =========================================================================
     FILE DETAIL PAGE & QUICK HOVER PREVIEW MODAL
     ========================================================================= */

  const TEXT_FILE_EXTENSIONS = new Set([
    'txt', 'py', 'js', 'ts', 'jsx', 'tsx', 'html', 'htm', 'css', 'scss',
    'json', 'md', 'markdown', 'yaml', 'yml', 'xml', 'sh', 'bash', 'zsh',
    'sql', 'c', 'cpp', 'h', 'hpp', 'java', 'go', 'rs', 'php', 'rb',
    'ini', 'conf', 'env', 'properties', 'log', 'csv', 'tsv', 'svg'
  ]);

  function isTextFile(filename) {
    const ext = (filename || '').split('.').pop().toLowerCase();
    return TEXT_FILE_EXTENSIONS.has(ext);
  }

  function getFileMimeOrCategory(name) {
    const ext = (name || '').split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'svg', 'bmp', 'ico'].includes(ext)) return `Image (${ext.toUpperCase()})`;
    if (['mp4', 'mov', 'avi', 'mkv', 'webm'].includes(ext)) return `Video (${ext.toUpperCase()})`;
    if (['mp3', 'wav', 'flac', 'm4a', 'aac', 'ogg'].includes(ext)) return `Audio (${ext.toUpperCase()})`;
    if (ext === 'pdf') return 'PDF Document';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return `Archive (${ext.toUpperCase()})`;
    if (TEXT_FILE_EXTENSIONS.has(ext)) return `Text / Code (${ext.toUpperCase()})`;
    return `Binary / ${ext.toUpperCase() || 'File'}`;
  }

  function scheduleFileHoverPreview(element, filename) {
    // Disabled hover preview
    return;
  }

  function cancelFileHoverPreview() {
    if (fileHoverTimer) {
      clearTimeout(fileHoverTimer);
      fileHoverTimer = null;
    }
  }

  function closeHoverPreview(e) {
    if (!e || e.target?.id === 'fileHoverPreviewModal' || e.type === 'click' || e.key === 'Escape') {
      const modal = document.getElementById('fileHoverPreviewModal');
      if (modal) modal.classList.remove('active');
      cancelFileHoverPreview();
    }
  }

  function openDetailFromHover() {
    const target = hoverPreviewTargetFile;
    closeHoverPreview();
    if (target) {
      openFileDetail(target.name);
    }
  }

  function showFileHoverPreview(filename) {
    const file = allFiles.find(f => f.name === filename);
    if (!file) return;
    hoverPreviewTargetFile = file;

    const modal = document.getElementById('fileHoverPreviewModal');
    if (!modal) return;

    const iconEl = document.getElementById('hoverPreviewTypeIcon');
    if (iconEl) iconEl.innerText = getFileIcon(file.name);

    const nameEl = document.getElementById('hoverPreviewFileName');
    if (nameEl) {
      nameEl.innerText = file.name;
      nameEl.title = file.name;
    }

    const metaEl = document.getElementById('hoverPreviewFileMeta');
    if (metaEl) metaEl.innerText = `${file.size_formatted} • ${file.date || file.date_formatted || ''}`;

    const downloadBtn = document.getElementById('hoverPreviewDownloadBtn');
    if (downloadBtn) {
      downloadBtn.href = `/download/${encodeURIComponent(file.name)}`;
      downloadBtn.setAttribute('download', file.name);
    }

    const tagsContainer = document.getElementById('hoverPreviewTags');
    if (tagsContainer) {
      const labels = file.labels || [];
      if (labels.length > 0) {
        tagsContainer.innerHTML = labels.map(l => `<span class="label-chip" style="font-size: 0.72rem; padding: 2px 6px;">#${escapeHtml(l)}</span>`).join('');
      } else {
        tagsContainer.innerHTML = '';
      }
    }

    const body = document.getElementById('hoverPreviewBody');
    if (!body) return;

    const ext = file.name.split('.').pop().toLowerCase();
    const encodedName = encodeURIComponent(file.name);

    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico'].includes(ext)) {
      body.innerHTML = `<img src="/view/${encodedName}" style="max-height: 240px; max-width: 100%; object-fit: contain; border-radius: 6px;" alt="${escapeHtml(file.name)}" />`;
    } else if (['mp4', 'webm', 'ogv', 'mov', 'mkv'].includes(ext)) {
      body.innerHTML = `<video src="/view/${encodedName}" controls style="max-height: 240px; max-width: 100%; border-radius: 6px;" preload="metadata"></video>`;
    } else if (['mp3', 'wav', 'ogg', 'm4a', 'flac', 'aac'].includes(ext)) {
      body.innerHTML = `
        <div style="padding: 20px; width: 100%; text-align: center;">
          <div style="font-size: 2.4rem; margin-bottom: 8px;">🎵</div>
          <audio src="/view/${encodedName}" controls style="width: 100%; max-width: 320px;" preload="metadata"></audio>
        </div>`;
    } else if (ext === 'pdf') {
      body.innerHTML = `
        <div style="text-align: center; padding: 24px;">
          <div style="font-size: 2.8rem; margin-bottom: 6px;">📕</div>
          <div style="font-size: 0.84rem; font-weight: 600; color: var(--text);">PDF Document</div>
          <div style="font-size: 0.74rem; color: var(--text-muted); margin-top: 2px;">${file.size_formatted}</div>
        </div>`;
    } else if (isTextFile(file.name)) {
      body.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted); padding: 12px;">Loading preview snippet...</div>`;
      fetch(`/view/${encodedName}`)
        .then(res => res.text())
        .then(text => {
          if (hoverPreviewTargetFile && hoverPreviewTargetFile.name === file.name) {
            const snippet = text.slice(0, 1000);
            body.innerHTML = `<pre class="hover-preview-code" style="margin: 0; padding: 10px; width: 100%; height: 100%; max-height: 240px; overflow: hidden; font-size: 0.74rem; font-family: ui-monospace, monospace; color: var(--text); line-height: 1.4; white-space: pre-wrap; word-break: break-all;"><code>${escapeHtml(snippet)}${text.length > 1000 ? '\n...' : ''}</code></pre>`;
          }
        })
        .catch(() => {
          if (hoverPreviewTargetFile && hoverPreviewTargetFile.name === file.name) {
            body.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-muted);">Could not load preview</div>`;
          }
        });
    } else {
      body.innerHTML = `
        <div style="text-align: center; padding: 24px;">
          <div style="font-size: 2.8rem; margin-bottom: 6px;">${getFileIcon(file.name)}</div>
          <div style="font-size: 0.84rem; font-weight: 600; color: var(--text);">${escapeHtml(file.name)}</div>
          <div style="font-size: 0.74rem; color: var(--text-muted); margin-top: 2px;">${file.size_formatted}</div>
        </div>`;
    }

    modal.classList.add('active');
  }

  function openFileDetail(filename) {
    cancelFileHoverPreview();
    const modal = document.getElementById('fileHoverPreviewModal');
    if (modal) modal.classList.remove('active');

    const file = allFiles.find(f => f.name === filename);
    if (!file) {
      showToast('⚠️ File not found');
      return;
    }

    previousTabBeforeDetail = activeTab || 'upload';

    // Hide all tab panes
    ['tabUpload', 'tabFiles', 'tabNotes', 'tabOpenApi', 'tabMarkdownDocs', 'tabSearch', 'tabEnvVar'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });

    const detailPage = document.getElementById('fileDetailPage');
    if (detailPage) {
      detailPage.style.display = 'block';
    }

    renderFileDetailPage(file);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function closeFileDetail() {
    const detailPage = document.getElementById('fileDetailPage');
    if (detailPage) {
      detailPage.style.display = 'none';
    }
    switchTab(previousTabBeforeDetail || 'upload');
  }

  function renderFileDetailPage(file) {
    currentDetailFile = file;

    // Header info
    const nameEl = document.getElementById('detailFileName');
    if (nameEl) nameEl.textContent = file.name;

    const subEl = document.getElementById('detailFileSub');
    if (subEl) subEl.textContent = `${file.size_formatted} (${(file.size || 0).toLocaleString()} bytes) • Uploaded on ${file.date || file.date_formatted || ''}`;

    const iconEl = document.getElementById('detailTypeIcon');
    if (iconEl) iconEl.textContent = getFileIcon(file.name);

    const downloadBtn = document.getElementById('detailDownloadBtn');
    if (downloadBtn) {
      downloadBtn.href = `/download/${encodeURIComponent(file.name)}`;
      downloadBtn.setAttribute('download', file.name);
    }

    const openTabBtn = document.getElementById('detailOpenTabBtn');
    if (openTabBtn) {
      openTabBtn.href = `/view/${encodeURIComponent(file.name)}`;
    }

    const pinText = document.getElementById('detailPinText');
    if (pinText) {
      pinText.textContent = file.is_pinned ? 'Unpin' : 'Pin';
    }

    // Sidebar metadata
    const metaName = document.getElementById('detailMetaFileName');
    if (metaName) metaName.textContent = file.name;

    const metaSize = document.getElementById('detailMetaFileSize');
    if (metaSize) metaSize.textContent = `${file.size_formatted} (${(file.size || 0).toLocaleString()} bytes)`;

    const metaDate = document.getElementById('detailMetaFileDate');
    if (metaDate) metaDate.textContent = file.date || file.date_formatted || '';

    const metaType = document.getElementById('detailMetaFileType');
    if (metaType) metaType.textContent = file.mime_type || getFileMimeOrCategory(file.name);

    // Sidebar tags
    renderDetailTags(file);

    // Sidebar Direct LAN URL & QR
    const directUrl = `${getLanUrl()}/download/${encodeURIComponent(file.name)}`;
    const urlInput = document.getElementById('detailDirectUrlInput');
    if (urlInput) urlInput.value = directUrl;

    const qrCanvas = document.getElementById('detailQrCanvas');
    if (qrCanvas) {
      generateQRCode(directUrl, qrCanvas);
    }

    // Main Preview Area
    const previewContainer = document.getElementById('detailPreviewContainer');
    if (!previewContainer) return;

    const ext = file.name.split('.').pop().toLowerCase();
    const encodedName = encodeURIComponent(file.name);

    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico'].includes(ext)) {
      previewContainer.innerHTML = `
        <div style="text-align: center; width: 100%;">
          <img src="/view/${encodedName}" alt="${escapeHtml(file.name)}" style="max-height: 550px; max-width: 100%; border-radius: 8px; object-fit: contain; box-shadow: 0 4px 16px rgba(0,0,0,0.25);" />
        </div>`;
    } else if (['mp4', 'webm', 'ogv', 'mov', 'mkv'].includes(ext)) {
      previewContainer.innerHTML = `
        <div style="text-align: center; width: 100%;">
          <video src="/view/${encodedName}" controls autoplay muted style="max-height: 520px; width: 100%; max-width: 800px; border-radius: 8px; background: #000; box-shadow: 0 4px 16px rgba(0,0,0,0.3);"></video>
        </div>`;
    } else if (['mp3', 'wav', 'ogg', 'm4a', 'flac', 'aac'].includes(ext)) {
      previewContainer.innerHTML = `
        <div style="text-align: center; width: 100%; padding: 40px 20px;">
          <div style="font-size: 3.5rem; margin-bottom: 16px;">🎵</div>
          <h4 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 14px; color: var(--text);">${escapeHtml(file.name)}</h4>
          <audio src="/view/${encodedName}" controls style="width: 100%; max-width: 500px; margin: 0 auto; display: block;"></audio>
        </div>`;
    } else if (ext === 'pdf') {
      previewContainer.innerHTML = `
        <div style="width: 100%; height: 620px;">
          <iframe src="/view/${encodedName}" style="width: 100%; height: 100%; border: none; border-radius: 8px; background: white;" title="PDF Preview"></iframe>
        </div>`;
    } else if (isTextFile(file.name)) {
      previewContainer.innerHTML = `
        <div style="width: 100%;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 0.78rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Source / Text Preview</span>
            <div style="display: flex; gap: 6px;">
              <button type="button" class="btn btn-secondary btn-sm" id="detailCodeWrapBtn" onclick="toggleDetailCodeWrap(this)" style="font-size: 0.72rem; padding: 3px 8px;">Wrap</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyDetailTextContent(this)" style="font-size: 0.72rem; padding: 3px 8px;">📋 Copy</button>
            </div>
          </div>
          <pre id="detailCodeBlock" style="width: 100%; max-height: 550px; overflow: auto; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: ui-monospace, monospace; font-size: 0.85rem; line-height: 1.5; white-space: pre; margin: 0;"><code id="detailCodeContent">Loading content...</code></pre>
        </div>`;
      fetch(`/view/${encodedName}`)
        .then(res => res.text())
        .then(text => {
          const codeEl = document.getElementById('detailCodeContent');
          if (codeEl) {
            codeEl.textContent = text;
          }
        })
        .catch(() => {
          const codeEl = document.getElementById('detailCodeContent');
          if (codeEl) {
            codeEl.textContent = '❌ Failed to load file content.';
          }
        });
    } else {
      previewContainer.innerHTML = `
        <div style="text-align: center; width: 100%; padding: 48px 20px;">
          <div style="font-size: 4rem; margin-bottom: 16px;">${getFileIcon(file.name)}</div>
          <h3 style="font-size: 1.2rem; font-weight: 700; margin-bottom: 8px; color: var(--text);">${escapeHtml(file.name)}</h3>
          <p style="font-size: 0.84rem; color: var(--text-muted); margin-bottom: 20px;">${file.size_formatted} • No direct in-browser preview for this file type</p>
          <a href="/download/${encodedName}" class="btn btn-primary" download style="display: inline-flex; align-items: center; gap: 8px; padding: 10px 20px; font-weight: 700;">
            <span>⬇️</span> <span>Download File</span>
          </a>
        </div>`;
    }
  }

  function renderDetailTags(file) {
    const container = document.getElementById('detailTagsList');
    if (!container) return;
    const labels = (file && file.labels) || [];
    if (labels.length === 0) {
      container.innerHTML = '<span style="font-size: 0.75rem; color: var(--text-muted); font-style: italic;">No tags added yet</span>';
      return;
    }
    container.innerHTML = labels.map(lbl => `
      <span class="label-chip" style="display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; font-size: 0.74rem;">
        <span>#${escapeHtml(lbl)}</span>
        <button type="button" onclick="removeTagFromDetail('${escapeHtml(lbl)}')" style="background: none; border: none; color: inherit; cursor: pointer; padding: 0 2px; font-size: 0.8rem; line-height: 1; opacity: 0.7;" title="Remove tag">&times;</button>
      </span>
    `).join('');
  }

  function removeTagFromDetail(label) {
    if (!currentDetailFile) return;
    updateItemLabel('file', currentDetailFile.name, label, 'remove');
  }

  function openTagModalForDetail() {
    if (currentDetailFile) {
      openTagModal('file', currentDetailFile.name);
    }
  }

  function toggleDetailCodeWrap(btn) {
    const block = document.getElementById('detailCodeBlock');
    if (!block) return;
    if (block.style.whiteSpace === 'pre-wrap') {
      block.style.whiteSpace = 'pre';
      if (btn) btn.innerText = 'Wrap';
    } else {
      block.style.whiteSpace = 'pre-wrap';
      block.style.wordBreak = 'break-all';
      if (btn) btn.innerText = 'Unwrap';
    }
  }

  function copyDetailTextContent(btn) {
    const codeEl = document.getElementById('detailCodeContent');
    const text = codeEl ? codeEl.textContent : '';
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerText;
      btn.innerText = '✓ Copied';
      setTimeout(() => btn.innerText = orig, 1500);
    }).catch(() => showToast('❌ Failed to copy'));
  }

  function copyDetailDirectUrl(btn) {
    const input = document.getElementById('detailDirectUrlInput');
    if (!input || !input.value) return;
    navigator.clipboard.writeText(input.value).then(() => {
      const orig = btn.innerText;
      btn.innerText = '✓ Copied';
      setTimeout(() => btn.innerText = orig, 1500);
      showToast('📋 Copied download link to clipboard');
    }).catch(() => showToast('❌ Failed to copy link'));
  }

  function togglePinFromDetail() {
    if (!currentDetailFile) return;
    togglePin(currentDetailFile.name);
    const pinText = document.getElementById('detailPinText');
    if (pinText) {
      pinText.textContent = currentDetailFile.is_pinned ? 'Unpin' : 'Pin';
    }
  }

  function deleteFileFromDetail() {
    if (!currentDetailFile) return;
    const name = currentDetailFile.name;
    if (!confirm(`Delete "${name}"?`)) return;
    fetch('/api/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: name })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showToast('🗑️ File deleted');
        closeFileDetail();
        fetchFilesList();
      } else {
        showToast('❌ ' + (data.error || 'Failed to delete'));
      }
    })
    .catch(() => showToast('❌ Network error deleting file'));
  }

  // Auto-init
  window.addEventListener('DOMContentLoaded', () => {
    initSettings();
    initIpSelector();
    // Initial fetch of both files and notes
    Promise.all([fetchFilesList(), fetchNotesList()]).then(() => {
      isInitialLoad = false;
    });
    // Auto-poll both files and notes every 2.5 seconds to keep Live Feed in real-time sync
    setInterval(() => {
      fetchFilesList();
      fetchNotesList();
    }, 2500);
  });
</script>
</body>
</html>
"""


def print_banner(ips, port, upload_dir):
    """Print connection information to the terminal."""
    url = f"http://{ips[0]}:{port}"
    border = "=" * 60
    print(border)
    print("   ⚡ LAN FILE TRANSFER SERVER IS RUNNING ⚡")
    print(border)
    print(f"  Upload Folder : {os.path.abspath(upload_dir)}")
    print("\n  📲 Connect any phone or device on the same Wi-Fi to:")
    for ip in ips:
        print(f"     👉  http://{ip}:{port}")
    print("\n  💻 On this computer:")
    print(f"     👉  http://localhost:{port}")

    # Try printing terminal QR code if qrcode library is installed
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make()
        print("\n  📸 Scan QR Code from your phone:")
        qr.print_ascii(invert=True)
    except ImportError:
        print("\n  💡 Tip: Install 'qrcode' (`pip install qrcode`) for a scannable")
        print(f"     QR code in terminal, or simply open http://localhost:{port}")
        print("     in your computer's browser to see the QR code on screen.")

    print(border)
    print("  Press Ctrl+C to stop the server.\n")


def run_server():
    default_port = int(os.environ.get("PORT", DEFAULT_PORT))
    default_upload_dir = os.environ.get("UPLOAD_DIR", DEFAULT_UPLOAD_DIR)
    default_bind = os.environ.get("BIND_HOST", "0.0.0.0")

    parser = argparse.ArgumentParser(description="LAN File Transfer Server with Web UI")
    parser.add_argument("--port", "-p", type=int, default=default_port, help=f"Port to listen on (default: {default_port})")
    parser.add_argument("--dir", "-d", type=str, default=default_upload_dir, help=f"Directory to store uploads (default: {default_upload_dir})")
    parser.add_argument("--bind", "-b", type=str, default=default_bind, help=f"Host/IP to bind to (default: {default_bind})")
    parser.add_argument("--lan-ip", type=str, default=os.environ.get("LAN_IP") or os.environ.get("HOST_IP"), help="Custom LAN IP to advertise (e.g. inside Docker)")
    args = parser.parse_args()

    upload_dir = os.path.abspath(args.dir)
    os.makedirs(upload_dir, exist_ok=True)

    # Load persistent notes from disk
    saved_notes = get_saved_notes(upload_dir)
    SHARED_NOTES.clear()
    SHARED_NOTES.extend(saved_notes)

    ips = get_lan_ips()
    if args.lan_ip and args.lan_ip.strip():
        custom = args.lan_ip.strip()
        if custom in ips:
            ips.remove(custom)
        ips.insert(0, custom)
    primary_ip = ips[0]

    server_address = (args.bind, args.port)
    httpd = ThreadingHTTPServer(server_address, LanFileHandler)
    httpd.upload_dir = upload_dir
    httpd.primary_ip = primary_ip
    httpd.lan_ips = ips

    print_banner(ips, args.port, upload_dir)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LAN File Server...")
    finally:
        httpd.server_close()
        print("Server stopped.")


if __name__ == "__main__":
    run_server()
