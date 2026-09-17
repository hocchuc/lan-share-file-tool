# LAN File Transfer Server & Port Scanner

A lightweight, zero-dependency toolkit for your local network (LAN / Wi-Fi) built with Python 3.

---

## 📁 1. LAN File Transfer Server (`server.py`)

Provides a modern mobile-optimized Web UI allowing smartphones, tablets, and computers on the same Wi-Fi network to upload and download files directly to/from this computer.

### Quick Start:

#### Option A: Native Python (Zero Dependencies)
```bash
git clone <your-repo-url>
cd lan-file-share
python3 server.py
# Or use the runner script with a custom port:
./run.sh 8080
```

#### Option B: Docker Compose (Recommended)
```bash
# Launch in the background with persistent volume
docker compose up -d

# View logs and terminal QR code
docker compose logs -f
```

#### Option C: Docker Run
```bash
# 1. Build the lightweight image (~50MB Alpine)
docker build -t lan-file-share .

# 2. Run container with persistent uploads volume
docker run -d \
  --name lan-file-share \
  -p 8080:8080 \
  -v $(pwd)/uploads:/app/uploads \
  -e LAN_IP=192.168.1.100 \
  lan-file-share
```

> **Note on LAN IP in Docker**: Because bridge mode containers have an internal IP (like `172.17.0.2`), you can set `-e LAN_IP=<your-pc-ip>` so the startup banner and terminal QR code display your reachable computer IP. Alternatively on Linux, use `network_mode: host` in `docker-compose.yml`.

### 📱 How to Connect from Your Phone:
1. Ensure your phone and this computer are connected to the **same Wi-Fi or LAN**.
2. When the server starts, it automatically detects your computer's local IP address and displays the URL:
   ```text
   📲 Connect any phone or device on the same Wi-Fi to:
      👉  http://192.168.1.100:8080
   ```
3. Open your phone's browser (Safari, Chrome, etc.) and visit that URL.
4. **Upload Files**: Select photos, videos, or documents, and hit **"Send to Computer Now"**.
   - Uploaded files are saved on this computer in `./uploads/`.
5. **Notes & Developer Utilities**:
   - Switch to the **"📝 Notes"** tab.
   - **Markdown Support**: Supports `# Headings`, `**bold**`, `*italic*`, `> quotes`, `- lists`, and ````fenced code blocks```` with a one-click **"Copy Code"** button. Toggle live **"👁️ MD Preview"** at any time.
   - **JSON Tools & JSONC Lenient Validation**:
     - **✨ JSON Format**: Beautify / indent JSON payloads with syntax highlighting.
     - **JSONC Comments Supported**: Allows single-line comments `// ...` and multi-line comments `/* ... */`.
     - **Lenient Validation**: Non-strict validation tolerates trailing commas and unquoted keys.
     - **Temporary Red Error Underline**: When JSON syntax is invalid, the exact invalid character and line are temporarily underlined with a red wavy border, the cursor jumps to the error position, and an error banner displays the snippet with the offending token highlighted.
     - **🗜️ JSON Minify**: Compact JSON strings into single-line format.
   - **String Tools**:
     - **🔤 Escape**: Escape quotes, backslashes, and newlines.
     - **🔓 Unescape**: Restore escaped strings.
   - **Base64 Tools**:
     - **🔒 Base64 Enc**: Encode text to standard Base64 (UTF-8 safe).
     - **🔓 Base64 Dec**: Decode Base64 strings back to plain text.
   - **Title & Labels**: Optional note title and comma-separated tags (up to 50 characters per label, spaces disallowed and converted to hyphens `-`).
   - Notes are persisted to `uploads/.notes.json` and logged to `uploads/clipboard_notes.txt`.
6. **Quick Tag Modal & Recent Tags Hover (Max 50 Characters, No Spaces)**:
   - **Hover `+ Tag` Popover**: Hovering over the `+ Tag` button on any file or note reveals a floating quick-picker directly above the button showing recently used tags for instant 1-click assignment.
   - **Quick Tag Modal**: Click the **"+ Tag"** button to open the full tag manager modal:
     - **Option on Top to Create Tag**: Displays `➕ Create tag: "<name>"` right above the input box (shortcut: **Arrow Up ⬆️**).
     - **Live Filtered List Below Edit Box**: Existing tags are filtered and ranked in real time as you type, placing the nearest match directly below the input box.
     - **Green Highlight & Enter to Select**: If a matching tag is found, the nearest tag below the text box is automatically highlighted in green, so pressing **Enter** selects it immediately.
     - **Keyboard Navigation (↑ / ↓)**: Press **Arrow Up** to highlight the "Create tag" option on top, or **Arrow Down** to navigate the filtered matches list.
     - Enforces up to 50 characters per label and disallows spaces between words (converting whitespace to hyphens).
   - Click any `#tag` badge anywhere in the UI to jump directly to the **Search Tab** filtered by that tag.
7. **JSON Beautify Highlighting & Multi-Language Code Format**:
   - **JSON Format & Syntax Highlighting**: Prettifying JSON automatically formats indentation and syntax-highlights keys, strings, numbers, booleans, and nulls with rich color coding.
   - **Code Format Selector**: Switch code format highlighting on any note across JSON, JavaScript, Python, SQL, Bash, and HTML, or format code inside markdown fenced blocks.
8. **⚙️ Tab 5: Environment Variable Generator (like env.simplestep.ca)**:
   - **Spring Boot App Variable Conversions**:
     - Convert hierarchical **Spring Boot YAML (`application.yml`)** or **Properties (`application.properties`)** to canonical Spring Boot relaxed environment variables.
     - Example:
       ```yaml
       foo-bar:
         baz:
           - value1
           - value2
         enabled: true
       abcDef: value3
       ```
       Converts to Terminal Environment Variables:
       `FOOBAR_BAZ_0_=value1 FOOBAR_BAZ_1_=value2 FOOBAR_ENABLED=true ABCDEF=value3`
     - **Supported Output Formats**:
       - **Terminal Environment Variables** (single-line space-separated)
       - **Multi-line Environment Variables** (`KEY=value`)
       - **Shell Export** (`export KEY="value"`)
       - **Docker Compose Environment** (`- KEY=value`)
       - **Kubernetes ConfigMap** (`apiVersion: v1 ...`)
       - **Spring Boot YAML** & **Properties**
     - **Bidirectional**: Convert from terminal or docker environment variables back into structured Spring Boot YAML.
      - 1-click **Swap Formats**, **Copy Output**, and **Send as Note**.
9. **Live Activity Stream with Collapsible Notes (No Scroll in Scroll)**:
   - Notes in the live activity stream collapse to a uniform, consistent height with a smooth fade gradient and no nested internal scrollbars.
   - Click **"▼ Show more"** or **"▲ Collapse"** to expand and collapse long notes while preserving layout integrity.
10. **Grid vs. Vertical Layout Switcher**:
    - Easily toggle between **⊞ Grid Layout** (side-by-side desktop panels) and **☰ Vertical Layout** (classic stacked single-column flow) via the top header button or Settings modal.
    - Preference is automatically remembered in `localStorage`.
11. **Settings & Appearance Panel (Themes & Center Narrowness Slider)**:
    - Click **⚙️ Settings** in the header to open the configuration panel.
    - **7 Color Themes**: Instant visual theme switching between *Dark Slate*, *Midnight OLED*, *Forest Emerald*, *Cyber Neon*, *Warm Amber*, *Nordic Frost*, and *Clean Light*.
    - **Interactive Side Spacing Slider**: Live drag slider (0px to 360px) that adjusts space on both left and right simultaneously, dynamically pushing wide desktop content into a focused, narrower center column in real time as you drag. Includes a 1-click **Reset** button.
12. **Desktop / Wide-Screen Layout & Large Monospace Workspaces**:
    - Automatically expands container up to 95% / 1560px–1760px on wide desktop screens (`@media (min-width: 992px)`):
      - **Upload tab**: Side-by-side 2-column grid featuring the upload dropzone/queue on the left and the Live Activity Stream on the right (or stacked when in vertical mode).
      - **Notes tab**: Side-by-side 2-column grid featuring a large fixed-size note editor (320px height, monospace) on the left and the saved notes feed on the right.
      - **Env Var tab**: Expansive 480px height side-by-side 2-column grid for source input and converted output with full width utilization.
      - **Files & Search tabs**: Multi-column responsive card grids for efficient browsing.
13. **Search & Label Explorer Tab**:
    - Dedicated **"🔍 Search"** tab to instantly find items across the entire server.
    - **Full-Text Search**: Filter by note title, filename, message body, or `#label`.
    - **Type Filtering**: Filter by `All Items`, `📁 Files`, `📝 Notes`, `🖼️ Images`, or `🎬 Videos`.
    - **Interactive Label Cloud**: Click any tag in the label cloud to filter all associated files, photos, videos, and notes.
14. **Pin Files to Top**:
    - Click the **📌 Pin** button on any file in the Live Stream, Files tab, or Search tab.
    - Pinned files stay persistently anchored on top across all tabs for immediate access.

### Server Options:
| Option | Default | Description |
| :--- | :--- | :--- |
| `--port`, `-p` | `8080` | Port to run on |
| `--dir`, `-d` | `./uploads` | Directory to store uploaded files |
| `--bind`, `-b` | `0.0.0.0` | Bind host address |

---

## 🔍 2. High-Speed Port Scanner (`port_scanner.py`)

A multi-threaded TCP port scanner and port availability checker. Uses Python's standard `concurrent.futures` and `socket` modules (zero third-party dependencies).

### Usage Examples:

1. **Check if a specific port is free or occupied** (e.g. before launching a server):
   ```bash
   python3 port_scanner.py --check 8080
   ```

2. **Scan top common ports on localhost**:
   ```bash
   python3 port_scanner.py
   ```

3. **Scan another device on your LAN** (e.g., your router or phone):
   ```bash
   python3 port_scanner.py 192.168.1.1
   ```

4. **Scan a custom port range** (e.g. 8000 to 9000):
   ```bash
   python3 port_scanner.py --range 8000-9000
   ```

5. **Scan specific ports with service banner grabbing**:
   ```bash
   python3 port_scanner.py -p 22,80,443,3306,8080 --banner
   ```

6. **Adjust concurrency threads and timeout**:
   ```bash
   python3 port_scanner.py --range 1-1024 -t 200 --timeout 0.5
   ```

7. **Export scan results as JSON**:
   ```bash
   python3 port_scanner.py --json > scan_result.json
   ```

### Scanner Options:
| Option | Description |
| :--- | :--- |
| `target` | Target IP or hostname (default: `127.0.0.1`) |
| `--check`, `-c <PORT>` | Quick check if a single port is free or occupied |
| `--ports`, `-p <PORTS>` | Comma-separated list of ports (e.g. `80,443,8080`) |
| `--range`, `-r <START-END>` | Port range to scan (e.g. `8000-8090`) |
| `--all`, `-a` | Scan all 65,535 TCP ports |
| `--threads`, `-t <N>` | Number of concurrent threads (default: `100`) |
| `--timeout <SEC>` | Socket timeout in seconds (default: `0.8`) |
| `--banner`, `-b` | Grab service banners / HTTP headers |
| `--json` | Output results in JSON format |
