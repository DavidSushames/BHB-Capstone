#!/usr/bin/python3
import os
import re
import json
import subprocess
import time
import requests  # Ollama's HTTP API, not the `ollama` CLI

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "gemma4-df"  # verify this tag exists locally: `ollama list`

# Foremost's per-type subfolder convention.
EXT_SUBFOLDER = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpg",
    ".jpeg": "jpg",
    ".gif": "gif",
    ".zip": "zip",
    ".ole": "ole",
}

# --- Tool schemas the model can choose to call during the investigation pass ---
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_pdf_encrypted",
            "description": "Check whether a carved PDF file is password-protected. Provide only the filename as listed in audit.txt.",
            "parameters": {
                "type": "object",
                "properties": {"filename": {"type": "string"}},
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_pdfcrack",
            "description": "Attempt to crack a password-protected PDF using the case wordlist. Provide only the filename as listed in audit.txt.",
            "parameters": {
                "type": "object",
                "properties": {"filename": {"type": "string"}},
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_pdf_text",
            "description": "Extract the text contents of a PDF using a confirmed password from a successful run_pdfcrack call. Use this after cracking a PDF to read what it actually contains, so the report can describe its contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["filename", "password"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_steghide",
            "description": "Attempt to extract hidden data from a carved file using steghide with a confirmed passphrase. IMPORTANT: steghide only supports JPEG, BMP, WAV, and AU files — it does NOT support PDF files. Only call this on .jpg/.jpeg/.bmp/.wav/.au files, never on .pdf files. Provide only the filename as listed in audit.txt, and a password that was actually returned by a successful run_pdfcrack call.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "password": {"type": "string"}
                },
                "required": ["filename", "password"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_extracted_file",
            "description": "Read the contents of a file that was successfully extracted by run_steghide (e.g. a .txt file hidden inside an image), so its contents can be included in the report.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "The filename reported in a successful run_steghide raw_output, e.g. 'Eight.txt'"}
                },
                "required": ["filename"]
            }
        }
    }
]

def resolve_path(output_dir, filename):
    """
    Resolve a bare filename (as it appears in audit.txt) to its real path
    under Foremost's per-type subfolder layout. Returns None if not found.
    This is filesystem plumbing, not forensic interpretation, so the
    harness handles it rather than the model.
    """
    ext = os.path.splitext(filename)[1].lower()
    subfolder = EXT_SUBFOLDER.get(ext)
    candidates = []
    if subfolder:
        candidates.append(os.path.join(output_dir, subfolder, filename))
    candidates.append(os.path.join(output_dir, filename))  # flat-layout fallback
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def parse_files_from_audit(audit_path, output_dir, extension):
    """Locate real paths for filenames of a given extension in audit.txt.
    Used only to let tool calls resolve real paths — the model still reads
    and interprets audit.txt's actual content itself for the report."""
    if not os.path.exists(audit_path):
        raise FileNotFoundError(f"audit.txt not found at {audit_path}")
    pattern = re.compile(rf"\b(\S+\.{extension})\b", re.IGNORECASE)
    results = []
    with open(audit_path, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                filename = match.group(1)
                results.append((filename, resolve_path(output_dir, filename)))
    return results

# --- Real tool implementations. The model names a file; the script resolves it. ---
def check_pdf_encrypted(filename, known_pdfs):
    full_path = known_pdfs.get(filename)
    if not full_path:
        return {"error": f"'{filename}' not found among PDFs listed in audit.txt"}
    result = subprocess.run(["pdfinfo", full_path], capture_output=True, text=True)
    combined = (result.stdout + result.stderr).lower()
    return {"encrypted": "encrypted" in combined or result.returncode != 0}

def run_pdfcrack(filename, wordlist_path, known_pdfs):
    full_path = known_pdfs.get(filename)
    if not full_path:
        return {"error": f"'{filename}' not found among PDFs listed in audit.txt"}
    if not os.path.exists(wordlist_path):
        return {"error": f"wordlist not found: {wordlist_path}"}
    try:
        result = subprocess.run(
            ["pdfcrack", full_path, "-w", wordlist_path],
            capture_output=True, text=True, timeout=600
        )
    except subprocess.TimeoutExpired:
        return {"error": "pdfcrack timed out"}
    except FileNotFoundError:
        return {"error": "pdfcrack binary not found on PATH"}

    output = result.stdout.strip()
    password = None
    if "found user-password" in output.lower():
        try:
            password = output.split("'")[1]
        except IndexError:
            pass
    return {"raw_output": output, "password": password}

def get_pdf_text(filename, password, known_pdfs):
    full_path = known_pdfs.get(filename)
    if not full_path:
        return {"error": f"'{filename}' not found among PDFs listed in audit.txt"}
    try:
        result = subprocess.run(
            ["pdftotext", "-upw", password, full_path, "-"],
            capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        return {"error": "pdftotext timed out"}
    except FileNotFoundError:
        return {"error": "pdftotext binary not found on PATH (install poppler-utils)"}

    if result.returncode != 0:
        return {"error": f"pdftotext failed: {result.stderr.strip()}"}

    text = result.stdout.strip()
    return {"text": text if text else "(PDF decrypted but contains no extractable text)"}

def run_steghide(filename, password, known_files, rep_dir):
    """
    Runs steghide with cwd set to rep_dir, since steghide extracts to the
    current working directory by default (not the source file's directory).
    """
    full_path = known_files.get(filename)
    if not full_path:
        return {"error": f"'{filename}' not found among files listed in audit.txt"}
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
        return {"error": f"steghide does not support {ext} files; skip this file"}
    try:
        result = subprocess.run(
            ["steghide", "extract", "-sf", full_path, "-p", password, "-f"],
            capture_output=True, text=True, timeout=120, cwd=rep_dir
        )
    except subprocess.TimeoutExpired:
        return {"error": "steghide timed out"}
    except FileNotFoundError:
        return {"error": "steghide binary not found on PATH"}

    output = (result.stdout + result.stderr).strip()
    extracted_filename = None
    match = re.search(r'wrote extracted data to "([^"]+)"', output)
    if match:
        extracted_filename = match.group(1)

    return {"raw_output": output, "extracted_filename": extracted_filename}

def read_extracted_file(filename, extracted_files):
    """
    Read a file that steghide actually extracted this session. Only files
    confirmed present in extracted_files (populated from a real run_steghide
    success) can be read — prevents reading arbitrary filesystem paths.
    """
    full_path = extracted_files.get(filename)
    if not full_path:
        return {"error": f"'{filename}' was not extracted by any run_steghide call this session"}
    try:
        with open(full_path, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return {"error": f"could not read '{filename}': {e}"}
    return {"content": content}

def call_ollama(messages, tools=None, think=False):
    payload = {
        "model": MODEL,
        "messages": messages,
        "think": think,
        "stream": False
    }
    if tools:
        payload["tools"] = tools
    resp = requests.post(OLLAMA_URL, json=payload)
    resp.raise_for_status()
    return resp.json()

def get_message_content(response):
    """Extract usable text from a response, falling back to 'thinking' if
    'content' is empty (some models route final text through thinking)."""
    message = response.get("message", {})
    content = message.get("content", "").strip()
    if not content:
        content = message.get("thinking", "").strip()
    return content, message


# --- PASS 1: dedicated inventory call. Short, focused context, no tools,
#     no competing investigation thread — the model's only job is to read
#     audit.txt and produce the inventory-side sections of the report. ---
def run_inventory_pass(audit_text):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a DFIR reporting assistant. You will be given the "
                "complete, unmodified output of Foremost's audit.txt for a "
                "disk image carving operation. Your only job right now is to "
                "read it carefully and produce two report sections, based "
                "strictly on what audit.txt actually contains:\n\n"
                "## Tool Configuration\n"
                "Report Foremost's version, authors, input image name and "
                "size, config file path, and execution timestamp, exactly as "
                "stated in audit.txt's own header. If any of these are not "
                "present in the text you were given, say so explicitly rather "
                "than inventing a value.\n\n"
                "## Forensic Findings\n"
                "A File Type Distribution table covering EVERY file type "
                "listed anywhere in audit.txt, each with its count and a "
                "short description of that file format. Then a Key "
                "Observations subsection noting anything notable in the data "
                "(unusual file sizes, clusters of the same file type at the "
                "same resolution, offsets, etc.).\n\n"
                "Do not omit any file type present in the data. Do not "
                "estimate or round counts — count directly from the text "
                "given to you. Output only these two sections, formatted in "
                "Markdown, nothing else."
            )
        },
        {
            "role": "user",
            "content": f"audit.txt contents:\n{audit_text}"
        }
    ]
    response = call_ollama(messages, tools=None, think=False)
    content, _ = get_message_content(response)
    return content or "ERROR: inventory pass returned no content"


# --- PASS 2: agentic tool-calling investigation. Unchanged in mechanics —
#     the model decides what to check, crack, and extract. ---
def run_investigation_pass(rep_dir, audit_text, max_turns=100):
    output_dir = f"{rep_dir}/output"
    audit_path = f"{output_dir}/audit.txt"
    wordlist_path = f"{rep_dir}/wifite.txt"

    pdf_entries = parse_files_from_audit(audit_path, output_dir, "pdf")
    known_pdfs = {name: path for name, path in pdf_entries if path}
    missing_pdfs = [name for name, path in pdf_entries if not path]

    all_entries = []
    for ext in EXT_SUBFOLDER:
        all_entries.extend(parse_files_from_audit(audit_path, output_dir, ext.lstrip(".")))
    known_files = {name: path for name, path in all_entries if path}

    image_files = [
        name for name in known_files
        if os.path.splitext(name)[1].lower() in (".jpg", ".jpeg", ".bmp", ".wav", ".au")
    ]

    tool_call_log = []
    cracked_passwords = {}
    extracted_files = {}

    pdf_list_str = ", ".join(known_pdfs.keys()) if known_pdfs else "none found"
    image_list_str = ", ".join(image_files) if image_files else "none found"

    messages = [
        {
            "role": "system",
            "content": (
                "You are a DFIR reporting assistant conducting the "
                "investigative portion of a forensic analysis. A separate "
                "inventory of the carved files has already been produced, so "
                "you do not need to re-list file types or counts. Your job "
                "here is to investigate PDF encryption and steganography. "
                "You have tools to check if PDFs are encrypted, crack them "
                "with a wordlist, read decrypted PDF text, check image files "
                "for hidden data with steghide, and read files that steghide "
                "successfully extracts. Refer to files ONLY by the filename "
                "shown in audit.txt — the system resolves the actual file "
                "path for you; do not construct paths yourself. "
                f"PDF files available: {pdf_list_str}. "
                f"Image files eligible for steghide analysis (jpg/bmp/wav/au "
                f"only — steghide does NOT work on PDFs): {image_list_str}. "
                "After successfully cracking a PDF's password, use "
                "get_pdf_text to read its actual contents. If run_steghide "
                "successfully extracts a file, use read_extracted_file to "
                "read its contents. You may only call run_steghide or "
                "get_pdf_text with a password that was actually returned by "
                "a successful run_pdfcrack call earlier in this conversation "
                "— never invent or guess a password. You must attempt "
                "run_steghide on every eligible image file before concluding, "
                "even after finding a successful extraction — do not stop "
                "early. "
                "When finished, write an Investigative Findings section "
                "(full decrypted PDF text and any steghide-recovered content), "
                "a Methodology section listing every tool call you made "
                "including failures, and a Conclusion. Do not include a file "
                "type inventory — that is handled separately. Base every "
                "claim strictly on tool output you actually received."
            )
        },
        {
            "role": "user",
            "content": f"audit.txt contents:\n{audit_text}"
        }
    ]

    if missing_pdfs:
        messages.append({
            "role": "user",
            "content": "Note: these PDFs are listed in audit.txt but not found on disk: " + ", ".join(missing_pdfs)
        })

    for turn in range(max_turns):
        if turn == max_turns - 3:
            messages.append({
                "role": "user",
                "content": (
                    "You have only a few tool-call turns remaining. Finish any "
                    "essential checks now, then write the Investigative "
                    "Findings, Methodology, and Conclusion sections."
                )
            })

        response = call_ollama(messages, tools=TOOLS, think=False)
        message = response["message"]
        messages.append(message)

        tool_calls = message.get("tool_calls")
        if not tool_calls:
            content = message.get("content", "").strip()
            if content:
                return content, tool_call_log

            print(f"DEBUG - investigation pass turn {turn}: empty content, forcing final turn")
            messages.append({
                "role": "user",
                "content": (
                    "Based on everything above, write the Investigative "
                    "Findings, Methodology, and Conclusion sections now."
                )
            })
            final_response = call_ollama(messages, tools=None, think=False)
            content, final_message = get_message_content(final_response)
            print("DEBUG - investigation pass forced final message:", final_message)
            return content or "ERROR: investigation pass returned no content even after forced final turn", tool_call_log

        for call in tool_calls:
            fn_name = call["function"]["name"]
            fn_args = call["function"].get("arguments", {})
            tool_call_log.append({"turn": turn, "tool": fn_name, "args": fn_args})

            if fn_name == "check_pdf_encrypted":
                result = check_pdf_encrypted(fn_args.get("filename"), known_pdfs)

            elif fn_name == "run_pdfcrack":
                result = run_pdfcrack(fn_args.get("filename"), wordlist_path, known_pdfs)
                if result.get("password"):
                    cracked_passwords[fn_args.get("filename")] = result["password"]

            elif fn_name == "get_pdf_text":
                requested_password = fn_args.get("password")
                filename = fn_args.get("filename")
                if requested_password not in cracked_passwords.values():
                    result = {"error": f"Rejected: password '{requested_password}' was not returned by a successful run_pdfcrack call this session."}
                else:
                    result = get_pdf_text(filename, requested_password, known_pdfs)

            elif fn_name == "run_steghide":
                requested_password = fn_args.get("password")
                filename = fn_args.get("filename")
                if requested_password not in cracked_passwords.values():
                    result = {"error": f"Rejected: password '{requested_password}' was not returned by a successful run_pdfcrack call this session."}
                else:
                    result = run_steghide(filename, requested_password, known_files, rep_dir)
                    if result.get("extracted_filename"):
                        extracted_files[result["extracted_filename"]] = os.path.join(rep_dir, result["extracted_filename"])

            elif fn_name == "read_extracted_file":
                result = read_extracted_file(fn_args.get("filename"), extracted_files)

            else:
                result = {"error": f"unknown tool requested: {fn_name}"}

            tool_call_log[-1]["result"] = result
            messages.append({"role": "tool", "content": json.dumps(result)})

    return "ERROR: max turns reached without final report", tool_call_log


# --- PASS 3: combine the two AI-generated pieces into one finished report.
#     Still an AI call, not string concatenation in Python — the model does
#     the actual assembly, formatting, cover page, and executive summary. ---
def run_combine_pass(inventory_section, investigation_section):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a DFIR reporting assistant. You are given two "
                "report sections that were produced separately: an "
                "inventory section (Tool Configuration + Forensic Findings) "
                "and an investigative section (Investigative Findings + "
                "Methodology + Conclusion). Combine them into a single, "
                "polished forensic report. Add a cover page (case title, "
                "date, author: 'DFIR Reporting Assistant') and an Executive "
                "Summary at the top. Preserve all factual content from both "
                "sections exactly as given — do not drop, summarize away, "
                "or alter any file counts, tool results, passwords, or "
                "extracted content. Order the sections as: Cover Page, "
                "Executive Summary, Tool Configuration, Forensic Findings, "
                "Investigative Findings, Methodology, Conclusion."
            )
        },
        {
            "role": "user",
            "content": (
                f"--- Inventory section ---\n{inventory_section}\n\n"
                f"--- Investigative section ---\n{investigation_section}"
            )
        }
    ]
    response = call_ollama(messages, tools=None, think=False)
    content, _ = get_message_content(response)
    return content or "ERROR: combine pass returned no content"


startTime = time.perf_counter()

print(" ")
print("WELCOME TO TENMOST")
print(" ")
print("The premier in file carving analysis. Now with Cryptography!")
print(" ")

repDir = os.getcwd()
auditPath = f"{repDir}/output/audit.txt"

with open(auditPath, "r") as f:
    auditText = f.read()

print("Running inventory pass...")
inventory_section = run_inventory_pass(auditText)

print("Running investigation pass...")
investigation_section, tool_log = run_investigation_pass(repDir, auditText, max_turns=100)

print("Running combine pass...")
final_report = run_combine_pass(inventory_section, investigation_section)

with open(f"{repDir}/AI_Report.txt", "w") as f:
    f.write(final_report)

with open(f"{repDir}/tool_call_log.json", "w") as f:
    json.dump(tool_log, f, indent=2)

print(" ")
print(f"Report generated in {repDir}/AI_Report.txt")
print(f"Tool call log in {repDir}/tool_call_log.json")
print(" ")

endTime = time.perf_counter()
procTime = endTime - startTime
print(f"Report created in {procTime:.2f} seconds")
