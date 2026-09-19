#!/usr/bin/python3

import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime, timezone


# --------------------------------------------------
# Configuration
# --------------------------------------------------

OUTPUT_DIR = "Sixmost"
HASH_ALGORITHM = "sha256"


# --------------------------------------------------
# Evidence hashing
# --------------------------------------------------

def calculate_hash(file_path):
    """Calculate a SHA-256 hash of a recovered file."""
    file_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            file_hash.update(chunk)

    return file_hash.hexdigest()


def save_hash_to_file(recovered_file):
    """Calculate and store the hash of a recovered file."""
    file_path = os.path.join(OUTPUT_DIR, recovered_file)
    hash_of_file = calculate_hash(file_path)

    with open(os.path.join(OUTPUT_DIR, "hash.txt"), "a",
              encoding="utf-8") as hash_file:
        hash_file.write(f"{recovered_file}:\n")
        hash_file.write(f"{hash_of_file}\n\n")

    return hash_of_file


# --------------------------------------------------
# Carved-file evidence records
# --------------------------------------------------

def save_evidence_record(file_name, file_type, start_offset,
                         end_offset, file_size, file_hash):
    """Store structured information about a recovered file."""

    record = {
        "file_name": file_name,
        "file_type": file_type,
        "file_size_bytes": file_size,
        "start_offset": start_offset,
        "end_offset": end_offset,
        "sha256": file_hash,
        "recovery_timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat()
    }

    evidence_path = os.path.join(OUTPUT_DIR, "carved_files.json")

    # Read existing records if the file exists.
    if os.path.exists(evidence_path):
        with open(evidence_path, "r", encoding="utf-8") as f:
            records = json.load(f)
    else:
        records = []

    records.append(record)

    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)


# --------------------------------------------------
# File carving
# --------------------------------------------------

def detect_files(data, file_name, sof, eof,
                 sof_mem_bytes, eof_mem_bytes, output_file_type):

    with open(file_name, "rb") as binary_file:
        binary_file.read(1)

    sof_stack = []
    memory_counter = 0

    while memory_counter < len(data):

        probable_sof = data[
            memory_counter:memory_counter + sof_mem_bytes
        ]

        probable_eof = data[
            memory_counter:memory_counter + eof_mem_bytes
        ]

        if probable_sof == sof:
            sof_stack.append(memory_counter)

        if probable_eof == eof:

            if sof_stack and sof_stack[-1] < memory_counter:

                start_offset = sof_stack[-1]
                end_offset = memory_counter + eof_mem_bytes

                file_data = data[start_offset:end_offset]

                recovered_file_name = (
                    f"Recovered_{start_offset}_{end_offset}."
                    f"{output_file_type}"
                )

                recovered_file_path = os.path.join(
                    OUTPUT_DIR, recovered_file_name
                )

                with open(recovered_file_path, "wb") as recovered_file:
                    recovered_file.write(file_data)

                file_size = os.path.getsize(recovered_file_path)

                file_hash = save_hash_to_file(
                    recovered_file_name
                )

                save_evidence_record(
                    recovered_file_name,
                    output_file_type,
                    start_offset,
                    end_offset,
                    file_size,
                    file_hash
                )

                sof_stack.pop()

                print(
                    f"Carved file: {recovered_file_name} | "
                    f"Type: {output_file_type} | "
                    f"Size: {file_size} bytes | "
                    f"Offset: {start_offset}"
                )

        memory_counter += 1


# --------------------------------------------------
# File signatures
# --------------------------------------------------

def detect_pdf_files(data, file_name):
    sof = b'\x25\x50\x44\x46'
    eof_variety = {
        b'\x0A\x25\x25\x45\x4F\x46': 6,
        b'\x0A\x25\x25\x45\x4F\x46\x0A': 7,
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A': 9,
        b'\x0D\x25\x25\x45\x4F\x46\x0D': 7
    }

    for eof, eof_mem_bytes in eof_variety.items():
        detect_files(
            data, file_name, sof, eof,
            4, eof_mem_bytes, "pdf"
        )


def detect_png_files(data, file_name):
    detect_files(
        data, file_name,
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
        8, 8, "png"
    )


def detect_docx_files(data, file_name):
    detect_files(
        data, file_name,
        b'\x50\x4B\x03\x04\x14\x00\x06\x00',
        b'\x50\x4B\x05\x06',
        8, 4, "docx"
    )


def detect_jpeg_files(data, file_name):
    detect_files(
        data, file_name,
        b'\xff\xd8\xff',
        b'\xff\xd9',
        3, 2, "jpg"
    )


# --------------------------------------------------
# Read evidence image
# --------------------------------------------------

def read_file(file_name):
    if not os.path.isfile(file_name):
        print("File not found")
        sys.exit(1)

    with open(file_name, "rb") as binary_file:
        return binary_file.read()


# --------------------------------------------------
# Generate AI forensic report
# --------------------------------------------------

def generate_forensic_report():
    """Send structured carved-file records to Ollama."""

    evidence_path = os.path.join(
        OUTPUT_DIR, "carved_files.json"
    )

    report_path = os.path.join(
        OUTPUT_DIR, "forensic_report.txt"
    )

    if not os.path.exists(evidence_path):
        print("No carved-file evidence records found.")
        return

    with open(evidence_path, "r", encoding="utf-8") as f:
        evidence = json.load(f)

    prompt = """You are a digital forensics reporting assistant.

Generate a professional forensic summary of the carved files listed
below.

The report must include:

1. Examination overview
2. Total number of recovered files
3. A separate record for EVERY recovered file
4. File name and type
5. File size
6. Recovery offset
7. SHA-256 hash
8. Recovery timestamp, if available
9. Any relevant limitations
10. A concise conclusion

Important rules:
- Do not invent missing information.
- Do not omit recovered files.
- Do not combine multiple files into one record.
- Do not claim that carving proves deletion, ownership, or authorship.
- Distinguish recovery timestamps from file metadata timestamps.
- If metadata is unavailable, say so.
- Use factual, objective forensic language.
- Do not describe the contents of a file unless that information is
  actually present in the supplied evidence records.

Carved-file evidence records:
""" + json.dumps(evidence, indent=4)

    print("Generating forensic report with Ollama...")

    result = subprocess.run(
        [
            "ollama",
            "run",
            "gemma4:26b",
            "--think=false",
            prompt
        ],
        capture_output=True,
        text=True,
        check=True
    )

    with open(report_path, "a", encoding="utf-8") as report:
        report.write("\n")
        report.write("=" * 70 + "\n")
        report.write("FORENSIC REPORT\n")
        report.write("=" * 70 + "\n")
        report.write(result.stdout)
        report.write("\n")

    print(f"Forensic report saved to: {report_path}")


# --------------------------------------------------
# Main
# --------------------------------------------------

def take_input():

    if len(sys.argv) < 2:
        print("Usage: python3 Sixmost.py <evidence_image>")
        sys.exit(1)

    file_name = sys.argv[1]

    if not os.path.isdir(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)

    data = read_file(file_name)

    print("Starting file carving...")

    detect_png_files(data, file_name)
    detect_jpeg_files(data, file_name)
    detect_pdf_files(data, file_name)
    detect_docx_files(data, file_name)

    print("File carving complete.")

    generate_forensic_report()


if __name__ == "__main__":
    take_input()
