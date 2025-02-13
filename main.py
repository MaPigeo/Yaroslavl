import os
import zipfile
import subprocess
import tempfile
from datetime import datetime
import json

def disassemble_jar(jar_path, json_patterns_path):

    if not os.path.exists(jar_path):
        print(f"[ERROR] JAR file not found: {jar_path}")
        return
    if not zipfile.is_zipfile(jar_path):
        print(f"[ERROR] Invalid JAR file: {jar_path}")
        return

    if not os.path.exists(json_patterns_path):
        print(f"[ERROR] Pattern JSON file not found: {json_patterns_path}")
        return

    try:
        with open(json_patterns_path, "r", encoding="utf-8") as f:
            patterns = json.load(f)  # Expect a list of dicts
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse JSON patterns: {e}")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_folder = f"disassembly_{timestamp}"
    os.makedirs(output_folder, exist_ok=True)

    summary_file = os.path.join(output_folder, "pattern_matches_summary.txt")

    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            jar.extractall(temp_dir)

        for root, _, files in os.walk(temp_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                if file_name.endswith(".class"):
                    rel_class_path = os.path.relpath(file_path, temp_dir)
                    class_name = rel_class_path.replace(os.sep, '.').replace('.class', '')

                    try:
                        result = subprocess.run(
                            ["javap", "-c", "-p", "-verbose", class_name],
                            cwd=temp_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                    except FileNotFoundError:
                        print("[ERROR] 'javap' command not found. Install JDK & ensure it's in PATH.")
                        return

                    disassembly_txt = os.path.join(output_folder, f"{class_name}.txt")
                    with open(disassembly_txt, "w", encoding="utf-8") as out_f:
                        out_f.write(result.stdout)

                    if result.stderr:
                        print(f"[WARNING] javap error for {class_name}:\n{result.stderr}")

                    disassembly_str = result.stdout
                    for p in patterns:
                        pattern_str = p.get("pattern", "")
                        risk_level  = p.get("riskLevel", "Unknown")
                        pattern_type = p.get("type", "")
                        pattern_text = p.get("text", "")

                        if pattern_str and (pattern_str in disassembly_str):
                            summary_data = {
                                "fileName": class_name,
                                "pattern": pattern_str,
                                "riskLevel": risk_level,
                                "type": pattern_type,
                                "text": pattern_text
                            }
                            print("******** - http requests - ")
                            print(summary_data)

                            with open(summary_file, "a", encoding="utf-8") as sf:
                                sf.write(f"Class Name: {class_name}\n")
                                sf.write(f"Pattern: {pattern_str}\n")
                                sf.write(f"Risk Level: {risk_level}\n")
                                sf.write(f"Type: {pattern_type}\n")
                                sf.write(f"Text: {pattern_text}\n")
                                sf.write("=" * 80 + "\n\n")

                else:
                    with open(file_path, "rb") as asset_f:
                        raw_content = asset_f.read()

                    for p in patterns:
                        pattern_str = p.get("pattern", "")
                        risk_level  = p.get("riskLevel", "Unknown")
                        pattern_type = p.get("type", "")
                        pattern_text = p.get("text", "")

                        if pattern_str:
                            pattern_bytes = pattern_str.encode("utf-8")

                            if pattern_bytes in raw_content:
                                summary_data = {
                                    "fileName": file_path,
                                    "pattern": pattern_str,
                                    "riskLevel": risk_level,
                                    "type": pattern_type,
                                    "text": pattern_text
                                }
                                print("******** - http requests - ")
                                print(summary_data)

                                with open(summary_file, "a", encoding="utf-8") as sf:
                                    sf.write("******** - http requests - \n")
                                    sf.write(f"Asset File: {file_path}\n")
                                    sf.write(f"Pattern: {pattern_str}\n")
                                    sf.write(f"Risk Level: {risk_level}\n")
                                    sf.write(f"Type: {pattern_type}\n")
                                    sf.write(f"Text: {pattern_text}\n")
                                    sf.write("=" * 80 + "\n\n")


if __name__ == "__main__":
    jar_path = r"D:\newTry\newTry\cyberbez\ash-ora1.jar"
    json_patterns_path = r"D:\newTry\newTry\cyberbez\patterns.json"
    disassemble_jar(jar_path, json_patterns_path)
