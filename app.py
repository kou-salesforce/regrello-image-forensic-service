from flask import Flask, request, jsonify
import subprocess
import json
import os
import urllib.request

app = Flask(__name__)

@app.route('/verify', methods=['POST'])
def verify():
    path = "forensic_temp.jpg"
    response_data = {
        "trust_score": 0,
        "is_authentic": False,
        "flags": ["Missing Camera Metadata"],
        "software_detected": "Unknown",
        "camera_model": "Unknown"
    }

    try:
        if 'image' in request.files:
            file = request.files['image']
            file.save(path)
        elif 'image' in request.form:
            image_data = json.loads(request.form['image'])[0]
            image_url = image_data.get('signedUrl').replace('\\u0026', '&').replace('+', '%2B').replace(' ', '%20')
            with urllib.request.urlopen(image_url, timeout=10) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())

        if os.path.exists(path):
            # Photo DNA: Proof of physical light capture (Exposure, F-Stop, ISO)
            cmd = ["exiftool", "-j", "-m", "-Software", "-Model", "-MakerNotes", 
                   "-ExposureTime", "-FNumber", "-ISO", path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout.strip():
                metadata = json.loads(result.stdout)[0]
                software = metadata.get('Software', 'Unknown')
                model = metadata.get('Model', 'Unknown')
                has_photo_dna = any(metadata.get(tag) for tag in ['ExposureTime', 'FNumber', 'ISO'])
                
                flags = []
                trust_score = 100

                # Screenshot Detection: If no Camera Model, score is 0
                if model == "Unknown":
                    trust_score = 0
                    flags.append("Missing Camera Hardware ID (Screenshot detected)")
                
                # Editing Check
                if any(x in software.lower() for x in ['adobe', 'photoshop', 'canva']):
                    trust_score -= 60
                    flags.append(f"Software Fingerprint: {software}")
                
                # Hardware Fingerprint Check
                if 'MakerNotes' not in metadata and not has_photo_dna:
                    trust_score -= 30
                    flags.append("Missing proprietary hardware signatures")
                elif has_photo_dna:
                    flags.append("Verified Hardware Metadata (Photo DNA confirmed)")

                response_data.update({
                    "trust_score": max(0, trust_score),
                    "is_authentic": trust_score >= 90,
                    "flags": flags,
                    "software_detected": software,
                    "camera_model": model
                })

    except Exception as e:
        print(f"Forensic Error: {e}")

    finally:
        if os.path.exists(path):
            os.remove(path)
        return jsonify(response_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
