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
        "flags": ["Missing Metadata"],
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
            with urllib.request.urlopen(image_url, timeout=15) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())

        if os.path.exists(path):
            # Extract 'Photo DNA' (Exposure/Aperture) to verify real iPhone shots
            cmd = ["exiftool", "-j", "-m", "-Software", "-Model", "-MakerNotes", 
                   "-ExposureTime", "-FNumber", "-ISO", path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout.strip():
                metadata = json.loads(result.stdout)[0]
                software = metadata.get('Software', 'Unknown')
                model = metadata.get('Model', 'Unknown')
                
                # Check for physical camera settings (Photo DNA)
                has_photo_dna = any(metadata.get(tag) for tag in ['ExposureTime', 'FNumber', 'ISO'])
                
                flags = []
                trust_score = 100

                # 1. Screenshot Check: No Camera Model = 0 Score
                if model == "Unknown":
                    trust_score = 0
                    flags.append("Missing Camera Hardware ID (Screenshot detected)")
                
                # 2. Editing Software Check
                if any(x in software.lower() for x in ['adobe', 'photoshop', 'canva']):
                    trust_score -= 60
                    flags.append(f"Software: {software}")
                
                # 3. Hardware Fingerprint (Waived if Photo DNA is found)
                if 'MakerNotes' not in metadata and not has_photo_dna:
                    trust_score -= 30
                    flags.append("Missing hardware signatures")
                elif has_photo_dna:
                    flags.append("Verified Hardware Metadata (Exposure/Aperture confirmed)")

                response_data.update({
                    "trust_score": max(0, trust_score),
                    "is_authentic": trust_score >= 90,
                    "flags": flags,
                    "software_detected": software,
                    "camera_model": model
                })

    except Exception as e:
        print(f"Forensic Error: {e}")

    if os.path.exists(path):
        os.remove(path)
    return jsonify(response_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
