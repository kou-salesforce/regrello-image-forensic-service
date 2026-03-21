from flask import Flask, request, jsonify
import subprocess
import json
import os
import urllib.request

app = Flask(__name__)

@app.route('/verify', methods=['POST'])
def verify():
    path = "forensic_temp.jpg"
    
    # 1. Image Download Logic
    if 'image' in request.files:
        file = request.files['image']
        file.save(path)
    elif 'image' in request.form:
        try:
            image_data = json.loads(request.form['image'])[0]
            image_url = image_data.get('signedUrl')
            
            # Fix: Encode spaces and special characters in the URL
            image_url = image_url.replace('\\u0026', '&').replace('+', '%2B').replace(' ', '%20')
            
            with urllib.request.urlopen(image_url) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())
        except Exception as e:
            return jsonify({"error": f"Download failed: {str(e)}"}), 400
    else:
        return jsonify({"trust_score": 0, "is_authentic": False, "flags": ["No image found"]}), 400

    # 2. Run ExifTool Forensic Scan
    # Adding -Model to the scan to differentiate hardware from screenshots
    cmd = ["exiftool", "-j", "-m", "-Software", "-Model", "-MakerNotes", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(path):
        os.remove(path)
    
    exif_results = json.loads(result.stdout)
    
    # Default values for empty/failed scans
    response = {
        "trust_score": 0,
        "is_authentic": False,
        "flags": ["No forensic metadata found to analyze"],
        "software_detected": "None",
        "camera_model": "Unknown"
    }

    if exif_results and len(exif_results) > 0:
        metadata = exif_results[0]
        software = metadata.get('Software', 'Unknown')
        model = metadata.get('Model', 'Unknown')
        
        flags = []
        trust_score = 100

        # PENALTY 1: Editing Software Detected (e.g., Photoshop, Canva)
        if any(x in software.lower() for x in ['adobe', 'photoshop', 'gimp', 'canva', 'ai']):
            trust_score -= 60
            flags.append(f"Software Fingerprint: {software}")

        # PENALTY 2: Missing Camera Model (Screenshots/Graphics have no Model)
        if model == "Unknown":
            trust_score -= 40
            flags.append("Missing Camera Hardware ID (Screenshot or digital export)")

        # PENALTY 3: Missing MakerNotes (The unique hardware "handshake")
        if 'MakerNotes' not in metadata:
            trust_score -= 30
            flags.append("Missing proprietary hardware signatures")

        # Threshold set to 90: Only untouched camera photos will pass
        response.update({
            "trust_score": max(0, trust_score),
            "is_authentic": trust_score >= 90,
            "flags": flags if flags else ["Metadata Verified Original"],
            "software_detected": software,
            "camera_model": model
        })

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
