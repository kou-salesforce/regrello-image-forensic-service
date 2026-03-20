from flask import Flask, request, jsonify
import subprocess
import json
import os
import urllib.request

app = Flask(__name__)

@app.route('/verify', methods=['POST'])
def verify():
    path = "forensic_temp.jpg"
    
    # Standard image download logic (same as your GPS tool)
    if 'image' in request.files:
        file = request.files['image']
        file.save(path)
    elif 'image' in request.form:
        try:
            image_data = json.loads(request.form['image'])[0]
            image_url = image_data.get('signedUrl').replace('\\u0026', '&').replace('+', '%2B')
            with urllib.request.urlopen(image_url) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())
        except Exception as e:
            return jsonify({"error": f"Download failed: {str(e)}"}), 400

    # Run ExifTool to check for Software, SceneType, and MakerNotes
    cmd = ["exiftool", "-j", "-Software", "-SceneType", "-MakerNotes", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(path):
        os.remove(path)
    
    metadata = json.loads(result.stdout)[0]
    software = metadata.get('Software', 'Unknown')
    scene = metadata.get('SceneType', 'Unknown')
    
    # Forensic Logic
    flags = []
    trust_score = 100

    # 1. Check for Editing Software (Photoshop, GIMP, etc.)
    if any(x in software.lower() for x in ['adobe', 'photoshop', 'gimp', 'canva', 'ai']):
        trust_score -= 50
        flags.append(f"Edited with: {software}")

    # 2. Check Scene Type (Real cameras tag this as 'Directly photographed')
    if scene != "Directly photographed":
        trust_score -= 30
        flags.append("Digital creation or non-camera source detected")

    # 3. Check for MakerNotes (Metadata created by physical hardware like iPhone 14)
    if 'MakerNotes' not in metadata:
        trust_score -= 20
        flags.append("Missing hardware-specific signatures (MakerNotes)")

    return jsonify({
        "trust_score": max(0, trust_score),
        "is_authentic": trust_score > 70,
        "flags": flags,
        "software": software
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
