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
            
            # CRITICAL FIX: Encode spaces and special characters in the URL
            image_url = image_url.replace('\\u0026', '&').replace('+', '%2B').replace(' ', '%20')
            
            with urllib.request.urlopen(image_url) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())
        except Exception as e:
            return jsonify({"error": f"Download failed: {str(e)}"}), 400
    else:
        return jsonify({"error": "No image data found"}), 400

    # 2. Run ExifTool Forensic Scan
    # '-m' ignores minor formatting errors (essential for iPhone 14)
    cmd = ["exiftool", "-j", "-m", "-Software", "-SceneType", "-MakerNotes", "-History", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Cleanup temp file immediately
    if os.path.exists(path):
        os.remove(path)
    
    # 3. Analyze Results
    metadata = json.loads(result.stdout)[0]
    software = metadata.get('Software', 'Unknown')
    scene = metadata.get('SceneType', 'Unknown')
    history = metadata.get('History', '')
    
    flags = []
    trust_score = 100

    # FLAG: Editing Software Detected
    if any(x in software.lower() for x in ['adobe', 'photoshop', 'gimp', 'canva', 'ai', 'midjourney']):
        trust_score -= 50
        flags.append(f"Software Fingerprint: {software}")

    # FLAG: Digital Origin (Non-Camera)
    if scene != "Directly photographed" and scene != "Unknown":
        trust_score -= 30
        flags.append(f"Non-camera source detected: {scene}")

    # FLAG: Missing Hardware Signatures (iPhone Fix)
    if 'MakerNotes' not in metadata:
        trust_score -= 20
        flags.append("Missing hardware-specific signatures (MakerNotes)")

    # FLAG: Edit History Found
    if history:
        trust_score -= 10
        flags.append("Internal edit history detected in metadata")

    return jsonify({
        "trust_score": max(0, trust_score),
        "is_authentic": trust_score >= 80,
        "flags": flags,
        "software_detected": software,
        "scene_type": scene
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
