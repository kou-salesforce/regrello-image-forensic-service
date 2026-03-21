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
            
            # Encode spaces and special characters
            image_url = image_url.replace('\\u0026', '&').replace('+', '%2B').replace(' ', '%20')
            
            with urllib.request.urlopen(image_url) as response, open(path, 'wb') as out_file:
                out_file.write(response.read())
        except Exception as e:
            return jsonify({"error": f"Download failed: {str(e)}"}), 400
    else:
        # Return default 0 score if no image is found to prevent Regrello errors
        return jsonify({"trust_score": 0, "is_authentic": False, "flags": ["No image found"]}), 400

    # 2. Run ExifTool Forensic Scan (-m ignores minor iPhone errors)
    cmd = ["exiftool", "-j", "-m", "-Software", "-SceneType", "-MakerNotes", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(path):
        os.remove(path)
    
    exif_results = json.loads(result.stdout)
    
    # DEFAULT VALUES: Ensure these always exist to prevent Regrello "nil" errors
    response = {
        "trust_score": 0,
        "is_authentic": False,
        "flags": ["No forensic metadata found to analyze"],
        "software_detected": "None"
    }

    if exif_results and len(exif_results) > 0:
        metadata = exif_results[0]
        software = metadata.get('Software', 'Unknown')
        
        flags = []
        trust_score = 100

        # Check for Editing Software
        if any(x in software.lower() for x in ['adobe', 'photoshop', 'gimp', 'canva', 'ai']):
            trust_score -= 50
            flags.append(f"Software Fingerprint: {software}")

        # Check for MakerNotes (iPhone Signature)
        if 'MakerNotes' not in metadata:
            trust_score -= 20
            flags.append("Missing hardware-specific signatures")

        response.update({
            "trust_score": max(0, trust_score),
            "is_authentic": trust_score >= 80,
            "flags": flags if flags else ["Metadata Verified"],
            "software_detected": software
        })

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
