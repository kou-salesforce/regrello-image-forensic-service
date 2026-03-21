# ... (imports remain the same) ...

@app.route('/verify', methods=['POST'])
def verify():
    path = "forensic_temp.jpg"
    # ... (download logic remains the same) ...

    cmd = ["exiftool", "-j", "-m", "-Software", "-SceneType", "-MakerNotes", "-History", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(path):
        os.remove(path)
    
    exif_results = json.loads(result.stdout)
    
    # DEFAULT VALUES: Prevents Regrello "nil" errors
    response = {
        "trust_score": 0,
        "is_authentic": False,
        "flags": ["No forensic metadata found to analyze"],
        "software_detected": "None",
        "scene_type": "Unknown"
    }

    if exif_results and len(exif_results) > 0:
        metadata = exif_results[0]
        software = metadata.get('Software', 'Unknown')
        scene = metadata.get('SceneType', 'Unknown')
        
        flags = []
        trust_score = 100

        # If we actually found metadata, perform the logic
        if not any(k in metadata for k in ['Software', 'MakerNotes', 'SceneType']):
            flags.append("Insufficient metadata for forensic audit")
            trust_score = 0
        else:
            if any(x in software.lower() for x in ['adobe', 'photoshop', 'gimp', 'canva', 'ai']):
                trust_score -= 50
                flags.append(f"Software Fingerprint: {software}")
            
            if 'MakerNotes' not in metadata:
                trust_score -= 20
                flags.append("Missing hardware-specific signatures")

        response.update({
            "trust_score": max(0, trust_score),
            "is_authentic": trust_score >= 80,
            "flags": flags if flags else ["Metadata Present & Verified"],
            "software_detected": software,
            "scene_type": scene
        })

    return jsonify(response)
