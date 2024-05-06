from flask import Flask, render_template, request
import requests
import sys
from time import sleep
import logging
import os

app = Flask(__name__)
# Configure logging
logging.basicConfig(level=logging.DEBUG)

def print_slow(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def scan_file(file_data, api_key):
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {"apikey": api_key}

    try:
        files = {'file': file_data}
        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            file_id = response.json()['resource']
            return file_id
        else:
            logging.error(f"Error uploading file: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error: {e}")
        return None

def get_report(file_id, api_key):
    if file_id:
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": api_key, "resource": file_id}

        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                report = response.json()
                # Ensure 'scans' attribute exists
                if 'scans' not in report:
                    report['scans'] = {}
                return report
            else:
                logging.error(f"Error retrieving report: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Error retrieving report: {e}")
            return None
    else:
        return None

def create_folder(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        logging.debug(f"Received file: {file.filename}")

        if file.filename == '':
            return "No selected file"

        # File size validation
        max_file_size_mb = 5  # Max file size in MB
        if 'file' not in request.files:
            return "No file part"
        if file and file.filename.endswith('.pdf'):
            file_content = file.read()  # Store file content
            file.seek(0)  # Reset file cursor
            file_size_mb = len(file_content) / (1024 * 1024)  # Converting bytes to MB
            if file_size_mb > max_file_size_mb:
                return "File size exceeds the limit (5MB)"
        else:
            return "Invalid file format. Only PDF files are allowed."

        api_key = "00dd05020a99baef64f164b8989ff918cd8c90fc5228bfe80c3cf368612f207a"  # Replace with your actual VirusTotal API key

        file_id = scan_file(file_content, api_key)  # Pass file_content instead of file
        if file_id:
            print_slow("Analyzing...\n")
            report = get_report(file_id, api_key)
            if report:
                logging.debug("Report retrieved successfully")
                if report['positives'] == 0:  # File is secure
                    secure_folder = os.path.join(os.path.dirname(__file__), 'secure_files')
                    create_folder(secure_folder)
                    secure_file_path = os.path.join(secure_folder, file.filename)
                    with open(secure_file_path, 'wb') as secure_file:  # Open file in binary mode
                        secure_file.write(file_content)  # Write file content
                    # Rendering template with scanning details
                    return render_template('result.html', result="File scanned and stored securely.", details=report)
                else:
                    # Rendering template with scanning details
                    return render_template('result.html', result="File contains malware, not stored.", details=report)
            else:
                logging.error("Failed to retrieve report")
                return "Failed to retrieve report. Please try again later."
        else:
            logging.error("Scan failed")
            return "Scan failed. Please check the file and try again."

    return render_template('Vishwakarma.html')




if __name__ == "__main__":
    app.run(debug=True)
