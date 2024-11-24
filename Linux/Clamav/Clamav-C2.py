import pyclamd
import csv
import hashlib
import magic
import time, os, sys
import subprocess

# Initialize ClamAV
cd = pyclamd.ClamdUnixSocket()

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_type(file_path):
    file_type = magic.from_file(file_path, mime=True)
    return file_type

# Function to check if ClamAV is installed
def check_clamav_installed():
    try:
        version_info = subprocess.check_output(['clamscan', '--version']).decode().strip()
        return version_info
    except FileNotFoundError:
        return None

# Function to get ClamAV database information
def get_clamav_db_info():
    try:
        db_info = subprocess.check_output(['sigtool', '--version']).decode().strip()
        return db_info
    except FileNotFoundError:
        return None

def scan_file(file_path):
    try:
        result = cd.scan_file(file_path)
        if result is None:
            return 0  # benign
        else:
            return 1  # malicious
    except Exception as e:
        return f'error: {e}'

def scan_save_to_csv(in_dir, out_name):
    # Check if ClamAV is installed
    clamav_version = check_clamav_installed()
    if clamav_version is None:
        print("ClamAV is not installed.\nPlease install ClamAV and try again.")
        exit(1)

    # Get ClamAV database information
    clamav_db_info = get_clamav_db_info()

    # Open CSV file to write results
    with open(out_name, mode='w', newline='') as csv_file:
        fieldnames = ['file_path', 'file_name', 'sha256', 'file_type', 'is_malware', 'clamav_version', 'clamav_db']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)        
        writer.writeheader()

        for root, dirs, files in os.walk(in_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                sha256 = calculate_sha256(file_path)
                file_type = get_file_type(file_path)
                is_malware = scan_file(file_path)

                writer.writerow({'file_path': file_path, 
                                 'file_name': filename, 
                                 'sha256': sha256, 
                                 'file_type': file_type,
                                 'is_malware': is_malware,
                                 'clamav_version': clamav_version,
                                 'clamav_db': clamav_db_info})

def main(in_dir, out_name):
    scan_save_to_csv(in_dir, out_name)        

if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    # Check if a parameter is provided
    if len(sys.argv) == 3 :
        in_dir = sys.argv[1]
        if not os.path.exists(in_dir):
            print(f"Directory: '{in_dir}' does not exist.")
            exit()         
        print(f"\n\nBinary Directory:\t{in_dir}")

        out_name = sys.argv[2]

        print(f"CSV File will save:\t{out_name}")
        main(in_dir, out_name)
        print(f"Scanning complete. Results saved in {out_name}")
    else:
        print("No input directory and output csv filename provided.")