import json

with open(r"C:\Projects\cyber-security-awareness-platform\backend\reports\ml\phishing_hybrid_independent_evaluation\compphish_pilot\api_dataset_v4.json", encoding="utf-8") as f:
    data = json.load(f)

print("Name:", data.get("name"))
print("Version:", data.get("version"))
print("DOI:", data.get("doi"))
print("Licence:", data.get("licence"))
print("Description length:", len(data.get("description", "")))

files = data.get("files", [])
print(f"Total files: {len(files)}")
for f in files:
    fname = f.get("filename")
    sz = f.get("size")
    durl = f.get("download_url")
    print(f"  - {fname} | {sz:,} bytes ({sz/(1024*1024):.2f} MB) | {durl}")
