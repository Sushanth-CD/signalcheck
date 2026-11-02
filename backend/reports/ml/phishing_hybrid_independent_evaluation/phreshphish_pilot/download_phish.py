from huggingface_hub import hf_hub_download
import shutil
import os

try:
    path = hf_hub_download(
        repo_id='phreshphish/phreshphish',
        filename='benchmark/phish.txt',
        repo_type='dataset'
    )
    dest = r'C:\Projects\cyber-security-awareness-platform\backend\reports\ml\phishing_hybrid_independent_evaluation\phreshphish_pilot\phish.txt'
    shutil.copyfile(path, dest)
    print('HF Hub Download Success! Size:', os.path.getsize(dest))
except Exception as e:
    print('HF Hub Error:', e)
