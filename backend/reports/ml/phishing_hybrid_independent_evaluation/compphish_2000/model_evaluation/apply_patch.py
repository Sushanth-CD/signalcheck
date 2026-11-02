import sys
from pathlib import Path

target_file = Path(r"C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/run_preflight_and_evaluation.py")
text = target_file.read_text(encoding="utf-8")

old_func_start = "def load_all_corpus_html(manifest_df: pd.DataFrame) -> list[bytes]:"
idx_start = text.find(old_func_start)
if idx_start != -1:
    idx_end = text.find("def compute_file_sha256", idx_start)
    new_func = """def load_all_corpus_html(manifest_df: pd.DataFrame) -> list[bytes]:
    print("Loading 2,000 HTML samples concurrently from official archive via HTTP Range requests...", flush=True)
    zip_members = load_zip_index()
    loaded_bytes: list[bytes | None] = [None] * len(manifest_df)
    items = [(i, row["serial_number"], row["raw_html_sha256"]) for i, (_, row) in enumerate(manifest_df.iterrows())]

    def fetch_worker(it):
        i, s, expected_sha = it
        ze = zip_members[f"All_HTML/{s}.txt"]
        raw_b = fetch_s3_member(ze)
        return i, raw_b

    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=30) as executor:
        futs = [executor.submit(fetch_worker, it) for it in items]
        for f in as_completed(futs):
            i, raw_b = f.result()
            loaded_bytes[i] = raw_b
            done += 1
            if done % 500 == 0:
                elapsed = time.time() - t0
                print(f"  [{done}/2000] HTML samples retrieved in-memory in {elapsed:.1f}s...", flush=True)

    elapsed_total = time.time() - t0
    print(f"Retrieved and loaded all {len(loaded_bytes)} HTML byte arrays into memory in {elapsed_total:.2f}s.", flush=True)
    return loaded_bytes


"""
    text = text[:idx_start] + new_func + text[idx_end:]
    target_file.write_text(text, encoding="utf-8")
    print("Updated load_all_corpus_html successfully!")
else:
    print("old_func_start not found!")
