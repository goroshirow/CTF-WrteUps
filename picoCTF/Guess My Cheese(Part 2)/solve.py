import hashlib
import binascii

# --- 設定 ---
hash_target = "7c54a826acea5702a4b7d37ff434231a7228c3f16a4ed969ad24b07e2fe6286b"
wordlist_file = "cheese_list.txt"
# Write-upに基づき、最も可能性の高いエンコーディングとバリエーションを試す
ENCODINGS = ['utf-8', 'ascii', 'latin-1'] 

def compute_sha256(input: bytes) -> str:
    """バイト列を入力としてSHA-256ハッシュを計算し、16進数文字列で返す"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input)
    return sha256_hash.hexdigest()

def find_the_cheese():
    """すべてのパターンを試行し、ターゲットハッシュに一致する平文とソルトを見つける"""
    
    try:
        # ワードリストを一旦リストとして読み込む
        with open(wordlist_file, 'r', encoding='utf-8') as f:
            cheeses = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"エラー: ワードリストファイル '{wordlist_file}' が見つかりません。")
        return

    total_attempts = 0
    
    for enc in ENCODINGS:
        print(f"--- 試行エンコーディング: {enc} ---")
        
        for cheese_original in cheeses:
            
            # 大文字・小文字のバリエーションを定義
            case_variants = {
                "original": cheese_original,
                "lower": cheese_original.lower(),
                "upper": cheese_original.upper()
            }

            for case_name, variant_str in case_variants.items():
                try:
                    # 変換された文字列を、現在のエンコーディングでバイト列に変換
                    word_bytes = variant_str.encode(enc) 
                except UnicodeEncodeError:
                    continue # そのエンコードで表現できない文字はスキップ

                # ソルト (0x00 から 0xFF までの 256 通り) のループ
                for i in range(256):
                    salt_byte = bytes([i]) # 1バイトのバイナリソルト
                    
                    # ソルトの全位置挿入 (先頭から末尾まで)
                    for position in range(len(word_bytes) + 1):
                        total_attempts += 1
                        
                        # バイト列として連結: Part A + Salt + Part B
                        salted_word = word_bytes[:position] + salt_byte + word_bytes[position:]
                        
                        if compute_sha256(salted_word) == hash_target:
                            # マッチ発見！
                            print("--------------------------------------------------")
                            print(" マッチ発見！")
                            print(f"ターゲットハッシュ: {hash_target}")
                            print("--- 正解の構成要素 ---")
                            print(f"1. チーズ名 (ワードリスト): {cheese_original}")
                            print(f"2. 使用されたケース: {case_name}")
                            print(f"3. 使用されたエンコーディング: {enc}")
                            print(f"4. ソルト値 (10進数): {i} (16進数: {hex(i)})")
                            print(f"5. ソルト挿入位置: {position} (バイト列のインデックス)")
                            print("--- 連結された情報 ---")
                            print(f"連結前のバイト列: {word_bytes.hex()}")
                            print(f"最終入力バイト列: {salted_word.hex()} ({len(salted_word)} bytes)")
                            print("--------------------------------------------------")
                            
                            # ログ出力後、プログラムを終了
                            return

    print(f"\n合計 {total_attempts} 回の試行を行いましたが、マッチは見つかりませんでした。")
    print("問題のハッシュ、ワードリスト、または想定外のエンコーディング・処理の可能性を再確認してください。")

if __name__ == "__main__":
    find_the_cheese()