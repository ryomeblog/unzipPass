import os
import multiprocessing
import itertools
import string
import argparse
import csv
from datetime import datetime
from functools import partial
import pyzipper
from tqdm import tqdm
from multiprocessing import Manager, Queue

class OptimizedZIPPasswordCracker:
    def __init__(self, zip_path, max_length=4, dictionary_path=None):
        self.zip_path = zip_path
        self.max_length = max_length
        
        # CPUコア数に基づいてワーカー数を動的に設定
        self.max_workers = multiprocessing.cpu_count()
        
        # 高度な文字セット
        self.charset = (
            string.ascii_lowercase + 
            string.ascii_uppercase + 
            string.digits + 
            '!@#$%^&*'
        )
        
        # 辞書ファイルの読み込み
        self.dictionary = self.load_dictionary(dictionary_path)
        
        # タイムスタンプ付きのログファイル
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = f'optimized_password_attempts_{timestamp}.csv'
        
        with open(self.log_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv.writer(csvfile).writerow(['Timestamp', 'Method', 'Password', 'Result'])

    def load_dictionary(self, dictionary_path=None):
        """
        デフォルトの辞書を読み込み、カスタム辞書ファイルをサポート
        """
        # デフォルトの辞書
        default_passwords = [
            'password', 'admin', '123456', '12345678', 'qwerty', 
            '123456789', '1234', '12345', 'dragon', 'baseball',
            'abc123', 'football', 'monkey', 'letmein', 'shadow',
            'master', 'welcome', 'login', 'princess', 'starwars'
        ]
        
        # カスタム辞書ファイルが指定された場合
        if dictionary_path and os.path.exists(dictionary_path):
            try:
                with open(dictionary_path, 'r', encoding='utf-8') as f:
                    custom_passwords = [line.strip() for line in f if line.strip()]
                    default_passwords.extend(custom_passwords)
            except Exception as e:
                print(f"辞書ファイルの読み込みに失敗: {e}")
        
        return list(set(default_passwords))  # 重複を除去

    def generate_password_variations(self, base_password):
        """
        パスワードの変形バリエーションを生成
        """
        variations = [base_password]
        
        # 大文字・小文字の変形
        variations.append(base_password.capitalize())
        variations.append(base_password.upper())
        
        # 数字と特殊文字の追加
        for suffix in ['123', '!', '123!', '2024']:
            variations.append(base_password + suffix)
        
        return variations

    def generate_total_passwords(self):
        """
        総パスワード数を事前計算
        """
        # 辞書バリエーション数
        dict_variations = sum(len(self.generate_password_variations(p)) for p in self.dictionary)
        
        # 総当たり攻撃の組み合わせ数
        brute_force_total = sum(
            len(self.charset) ** length 
            for length in range(1, self.max_length + 1)
        )
        
        return dict_variations + brute_force_total

    def fast_password_generator(self, progress_queue=None):
        """
        より効率的なパスワード生成メソッド
        """
        def generate_passwords_fast(length, charset):
            for combo in itertools.product(charset, repeat=length):
                yield ''.join(combo)
        
        # 辞書攻撃を先に実行
        for base_password in self.dictionary:
            for variation in self.generate_password_variations(base_password):
                yield variation
                if progress_queue:
                    progress_queue.put(1)
        
        # 辞書攻撃で見つからない場合、総当たり攻撃
        for length in range(1, self.max_length + 1):
            for pwd in generate_passwords_fast(length, self.charset):
                yield pwd
                if progress_queue:
                    progress_queue.put(1)

    def test_password_fast(self, password):
        """
        pyzipper を使用した高速なパスワード検証
        """
        try:
            with pyzipper.AESZipFile(self.zip_path) as zf:
                zf.read(zf.namelist()[0], pwd=password.encode())
            return True
        except Exception:
            return False

    def worker_process(self, password_queue, result_queue, progress_queue):
        """
        並列処理のワーカープロセス
        """
        for password in iter(password_queue.get, 'STOP'):
            try:
                result = self.test_password_fast(password)
                progress_queue.put(1)
                
                if result:
                    result_queue.put(password)
                    break
            except Exception:
                pass

    def crack_password_multiprocess(self):
        """
        マルチプロセスを使用した高速なパスワード探索
        """
        # プロセス間通信のためのキュー
        manager = Manager()
        password_queue = manager.Queue()
        result_queue = manager.Queue()
        progress_queue = manager.Queue()

        # 総パスワード数を計算
        total_passwords = self.generate_total_passwords()

        # プログレスバーの初期化
        pbar = tqdm(total=total_passwords, desc="パスワード探索中", unit="pwd")

        # ワーカープロセスの作成
        processes = []
        for _ in range(self.max_workers):
            p = multiprocessing.Process(
                target=self.worker_process, 
                args=(password_queue, result_queue, progress_queue)
            )
            p.start()
            processes.append(p)

        # パスワードジェネレータからキューにパスワードを追加
        progress_thread_stop = False
        
        def update_progress():
            nonlocal progress_thread_stop
            while not progress_thread_stop:
                try:
                    progress_queue.get(timeout=1)
                    pbar.update(1)
                except:
                    pass

        # 進捗更新スレッドの開始
        from threading import Thread
        progress_thread = Thread(target=update_progress)
        progress_thread.start()

        # パスワードを順次追加
        for password in self.fast_password_generator():
            password_queue.put(password)
            
            # 結果が見つかったらループを抜ける
            if not result_queue.empty():
                break

        # すべてのプロセスを停止
        for _ in range(self.max_workers):
            password_queue.put('STOP')

        # すべてのプロセスの終了を待つ
        for p in processes:
            p.join()

        # 進捗更新スレッドを停止
        progress_thread_stop = True
        progress_thread.join()

        # 結果を取得
        try:
            found_password = result_queue.get(block=False)
            pbar.close()
            return found_password
        except:
            pbar.close()
            return None

def main():
    parser = argparse.ArgumentParser(description='Optimized ZIPパスワードクラッカー')
    parser.add_argument('zip_path', help='解凍対象のZIPファイルパス')
    parser.add_argument('-l', '--length', type=int, default=4, 
                        help='パスワード探索の最大長さ')
    parser.add_argument('-d', '--dictionary', type=str, 
                        help='カスタム辞書ファイルのパス')
    
    args = parser.parse_args()

    cracker = OptimizedZIPPasswordCracker(
        args.zip_path, 
        max_length=args.length, 
        dictionary_path=args.dictionary
    )
    found_password = cracker.crack_password_multiprocess()

    if found_password:
        print(f"\nパスワードが見つかりました: {found_password}")
    else:
        print("\nパスワードが見つかりませんでした。")

if __name__ == '__main__':
    main()