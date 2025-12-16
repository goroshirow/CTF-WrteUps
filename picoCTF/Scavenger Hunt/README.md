# Scavenger Hunt

## 解法

色々な場所からピースを集める。
1. htmlコメント
2. cssコメント
3. robots.txt
4. .htaccess (Apache)
5. .DS_Store (Mac)

## 発展

他にもいくつか調べたほうが良いディレクトリがある

### Apache

- .htaccess
- .htpasswd
- server-status
- httpd.conf

### Mac開発

- .DS_Store
- __MACOSX/

Google Dorkingという調査方法がある

```site:example.com intitle:"Index of /"```

この検索で結果が見つかった場合、それはそのWebサーバーに**「ディレクトリリスティング（ディレクトリ一覧の表示）」**という設定上の問題（脆弱性）があり、外部に以下の情報が漏洩していることを意味します。

- バックアップファイル（例: .zip, .bak, .old）

- 設定ファイル（例: .env、データベース接続情報を含むもの）

- 開発中のファイルやテスト用のディレクトリ

- ソースコード（意図せずアップロードされた場合）



## 有名なツール

Gobuster
