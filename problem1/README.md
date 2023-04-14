# Vulnerable signature schemes

## Server for CTF

```sh
npm i
cp -n example.env .env # edit `PRIVATE_KEY`
npm run run:server
```

でサーバーを起動し、もう一つのターミナルを開いて

```sh
node ./scripts/steps.js
```

でクライアントが（`steps.test.js` と同様に）正しく署名を作成する。

## API

クライアントを Alice、サーバーを Bob に見立てる。

### `/`

起動チェック用。正常であれば `{"message":"hello"}` が返る。

### `/bob-key`

Bob の秘密鍵（今回の攻撃対象）に対する公開鍵を取得する。

### `/bob-k-value`

Bob の K 値を取得する（実行するたびにランダムに選ばれます）。

### `/step2`

step2 の実行を Bob に行ってもらう。

## Test

### 正しく署名を作るテスト

```sh
npm test ./test/steps.test.js
```

### 脆弱であることを示すテスト

```sh
npm test ./test/vulnerability.test.js
```

テストを実行すると、たまに Bob の秘密鍵が現れる。
テストが失敗した時もその値に t2 を加えたものが Bob の秘密鍵なので、
何度か実行して /bob-key から得られる公開鍵に対応するものが見つかるまで探せば攻撃成功となる。
