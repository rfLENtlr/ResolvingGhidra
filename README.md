# ResolvingGhidra
GhidraScripts for automatic resolving API names from hash values

## Todo
### Emulate
- [ ] 開始アドレスの決定
  - from DBI
- [ ] 終了アドレスの決定
  - from DBI
- [x] API名を格納するメモリの確保
- [ ] API名を扱うレジスタの決定
  - アセンブラから決定する
- [ ] 埋め込みハッシュ値の洗い出し
  - [ ] オペランドのスカラー値
  - [ ] メモリ参照先のスカラー値（グローバル変数）

### Evaluate
#### compare hashvalues
- `SUB`
- `TEST`
- `XOR`