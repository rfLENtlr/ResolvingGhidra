# ResolvingGhidra (WIP)
This repository is the home of ResolvingGhidra (tentative name), a tool that automatically resolves API hashing. 

This tool mainly utilizes information obtained by DynamoRIO and emulation by Ghidra API to deobfuscate (resolve) API names obfuscated by API Hashing.

## Todo
### DBI
- [ ] 結果をjsonで出力
  - [ ] API名取得命令のアドレス 
  - [ ] API Hashingの後、実際に取得されたAPI名
  
### Ghidra Script (Emulate)
- [ ] 開始アドレスの決定
  - [ ] DBIの出力と連携
- [x] API名を格納するメモリの確保
- [ ] API名を扱うレジスタの決定
  - [x] 命令のディスティネーション
- [ ] 埋め込みハッシュ値の洗い出し
  - [x] CMP命令のオペランドに注目
    - [x] オペランドのハッシュ値
    - [x] メモリ参照先のハッシュ値（グローバル変数）
    - [x] 関数の引数として渡されるハッシュ値 