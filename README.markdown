# random_encrypt

## openssl加密 
### 仅实现了 AES-128-CBC

示例代码：
```go
e := random_encrypt.encrypt("hello world")
fmt.Println(e)
s := random_encrypt.decrypt(e)
fmt.Println(s)
```