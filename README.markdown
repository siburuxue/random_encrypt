# random_encrypt

## openssl加密 
### 仅实现了 AES-128-CBC

示例代码：
```go
e := random_encrypt.NewRandomEncrypt()
s := e.SetSalt("salt").Encrypt("hello world")
fmt.Println(s)
t := e.SetSalt("salt").Decrypt(s)
fmt.Println(t)
```