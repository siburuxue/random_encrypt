# random_encrypt

## openssl加密 
### 仅实现了 AES-128-CBC

示例代码：
```go
e := random_encrypt.NewRandomEncrypt()
s := e.setSalt("salt").encrypt("hello world")
fmt.Println(s)
t := e.setSalt("salt").encrypt(s)
fmt.Println(t)
```