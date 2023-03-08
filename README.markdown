# random_encrypt

## openssl加密 
### 仅实现了 AES-128-CBC

示例代码：
```go
e := random_encrypt.NewRandomEncrypt()
config := map[string]interface{}{"salt": "salt"}
e.Config(config)
s, key, iv, timestamp := e.Encrypt("hello world")
fmt.Println(s)
fmt.Println(key)
fmt.Println(iv)
fmt.Println(timestamp)
t := e.Decrypt(s)
fmt.Println(t)
```