package random_encrypt

import (
	"fmt"
)

func main() {
	config := map[string]interface{}{"salt": "salt"}
	e := NewRandomEncrypt(config)
	s, key, iv, timestamp := e.Encrypt("hello world")
	fmt.Println(s)
	fmt.Println(key)
	fmt.Println(iv)
	fmt.Println(timestamp)
	t := e.Decrypt(s)
	fmt.Println(t)
}
