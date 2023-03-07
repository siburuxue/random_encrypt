package random_encrypt

import "fmt"

func main() {
	e := NewRandomEncrypt()
	config := map[string]interface{}{"salt": "salt", "offset": 10, "timeInterval": 7, "secondRedundancy": 3}
	s := e.Config(config).Encrypt("hello world")
	fmt.Println(s)
	t := e.Config(config).Decrypt(s)
	fmt.Println(t)
}
