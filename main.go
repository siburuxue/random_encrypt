package random_encrypt

import "fmt"

func main() {
	e := NewRandomEncrypt()
	s := e.SetSalt("salt").Encrypt("hello world")
	fmt.Println(s)
	t := e.SetSalt("salt").Decrypt(s)
	fmt.Println(t)
}
