package random_encrypt

import "fmt"

func main() {
	e := NewRandomEncrypt()
	s := e.setSalt("salt").encrypt("hello world")
	fmt.Println(s)
	t := e.setSalt("salt").encrypt(s)
	fmt.Println(t)
}
