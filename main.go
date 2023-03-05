package random_encrypt

import "fmt"

func main() {
	e := Encrypt("hello world")
	fmt.Println(e)
	s := Decrypt(e)
	fmt.Println(s)
}
