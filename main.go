package random_encrypt

import "fmt"

func main() {
	e := encrypt("hello world")
	fmt.Println(e)
	s := decrypt(e)
	fmt.Println(s)
}
