package main

import (
	"fmt"
	"time"
)

func my_end(value int) int {
	if value > 0 {
		fmt.Println(value)
		return my_end(value-1)
	}
	fmt.Println("End")
	return value
}

func my_start(value int) int {
	fmt.Println("Start")
	return my_end(value)
}

func main() {
	my_start(3)
	time.Sleep(1*time.Second)
}
