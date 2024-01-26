package main
import (
        "fmt"
        "time"
        "github.com/mmcshane/salp"
)
 
var (
        probes = salp.NewProvider("myprobe")
        p1 = salp.MustAddProbe(probes, "start", salp.Int64)
        p2 = salp.MustAddProbe(probes, "ing", salp.Int64)
        p3 = salp.MustAddProbe(probes, "end", salp.Int64)
)

func my_end(value int) int {
        if value > 0 {
		p2.Fire(value)
                fmt.Println(value)
                return my_end(value-1)
        }
	p3.Fire(value)
        fmt.Println("End")
        return value
}
 
func my_start(value int) int {
	for true {
		p1.Fire(value)
        	fmt.Println("Start")
        	my_end(value)
		time.Sleep(1 * time.Second)
	}
	return 0
}

func main() {
        defer salp.UnloadAndDispose(probes)
        salp.MustLoadProvider(probes)
        my_start(3)
}

