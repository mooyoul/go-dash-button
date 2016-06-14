package main

import (
	"dashbutton"
	"log"
	"net"
	"time"
)

func main() {
	if iface, err := net.InterfaceByName("en0"); err != nil {
		panic(err)
	} else if dash, err := net.ParseMAC("11:11:11:11:11:11"); err != nil {
		panic(err)
	} else if dash2, err := net.ParseMAC("22:22:22:22:22:22"); err != nil {
		panic(err)
	} else if interceptor, err := dashbutton.NewInterceptor(iface); err != nil {
		panic(err)
	} else {
		log.Printf("Using network interface %v", iface.Name)
		interceptor.Add(dash)
		interceptor.Add(dash2)

		defer interceptor.Close()
		clicks := interceptor.Clicks()
		go func() {
			for {
				select {
				case device, ok := <-clicks:
					if !ok { // Check channel availability
						log.Printf("Channel was closed. Exiting goroutine")
						return
					}
					log.Printf("Clicked! IP: %v / Mac: %v", device.IP, device.HardwareAddr)
				}
			}
		}()
		time.Sleep(time.Second * 15)

		interceptor.Remove(dash2) // dash2 will not be detected
		log.Printf("Removed %v", dash2)

		time.Sleep(time.Second * 15)

		interceptor.Add(dash2) // dash2 will be detected again
		log.Printf("Added %v", dash2)

		time.Sleep(time.Second * 15)
	}
}
