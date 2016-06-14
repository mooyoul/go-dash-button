package main

import (
	"dashbutton"
	"log"
	"net"
)

func main() {
	if iface, err := net.InterfaceByName("en0"); err != nil {
		panic(err)
	} else if dash, err := net.ParseMAC("11:11:11:11:11:11"); err != nil {
		panic(err)
	} else if interceptor, err := dashbutton.NewInterceptor(iface); err != nil {
		panic(err)
	} else {
		log.Printf("Using network interface %v", iface.Name)
		interceptor.Add(dash)

		defer interceptor.Close()
		clicks := interceptor.Clicks()
		for {
			select {
			case device, ok := <-clicks:
				if !ok { // Check channel availability
					log.Printf("Channel was closed. Exiting goroutine")
					return
				}
				log.Printf("Clicked! IP %v / MAC: %v", device.IP, device.HardwareAddr)
			}
		}
	}
}
