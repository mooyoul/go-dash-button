// package dashbutton allows users of dashbutton to detect dashbutton clicks
package dashbutton

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

// Device contains network information of dash button.
type Device struct {
	HardwareAddr net.HardwareAddr
	IP           net.IP
}

// Interceptor sniff arp packets on specified network.
type Interceptor struct {
	iface   *net.Interface
	handle  *pcap.Handle
	packets <-chan gopacket.Packet
	dashes  map[string]bool
	clicks  chan Device
	done    chan struct{}
}

// New interceptor
func NewInterceptor(iface *net.Interface) (*Interceptor, error) {
	// Open up a pcap handle for packet sniff
	handle, err := pcap.OpenLive(iface.Name, 65536, true, time.Second)
	if err != nil {
		return nil, err
	} else if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

	interceptor := &Interceptor{
		iface,
		handle,
		src.Packets(),
		make(map[string]bool),
		make(chan Device),
		make(chan struct{}),
	}

	return interceptor, nil
}

// Add hardware address of dashbutton into watch group to detect clicks.
func (i *Interceptor) Add(dash net.HardwareAddr) {
	i.dashes[dash.String()] = true
}

// Remove hardware address of dashbutton from watch group.
func (i *Interceptor) Remove(dash net.HardwareAddr) {
	delete(i.dashes, dash.String())
}

// Start loop and return channel which produces Device on click
func (i *Interceptor) Clicks() <-chan Device {
	go i.loop()

	return i.clicks
}

// Close pcap handle and channels. loop will be stopped.
func (i *Interceptor) Close() {
	i.handle.Close()
	i.done <- struct{}{}
	<-i.done // wait
}

// Loop, detects arp packets by using pcap and produce (proxy) Device struct into clicks channel if dash button was clicked.
func (i *Interceptor) loop() {
	defer close(i.clicks)
	defer close(i.done)

	for {
		select {
		case packet := <-i.packets:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			if _, ok := i.dashes[net.HardwareAddr(arp.SourceHwAddress).String()]; arp.Operation == layers.ARPRequest && ok {
				// This is a packet dash sent.
				device := Device{
					net.HardwareAddr(arp.SourceHwAddress),
					net.IP(arp.SourceProtAddress),
				}

				i.clicks <- device
			}
		case <-i.done:
			return
		}
	}
}
