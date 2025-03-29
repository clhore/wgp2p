package main

import (
	"fmt"
	"os"

	"github.com/clhore/wireguard-packages/wgconf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Uso: go run main.go <path_to_wg0.conf>")
		return
	}

	wgAddress := wgconf.IPAddrAndMac{IpAddr: "192.168.111.11", MaskAddr: 24}

	wg := wgconf.NewWireGuardTrun(
		wgconf.WithInterfaceName("wg1"), wgconf.WithInterfaceIp(wgAddress), wgconf.WithListenPort(51822),
		wgconf.WithPrivateKey("gP69hmKxP01OXAikh/lD0tmNimDT+fLRCp0KkbxadWU="),
	)
	err := wg.CreateInterface()
	if err != nil {
		fmt.Println("Error creating interface:", err)
		return
	}

	peerOne := wgconf.Peer{
		PublicKey:  "7M2y7SRmOo0NUkJBRl7Ol0OitPrv1+/Y79rKu6FaQkw=",
		Endpoint:   wgconf.Endpoint{Host: "192.168.1.101", Port: 51820},
		AllowedIPs: []string{"10.0.0.1/32"},
		KeepAlive:  25,
	}

	peerTwo := wgconf.Peer{
		PublicKey:  "6M2y7SRmOo0NUkJBRl7Ol0OitPrv1+/Y79rKu6FaQkw=",
		Endpoint:   wgconf.Endpoint{Host: "192.168.1.101", Port: 51820},
		AllowedIPs: []string{"10.0.0.2/32"},
		KeepAlive:  25,
	}

	peerTree := wgconf.Peer{
		PublicKey:  "5M2y7SRmOo0NUkJBRl7Ol5OitPrv1+/Y79rKu6FaQkw=",
		Endpoint:   wgconf.Endpoint{Host: "192.168.1.101", Port: 51820},
		AllowedIPs: []string{"10.0.0.3/32"},
		KeepAlive:  25,
	}

	wg.AddPeer(peerOne)
	wg.AddPeer(peerTwo)
	wg.AddPeer(peerTree)
	wg.UpdateConfigInterfaceWgTrun()

	wg.DeleteInterface()
}
