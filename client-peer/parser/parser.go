package parser

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ParseConfig lee un archivo wg0.conf y lo convierte en wgtypes.Config
func ParseConfig(filePath string) (*wgtypes.Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var privateKey wgtypes.Key
	var listenPort int
	var peerPublicKey wgtypes.Key
	var allowedIPs []net.IPNet
	var endpoint *net.UDPAddr
	var keepalive *time.Duration

	scanner := bufio.NewScanner(file)
	section := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}

		parts := strings.SplitN(line, " = ", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]

		switch section {
		case "[Interface]":
			if key == "PrivateKey" {
				privateKey, err = wgtypes.ParseKey(value)
				if err != nil {
					return nil, fmt.Errorf("error al parsear PrivateKey: %v", err)
				}
			} else if key == "ListenPort" {
				listenPort, err = strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("error al parsear ListenPort: %v", err)
				}
			}

		case "[Peer]":
			if key == "PublicKey" {
				peerPublicKey, err = wgtypes.ParseKey(value)
				if err != nil {
					return nil, fmt.Errorf("error al parsear PublicKey: %v", err)
				}
			} else if key == "AllowedIPs" {
				for _, ip := range strings.Split(value, ",") {
					ip = strings.TrimSpace(ip)
					_, ipnet, err := net.ParseCIDR(ip)
					if err != nil {
						return nil, fmt.Errorf("error al parsear AllowedIPs: %v", err)
					}
					allowedIPs = append(allowedIPs, *ipnet)
				}
			} else if key == "Endpoint" {
				parts := strings.Split(value, ":")
				if len(parts) != 2 {
					return nil, fmt.Errorf("error al parsear Endpoint")
				}
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					return nil, fmt.Errorf("error al parsear puerto del Endpoint: %v", err)
				}
				endpoint = &net.UDPAddr{
					IP:   net.ParseIP(parts[0]),
					Port: port,
				}
			} else if key == "PersistentKeepalive" {
				ka, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("error al parsear PersistentKeepalive: %v", err)
				}
				interval := time.Duration(ka) * time.Second
				keepalive = &interval
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   peerPublicKey,
				AllowedIPs:                  allowedIPs,
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: keepalive,
			},
		},
	}, nil
}
