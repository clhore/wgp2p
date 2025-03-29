package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/clhore/wireguard-packages/wgconf"
)

// Configuración del cliente.
type Config struct {
	ServerAddr string   `json:"serverAddr"`
	ServerPort int      `json:"serverPort"`
	PeerID     string   `json:"peerID"`
	Token      string   `json:"token"`
	PrivateKey string   `json:"privateKey"`
	ListenPort int      `json:"listenPort"`
	AllowedIPs []string `json:"allowedIPs"`
}

// Peer representa la información de un par conectado al servidor.
type Peer struct {
	ID        string          `json:"id"`
	Token     string          `json:"token"`
	PublicKey string          `json:"publicKey"`
	Endpoint  wgconf.Endpoint `json:"endpoint"`
}

func main() {
	// Cargar la configuración del cliente.
	config := loadConfig("config.json")

	// Registrar el cliente en el servidor.
	peerInfo, err := registerWithServer(config)
	if err != nil {
		log.Fatalf("Error al registrarse en el servidor: %v", err)
	}

	// Configurar WireGuard.
	setupWireGuard(config, peerInfo)
}

// Cargar la configuración desde un archivo JSON.
func loadConfig(filename string) Config {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error al leer el archivo de configuración: %v", err)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error al analizar el archivo de configuración: %v", err)
	}

	return config
}

// Registrar el cliente en el servidor.
func registerWithServer(config Config) (Peer, error) {
	peer := Peer{
		ID:        config.PeerID,
		Token:     config.Token,
		PublicKey: config.PrivateKey, // Usamos la clave privada como clave pública para simplificar.
	}

	jsonData, err := json.Marshal(peer)
	if err != nil {
		return Peer{}, err
	}

	resp, err := http.Post(fmt.Sprintf("%s:%d/register", config.ServerAddr, config.ServerPort), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return Peer{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Peer{}, fmt.Errorf("Error al registrar el par: %s", resp.Status)
	}

	var peerInfo Peer
	err = json.NewDecoder(resp.Body).Decode(&peerInfo)
	if err != nil {
		return Peer{}, err
	}

	return peerInfo, nil
}

// Configurar WireGuard con la información del par.
func setupWireGuard(config Config, peerInfo Peer) {
	// Configurar la interfaz WireGuard.
	wgAddress := wgconf.IPAddrAndMac{IpAddr: "10.0.0.10", MaskAddr: 24} // Usamos una IP arbitraria en la subred 10.0.0.0/24.

	wg := wgconf.NewWireGuardTrun(
		wgconf.WithInterfaceName("wg0"),
		wgconf.WithInterfaceIp(wgAddress),
		wgconf.WithListenPort(config.ListenPort),
		wgconf.WithPrivateKey(config.PrivateKey),
	)

	err := wg.CreateInterface()
	if err != nil {
		log.Fatalf("Error al crear la interfaz WireGuard: %v", err)
	}

	// Agregar el par objetivo como par WireGuard.
	wgPeer := wgconf.Peer{
		PublicKey:  peerInfo.PublicKey,
		Endpoint:   peerInfo.Endpoint,
		AllowedIPs: config.AllowedIPs,
		KeepAlive:  25,
	}
	wg.AddPeer(wgPeer)

	// Actualizar la configuración de la interfaz WireGuard.
	wg.UpdateConfigInterfaceWgTrun()

	log.Printf("Interfaz WireGuard configurada para el par %s", peerInfo.ID)

	// Mantener el cliente WireGuard en ejecución.
	select {}
}
