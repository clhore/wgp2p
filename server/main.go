package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/clhore/wireguard-packages/wgconf"
)

// Peer representa la información de un par conectado al servidor.
type Peer struct {
	ID        string          `json:"id"`
	Token     string          `json:"token"`
	PublicKey string          `json:"publicKey"`
	Endpoint  wgconf.Endpoint `json:"endpoint"`
}

// Configuración del servidor.
type Config struct {
	ListenAddr     string            `json:"listenAddr"`
	ListenPort     int               `json:"listenPort"`
	ControlPort    int               `json:"controlPort"`
	PrivateKey     string            `json:"privateKey"`
	ConnectedPeers map[string]string `json:"connectedPeers"`
}

// Estado del servidor.
type Server struct {
	Config Config
	Peers  map[string]*Peer
	Mutex  sync.Mutex
}

func main() {
	// Cargar la configuración del servidor.
	config := loadConfig("config.json")

	// Crear el servidor.
	server := &Server{
		Config: config,
		Peers:  make(map[string]*Peer),
	}

	// Iniciar el servidor de control.
	go server.startControlServer()

	// Iniciar el servidor WireGuard.
	server.startWireGuardServer()
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

// Iniciar el servidor de control HTTP.
func (s *Server) startControlServer() {
	http.HandleFunc("/register", s.registerPeer)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", s.Config.ListenAddr, s.Config.ControlPort), nil))
}

// Registrar un par en el servidor.
func (s *Server) registerPeer(w http.ResponseWriter, r *http.Request) {
	var peer Peer
	err := json.NewDecoder(r.Body).Decode(&peer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validar el token del par.
	if peer.Token != "mi-token-secreto" {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	// Agregar el par al mapa de pares.
	s.Mutex.Lock()
	s.Peers[peer.ID] = &peer
	s.Mutex.Unlock()

	// Enviar la información de conexión al par objetivo.
	targetPeerID := s.Config.ConnectedPeers[peer.ID]
	s.sendPeerInfo(peer.ID, targetPeerID)

	// Enviar la información del servidor WireGuard al cliente.
	serverInfo := struct {
		ListenAddr string `json:"listenAddr"`
		ListenPort int    `json:"listenPort"`
	}{
		ListenAddr: s.Config.ListenAddr,
		ListenPort: s.Config.ListenPort,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(serverInfo)
}

// Iniciar el servidor WireGuard UDP.
func (s *Server) startWireGuardServer() {
	// Configurar la interfaz WireGuard.
	wgAddress := wgconf.IPAddrAndMac{IpAddr: s.Config.ListenAddr, MaskAddr: 24}

	wg := wgconf.NewWireGuardTrun(
		wgconf.WithInterfaceName("wg0"),
		wgconf.WithInterfaceIp(wgAddress),
		wgconf.WithListenPort(s.Config.ListenPort),
		wgconf.WithPrivateKey(s.Config.PrivateKey),
	)

	err := wg.CreateInterface()
	if err != nil {
		log.Fatalf("Error al crear la interfaz WireGuard: %v", err)
	}

	// Agregar los pares conectados al servidor como pares WireGuard.
	s.Mutex.Lock()
	for _, peer := range s.Peers {
		wgPeer := wgconf.Peer{
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{"10.0.0.0/24"}, // Permite todas las IPs en la subred 10.0.0.0/24.
			KeepAlive:  25,
		}
		wg.AddPeer(wgPeer)
	}
	s.Mutex.Unlock()

	// Actualizar la configuración de la interfaz WireGuard.
	wg.UpdateConfigInterfaceWgTrun()

	log.Printf("Servidor WireGuard iniciado en %s:%d", s.Config.ListenAddr, s.Config.ListenPort)

	// Mantener el servidor WireGuard en ejecución.
	select {}
}

// Enviar la información de conexión de un par a otro.
func (s *Server) sendPeerInfo(peerID string, targetPeerID string) {
	s.Mutex.Lock()
	peer, ok := s.Peers[peerID]
	if !ok {
		s.Mutex.Unlock()
		log.Printf("Par con ID %s no encontrado", peerID)
		return
	}

	targetPeer, ok := s.Peers[targetPeerID]
	if !ok {
		s.Mutex.Unlock()
		log.Printf("Par objetivo con ID %s no encontrado", targetPeerID)
		return
	}
	s.Mutex.Unlock()

	// Enviar la información de conexión al par objetivo.
	jsonData, err := json.Marshal(peer)
	if err != nil {
		log.Printf("Error al serializar la información del par: %v", err)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s:%d/connect", targetPeer.Endpoint.Host, targetPeer.Endpoint.Port), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error al enviar la información del par: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error al enviar la información del par: %s", resp.Status)
		return
	}
}
