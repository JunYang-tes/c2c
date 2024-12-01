package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
)

func main() {
	pairCode := flag.String("pairCode", "", "The pair code to use for encryption")
	flag.Parse()
	// Check if pairCode is provided
	if *pairCode == "" {
		fmt.Println("Error: pairCode is required")
		os.Exit(1)
	}

	// 绑定到所有网络接口并监听 UDP 广播端口
	addr := net.UDPAddr{
		Port: 8888, // 替换为你的广播端口
		IP:   net.IPv4(0, 0, 0, 0),
	}

	// 创建 UDP 套接字
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Printf("Error listening on UDP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Listening for UDP broadcasts on port %d...\n", addr.Port)

	// 循环接收消息
	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error reading from UDP: %v\n", err)
			continue
		}

		fmt.Printf("Received message from %s\n", remoteAddr.String())
		data, err := aesDecrpytion(buf[:n], *pairCode)
		if err != nil {
			fmt.Printf("Error decrypting message: %v\n", err)
			continue
		} else {
			port, err := strconv.Atoi(string(data))
			if err != nil {
				fmt.Printf("Error decrypting message: %v\n", err)
			} else {
				startScrcpy(remoteAddr.IP.String(), port)
			}
		}
	}
}

func generateKey(password string) []byte {
	hasher := sha256.New()
	io.WriteString(hasher, password)
	return hasher.Sum(nil)[:16] // Use only the first 128 bits (16 bytes) for AES-128
}

func aesDecrpytion(data []byte, password string) ([]byte, error) {
	key := generateKey(password)
	iv := data[:16]
	data = data[16:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Remove PKCS5Padding
	padding := data[len(data)-1]
	if int(padding) > len(data) || int(padding) > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-int(padding)], nil
}

func startScrcpy(ip string, port int) {
	fmt.Printf("adb connect to %s:%d\n", ip, port)
	cmd := exec.Command("adb", "connect", fmt.Sprintf("%s:%d", ip, port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error connecting to device: %v\n", err)
		return
	}

	scrCpycmd := exec.Command("scrcpy")
	scrCpycmd.Stdout = os.Stdout
	scrCpycmd.Stderr = os.Stderr
	if err := scrCpycmd.Start(); err != nil {
		fmt.Printf("Error starting scrcpy: %v\n", err)
		return
	}
}
