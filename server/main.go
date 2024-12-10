package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	unusedArgs := flag.Args()

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
		if n < 17 {
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
				if startScrcpy(remoteAddr.IP.String(), port, unusedArgs...) {
					encryptedOK, err := aesEncryption([]byte("OK"), *pairCode)
					if err != nil {
						fmt.Printf("Error encrypting response: %v\n", err)
						continue
					}
					conn.WriteToUDP(encryptedOK, remoteAddr)
				} else {
					encryptedFAIL, err := aesEncryption([]byte("FAIL"), *pairCode)
					if err != nil {
						fmt.Printf("Error encrypting response: %v\n", err)
						continue
					}
					conn.WriteToUDP(encryptedFAIL, remoteAddr)
				}
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
func aesEncryption(data []byte, password string) ([]byte, error) {
	key := generateKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS5 padding
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	data = append(data, padText...)

	// Encrypt data
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	// Prepend IV to the ciphertext
	return append(iv, ciphertext...), nil
}
func sendNotification(message string) {
	fmt.Println("Sending notification...")
	cmd := exec.Command("notify-send", message)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error sending notification: %v\n", err)
	}
}

func startScrcpy(ip string, port int, arg ...string) bool {
	fmt.Printf("adb connect to %s:%d\n", ip, port)
	cmd := exec.Command("adb", "connect", fmt.Sprintf("%s:%d", ip, port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error connecting to device: %v\n", err)
		return false
	}
	sendNotification(fmt.Sprintf("Connected to %s:%d", ip, port))

	scrCpycmd := exec.Command(
		"scrcpy",
		append([]string{"--serial", fmt.Sprintf("%s:%d", ip, port)}, arg...)...)
	scrCpycmd.Stdout = os.Stdout
	scrCpycmd.Stderr = os.Stderr
	if err := scrCpycmd.Start(); err != nil {
		fmt.Printf("Error starting scrcpy: %v\n", err)
		return false
	}
	return true
}
