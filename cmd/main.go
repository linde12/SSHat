package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"os/user"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/linde12/shat"
	"github.com/linde12/shat/sshd"
	"golang.org/x/crypto/ssh"
)

type Options struct {
	OpsFilePath        string `long:"ops" description:"File containing operator public keys"`
	MotdFilePath       string `long:"motd" description:"File containing message of the dat"`
	PrivateKeyFilePath string `long:"key" description:"File containing the private key"`
}

func fail(code int, message string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, message, args...)
	os.Exit(code)
}

func readPrivateKey(path string) ([]byte, error) {
	if strings.HasPrefix(path, "~/") {
		usrEnv, err := user.Current()
		if err != nil {
			return nil, err
		}
		strings.Replace(path, "~", usrEnv.HomeDir, 1)
	}

	privateKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %v", err)
	}

	block, rest := pem.Decode(privateKey)
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data when decoding private key")
	}
	if !x509.IsEncryptedPEMBlock(block) {
		return privateKey, nil
	}

	passphrase := os.Getenv("IDENTITY_PASSPHRASE")
	der, err := x509.DecryptPEMBlock(block, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}

	privateKey = pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: der,
	})

	return privateKey, nil
}

func main() {
	opts := Options{}
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		fail(1, "Failed to parse cmd arguments %v", err)
	}

	// Read privkey used for decryption of messages encrypted with pubkey
	privateKey, err := readPrivateKey(opts.PrivateKeyFilePath)
	if err != nil {
		fail(2, "Failed to parse private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		fail(3, "Failed to parse private key: %v", err)
	}
	chatConf := shat.NewConf()
	authConf := sshd.NewConf(*chatConf)
	authConf.AddHostKey(signer)

	serv, err := sshd.Listen("0.0.0.0:1337", authConf)
	if err != nil {
		fail(4, "Failed to listen on port: %v", err)
	}
	defer serv.Close()

	terminals := serv.ServeTerminal()
	for term := range terminals {
		// TODO: Connect terminals to a chatroom
		// this is just a short example of a working echo
		go func(term *sshd.Terminal) {
			for {
				term.SetPrompt("> ")
				line, _ := term.ReadLine()
				term.Write([]byte("server: " + line + "\r\n"))
			}
		}(term)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Wait for SIGINT(^C)
	<-sig
}
