package shat

import (
	"golang.org/x/crypto/ssh"
	"net"
)

// Auth stores a list of operators & banned ips. It implements sshd.Auth
type Auth struct {
	ops    []string
	banned []string
}

// NewConf creates an empty chat Auth struct
func NewConf() *Auth {
	return &Auth{}
}

func (auth Auth) AllowAnonymous() bool {
	return true
}

func (auth Auth) IsAllowed(addr net.Addr, pubKey ssh.PublicKey) (bool, error) {
	return true, nil
}
