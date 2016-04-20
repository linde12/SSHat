package sshd

import (
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
)

// Auth is used to determine if a client is allowed to connect or not
type Auth interface {
	AllowAnonymous() bool
	IsAllowed(net.Addr, ssh.PublicKey) (bool, error)
}

// NewConf creates an empty ssh config
func NewConf(auth Auth) *ssh.ServerConfig {
	return &ssh.ServerConfig{
		NoClientAuth: false,

		PublicKeyCallback: func(connInfo ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			ok, err := auth.IsAllowed(connInfo.RemoteAddr(), pubKey)
			if !ok {
				return nil, err
			}
			perm := &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(pubKey.Marshal()),
				},
			}

			return perm, nil
		},

		KeyboardInteractiveCallback: func(connInfo ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if !auth.AllowAnonymous() {
				return nil, errors.New("Anonymous authentication is not allowed")
			}

			_, err := auth.IsAllowed(connInfo.RemoteAddr(), nil)
			return nil, err
		},
	}
}
