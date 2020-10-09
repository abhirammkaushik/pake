package pake

import (
	"crypto/elliptic"
	"math/big"
)

type Pake struct {
	keyVerified      bool
	server           bool
	secret           []byte
	password         []byte
	sessionKey       []byte
	ax, ay           *big.Int
	bx, by           *big.Int
	gx, gy           *big.Int
	secretx, secrety *big.Int
	wx, wy           *big.Int
	Ux, Uy           *big.Int
	Vx, Vy           *big.Int
	curve            elliptic.Curve


}

type ServerExchange struct {
	Ax, Ay  *big.Int
	Bx, By  *big.Int
	Gx, Gy  *big.Int
	Ux, Uy  *big.Int
}

type ClientExchange struct {
	SessionKey []byte
	Vx, Vy     *big.Int
}