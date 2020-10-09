package pake

import (
	"crypto/elliptic"
	"crypto/sha1"
	"errors"
	"math/big"
	"utils"

	"golang.org/x/crypto/bcrypt"
)

const (
	p224 = "p224"
	p256 = "p256"
	p384 = "p384"
	p521 = "p521"
)

var (
	ErrNotOnCurve = errors.New("point not on curve")
	ErrSecretNotSet = errors.New("secret not set")
	ErrSessionKeyUnverified = errors.New("unable to verify session key")
	ErrUnidentifiedCurve = errors.New("tried to initialize unidentified curve")
)

func (p *Pake) Initialize(curveType string, password []byte) (err error) {
	switch curveType {
	case p224:
		p.curve = elliptic.P224()
	case p256:
		p.curve = elliptic.P256()
	case p384:
		p.curve = elliptic.P384()
	case p521:
		p.curve = elliptic.P521()
	default:
		err = ErrUnidentifiedCurve
		return err
	}
	p.password = password
	return
}

func generateRandomPoint(curve elliptic.Curve) (x, y *big.Int, err error) {
	randomBytes, err := utils.GenerateRandomBytes(16)
	if err != nil {
		return
	}
	x, y = curve.ScalarBaseMult(randomBytes)
	if !curve.IsOnCurve(x,y){
		err = ErrNotOnCurve
	}
	return
}

func (p *Pake) SetAsServer(server bool){
	p.server = server
}

func (p *Pake) GeneratePublicParameters() (err error) {
	p.ax, p.ay, err = generateRandomPoint(p.curve)
	p.bx, p.by, err = generateRandomPoint(p.curve)
	p.gx, p.gy, err = generateRandomPoint(p.curve)
	return
}

func (p *Pake) computeSecret() (err error) {
	p.secret, err = utils.GenerateRandomBytes(16)
	if err != nil {
		return
	}
	p.secretx, p.secrety = p.curve.ScalarMult(p.gx, p.gy, p.secret)
	if !p.curve.IsOnCurve(p.secretx, p.secrety) {
		err = ErrNotOnCurve
	}
	return err
}

func (p *Pake) Secret() (secret []byte, err error){
	if p.secret == nil {
		err = ErrSecretNotSet
		return nil, err
	}
	return p.secret, err
}

func (p *Pake) computeExchangeParameters() (err error) {
	x, y := p.ax, p.ay
	if p.server {
		x, y = p.bx, p.by
	}
	x, y = p.curve.ScalarMult(x, y, p.password)
	if !p.curve.IsOnCurve(x, y) {
		err = ErrNotOnCurve
		return
	}
	if p.server {
		p.Ux, p.Uy = p.curve.Add(p.secretx, p.secrety, x, y)
	} else {
		p.Vx, p.Vy = p.curve.Add(p.secretx, p.secrety, x, y)
	}
	return
}

func (p *Pake) ClientExchange() *ClientExchange {
	return &ClientExchange{
		Vx:         p.Vx,
		Vy:         p.Vy,
		SessionKey: p.sessionKey,
	}
}

func (p *Pake) ServerExchange() *ServerExchange {
	return &ServerExchange{
		Ax: p.ax,
		Ay: p.ay,
		Bx: p.bx,
		By: p.by,
		Gx: p.gx,
		Gy: p.gy,
		Ux: p.Ux,
		Uy: p.Uy,
	}

}

func (p *Pake) SetPublicParameters(serverExchange *ServerExchange) {
	p.ax, p.ay = serverExchange.Ax, serverExchange.Ay
	p.bx, p.by = serverExchange.Bx, serverExchange.By
	p.gx, p.gy = serverExchange.Gx, serverExchange.Gy
}

func InitPake2(curve string, password []byte) (p *Pake, err error) {
	p = new(Pake)
	if err = p.Initialize(curve, password); err != nil{
		return
	}
	return
}

func (p *Pake) ComputeParameters() (err error) {
	if err = p.computeSecret(); err != nil {
		return
	}
	if err = p.computeExchangeParameters(); err != nil {
		return
	}
	return
}


func (p *Pake) commonSecret(x, y *big.Int) (err error) {
	pointx, pointy := p.bx, p.by
	if p.server{
		pointx, pointy = p.ax, p.ay
	}
	pointx, pointy = p.curve.ScalarMult(pointx, pointy, p.password)
	pointx, pointy = p.curve.Add(x, y, pointx, new(big.Int).Neg(pointy))
	p.wx, p.wy = p.curve.ScalarMult(pointx, pointy, p.secret)
	if !p.curve.IsOnCurve(p.wx, p.wy){
		err = ErrNotOnCurve
		return
	}
	return
}

func (p *Pake) computeSessionKeyHash() {
	sha := sha1.New()
	sha.Write(p.password)
	sha.Write(p.Ux.Bytes())
	sha.Write(p.Uy.Bytes())
	sha.Write(p.Vx.Bytes())
	sha.Write(p.Vy.Bytes())
	sha.Write(p.wx.Bytes())
	sha.Write(p.wy.Bytes())
	p.sessionKey = sha.Sum(nil)
	return
}

func (p *Pake) ComputeSessionKey() (err error) {
	x,y := p.Vx, p.Vy
	if !p.server {
		x,y = p.Ux, p.Uy
	}
	if err = p.commonSecret(x,y); err != nil{
		return
	}
	p.computeSessionKeyHash()
	return
}

func compareSessionKeys(hashedSessionKey, receivedKey []byte) bool {
	if err := bcrypt.CompareHashAndPassword(hashedSessionKey, receivedKey); err != nil {
		return false
	}
	return true
}

func (p *Pake) VerifyKey(receivedKey []byte) (err error) {

	hashedSessionKey, err := bcrypt.GenerateFromPassword(p.sessionKey, bcrypt.DefaultCost)

	if !compareSessionKeys(hashedSessionKey, receivedKey) {
		err = ErrSessionKeyUnverified
		return
	}
	p.keyVerified = true
	return
}
