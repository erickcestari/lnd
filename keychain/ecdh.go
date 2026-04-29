package keychain

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
)

// NewPubKeyECDH wraps the given key of the key ring so it adheres to the
// SingleKeyECDH interface. If the underlying ring is a SecretKeyRing the
// private key is derived eagerly and cached so later ECDH calls stay
// entirely in memory; otherwise (e.g. a remote signer) every call is
// forwarded to the ring.
func NewPubKeyECDH(keyDesc KeyDescriptor, ecdh ECDHRing) *PubKeyECDH {
	p := &PubKeyECDH{
		keyDesc: keyDesc,
		ecdh:    ecdh,
	}

	if secretRing, ok := ecdh.(SecretKeyRing); ok {
		if priv, err := secretRing.DerivePrivKey(keyDesc); err == nil {
			p.cachedPriv = priv
		}
	}

	return p
}

// PubKeyECDH is an implementation of the SingleKeyECDH interface. It wraps an
// ECDH key ring so it can perform ECDH shared key generation against a single
// abstracted away private key.
//
// On the local-keyring path each call to the underlying ECDHRing.ECDH opens a
// read-write wallet DB transaction (to derive the private key), which forces a
// bbolt meta-page write and an fdatasync per call. Since the wrapped key
// descriptor never changes for the lifetime of a PubKeyECDH instance, the
// private key is derived once at construction time and reused for every
// subsequent ECDH operation. When the underlying ring cannot expose private
// keys (e.g. a remote signer), cachedPriv stays nil and we forward each call
// to the ring.
type PubKeyECDH struct {
	keyDesc KeyDescriptor
	ecdh    ECDHRing

	cachedPriv *btcec.PrivateKey
}

// PubKey returns the public key of the private key that is abstracted away by
// the interface.
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PubKeyECDH) PubKey() *btcec.PublicKey {
	return p.keyDesc.PubKey
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// abstracted private key and a remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx := k*P
//	s := sha256(sx.SerializeCompressed())
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PubKeyECDH) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	if p.cachedPriv != nil {
		return ecdhFromPriv(p.cachedPriv, pubKey), nil
	}

	return p.ecdh.ECDH(p.keyDesc, pubKey)
}

// ecdhFromPriv computes sha256(k*P) for a known private key k and remote
// public key P. It is the in-memory fast-path shared by PubKeyECDH (after
// caching) and PrivKeyECDH.
func ecdhFromPriv(priv *btcec.PrivateKey,
	pub *btcec.PublicKey) [32]byte {

	var (
		pubJacobian btcec.JacobianPoint
		s           btcec.JacobianPoint
	)
	pub.AsJacobian(&pubJacobian)

	btcec.ScalarMultNonConst(&priv.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := btcec.NewPublicKey(&s.X, &s.Y)

	return sha256.Sum256(sPubKey.SerializeCompressed())
}

// PrivKeyECDH is an implementation of the SingleKeyECDH in which we do have the
// full private key. This can be used to wrap a temporary key to conform to the
// SingleKeyECDH interface.
type PrivKeyECDH struct {
	// PrivKey is the private key that is used for the ECDH operation.
	PrivKey *btcec.PrivateKey
}

// PubKey returns the public key of the private key that is abstracted away by
// the interface.
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PrivKeyECDH) PubKey() *btcec.PublicKey {
	return p.PrivKey.PubKey()
}

// ECDH performs a scalar multiplication (ECDH-like operation) between the
// abstracted private key and a remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//	sx := k*P
//	s := sha256(sx.SerializeCompressed())
//
// NOTE: This is part of the SingleKeyECDH interface.
func (p *PrivKeyECDH) ECDH(pub *btcec.PublicKey) ([32]byte, error) {
	return ecdhFromPriv(p.PrivKey, pub), nil
}

var _ SingleKeyECDH = (*PubKeyECDH)(nil)
var _ SingleKeyECDH = (*PrivKeyECDH)(nil)
