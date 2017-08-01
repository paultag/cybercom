/* {{{ Copyright (c) 2017, Paul R. Tagliamonte <paultag@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package store

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
)

var (
	// If the Store has never had a Certificate pushed into the store,
	// the Store must return this error.
	Uninitialized error = fmt.Errorf("cyber store: Uninitialized Store")

	// If the Store has an Expired Certificate, tools that verify the
	// validity (or depend on a valid Certificate) should return this.
	Expired error = fmt.Errorf("cyber store: Expired Certificate")
)

// A Store, at its core, does a single thing. That one thing is to store
// x509 Certificates, Recieve x509 Certificates, and preform Signatures
// using the Private key that relates to the Public key.
//
// This API does not require that the implementation provide the private key.
// This is intentional, since a store that is hardware backed likely ought to
// flat out refuse to provide the private key.
//
// As such, the idea is that this should be as simple as possible. When in
// doubt, force complexity explicitly out of this interface.
//
// This interface is also unaware of the CA. This is the responsibility of
// the caller, and no logic involving who issued the CA is actually needed
// in here.
//
// This type also implements the `crypto.Signer` interface, to be used
// directly by higher level types.
type Store interface {

	// Get the last known Certificate. When the Store is first initialized,
	// and no Certificate is on record, the correct behavior is to return
	// a nil Certificate, and a `store.Uninitialized` error.
	//
	// The application can then take higher level action, such as creating
	// a self-signed Certificate (using Sign below) and calling `Update`.
	//
	// Avoid creating or signing a new Certificate in this function if at all
	// possible.
	Certificate() (*x509.Certificate, error)

	// Store a new copy of the Certificate. After this call, all calls to
	// Certificate above must return this certificate.
	Update(x509.Certificate) error

	// Get the public key that relates to the private key in the store.
	// Most practically, this is used to create a x509.CertificateRequest,
	// so it can be basically anything that it understands.
	Public() crypto.PublicKey

	// Sign (maybe using `rand`) the `digest`, and return the signature.
	// See the `crypto.Signer` interface for more on how this should work
	// (including the details on how hashing is done and passed into this
	// funcntion).
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// Decrypt (maybe using `rand`) the ciphertext `msg`, configured using
	// options `DecrypterOpts`, and return the plaintext.
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

// vim: foldmethod=marker
