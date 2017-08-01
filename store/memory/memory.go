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

package memory

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"pault.ag/go/cybercom/store"
)

func New() (*Store, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	return &Store{
		privateKey: privateKey,
	}, nil
}

type Store struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

func (s *Store) Certificate() (*x509.Certificate, error) {
	if s.certificate == nil {
		return nil, store.Uninitialized
	}
	return s.certificate, nil
}

func (s *Store) Update(certificate x509.Certificate) error {
	s.certificate = &certificate
	return nil
}

func (s *Store) Public() crypto.PublicKey {
	return s.privateKey.Public()
}

func (s *Store) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privateKey.Sign(rand, digest, opts)
}

func (s *Store) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return s.privateKey.Decrypt(rand, msg, opts)
}

// vim: foldmethod=marker
