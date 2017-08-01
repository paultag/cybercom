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
	"time"

	"crypto/tls"
)

// Given a `store.Store`, create a `tls.Certificate` out of the
// Store, for use in TLS Connections. This is most helpful to provide
// a TLS Peer Certificate for use in mutual authentication.
func TLSCertificate(store Store) (*tls.Certificate, error) {
	if err := Verify(store); err != nil {
		return nil, err
	}

	cert, err := store.Certificate()
	if err != nil {
		return nil, err
	}
	tlsCertificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  store,
		Leaf:        cert,
	}
	return &tlsCertificate, nil
}

// Check to make sure the provided `store.Store` is not obviously
// unfit for use. This just checks that we:
//
//   * Have a Certificate
//   * It's not before NotBefore
//   * It's not after NotAfter
func Verify(store Store) error {
	cert, err := store.Certificate()
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return Expired
	}
	return nil
}

// vim: foldmethod=marker
