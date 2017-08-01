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

package ca

import (
	"fmt"
	"io"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"

	"pault.ag/go/cybercom/policy"
	"pault.ag/go/cybercom/store"
)

// Encapsulation of a Certificate Authority. This has a set of defined
// operations to be used in conjunction with other packages in this
// library, such as a keystore.
//
// This struct and collection of functions exists only to sign CSRs and
// preform other CA operations that require a private key. The behavior of
// this module is designed to be simple, predictable, and default to sane
// and safe behavior.
type CA struct {
	Store    store.Store
	Preparer policy.Preparer
}

// Create an x509.CertPool out of our Certificate. In the future this function
// is likely to output all known root and intermediary Certificates.
func (c CA) CertPool() (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	caCert, err := c.Store.Certificate()
	if err != nil {
		return nil, err
	}
	certPool.AddCert(caCert)
	return certPool, nil
}

// Sign an x509.Certificate template (as one would pass to CreateCertificate)
// without first running it through the CA's Preparer. This is usually a very
// dangerous and ill advised move, since this will bypas the controls and
// policies the CA has put into place.
//
// The only exception to this rule is if the Certificate was put through the
// Preparer in the code block calling this, and has explicitly overridden
// known defaults in a thoughtful and meaningful way.
//
// There are no safey checks to see if signing this Certificate is, in fact,
// a good idea, this will just sign a given Certificate with the CA
// key.
func (c CA) SignWithoutPreparing(rand io.Reader, template *x509.Certificate) ([]byte, error) {
	caCert, err := c.Store.Certificate()
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(
		rand,
		template,
		caCert,
		template.PublicKey,
		c.Store,
	)
}

// Sign an x509.Certificate template (as one would pass to CreateCertificate)
// first running it through the given CA Preparer. This will set things like
// the Serial, NotAfter and NotBefore.
//
// There are no safey checks to see if signing this Certificate is, in fact,
// a good idea, this will just sign a given Certificate with the CA
// key.
func (c CA) Sign(rand io.Reader, template *x509.Certificate) ([]byte, error) {
	caCert, err := c.Store.Certificate()
	if err != nil {
		return nil, err
	}

	if err := c.Preparer.Prepare(rand, template); err != nil {
		return nil, err
	}

	return x509.CreateCertificate(
		rand,
		template,
		caCert,
		template.PublicKey,
		c.Store,
	)
}

// Do basic checking to see if someone is using a obviously wrong Certificate
// for running a CA, such as the IsCA attribute, and double checking we do,
// in fact, have a Certificate.
func sanityCheckCAStore(caStore store.Store) error {
	cert, err := caStore.Certificate()
	if err != nil {
		return err
	}
	if !cert.IsCA {
		return fmt.Errorf("cybercom ca: CA Certificate is marked IsCA: false")
	}
	return nil
}

// Create a new CA Struct from the given `store.Store` and `policy.Preparer`.
//
// This will double check the provided CA is valid for purposes of CA Signing.
func New(
	caStore store.Store,
	preparer policy.Preparer,
) (*CA, error) {
	if err := sanityCheckCAStore(caStore); err != nil {
		return nil, err
	}
	return &CA{
		Store:    caStore,
		Preparer: preparer,
	}, nil
}

func (c CA) CreateCRL(rand io.Reader, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) ([]byte, error) {
	caCert, err := c.Store.Certificate()
	if err != nil {
		return nil, err
	}
	return caCert.CreateCRL(rand, c.Store, revokedCerts, now, expiry)
}

// vim: foldmethod=marker
