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

package pb

import (
	"bytes"
	"fmt"

	"crypto"
	"crypto/x509"
)

func (c *Certificate) Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Der)
}

func NewCertificate(cert x509.Certificate) Certificate {
	return Certificate{Der: cert.Raw}
}

func (c *CSR) CertificateRequest() (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(c.Der)
}

func NewCertificateRequest(csr x509.CertificateRequest) CSR {
	return CSR{Der: csr.Raw}
}

func (c *CSR) StringHash() (string, error) {
	id, err := c.Hash()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

func (c *CSR) Hash() ([]byte, error) {
	hashFunc := crypto.SHA256.HashFunc().New()
	_, err := hashFunc.Write(c.Der)
	if err != nil {
		return nil, err
	}
	return hashFunc.Sum(nil), nil
}

func (c *Certificate) Hash() ([]byte, error) {
	hashFunc := crypto.SHA256.HashFunc().New()
	_, err := hashFunc.Write(c.Der)
	if err != nil {
		return nil, err
	}
	return hashFunc.Sum(nil), nil
}

func (c *CSR) Id() (*Id, error) {
	requestId, err := c.Hash()
	if err != nil {
		return nil, err
	}
	return &Id{Id: requestId}, nil
}

func (c *Certificate) Id() (*Id, error) {
	requestId, err := c.Hash()
	if err != nil {
		return nil, err
	}
	return &Id{Id: requestId}, nil
}

func (e *Entity) Validate() error {
	hash, err := e.Csr.Hash()
	if err != nil {
		return err
	}

	if bytes.Compare(hash, e.Id.Id) != 0 {
		return fmt.Errorf("cybercom pb: Given Hash doesn't match CSR Hash")
	}

	csr, err := e.Csr.CertificateRequest()
	if err != nil {
		return err
	}

	return csr.CheckSignature()
}

// vim: foldmethod=marker
