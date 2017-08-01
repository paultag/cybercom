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

package simple

import (
	"fmt"
	"io"
	"math/big"
	"time"

	"crypto/x509"
)

// Translator {{{

type Translator struct{}

func (t Translator) CSRToCertificate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	cert := x509.Certificate{
		// RawSubject:         csr.RawSubject,
		// XXX: this was done because OpenSSL creates CSRs that contain the
		//      emailAddress entry in the pkix Subject name. There is now an
		//      explicit search and drop in for this, in the server
		//      implementation.

		Subject:            csr.Subject,
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},

		BasicConstraintsValid: true,
		IsCA: false,
	}
	return &cert, nil
}

// }}}

// Preparer {{{

type Preparer struct {
	Duration    time.Duration
	SerialBytes int
}

func NewPreparer(duration time.Duration, serialBytes int) Preparer {
	return Preparer{
		Duration:    duration,
		SerialBytes: serialBytes,
	}
}

func (sp Preparer) Prepare(rand io.Reader, cert *x509.Certificate) error {
	serialNumber, err := sp.GenerateSerial(rand)
	if err != nil {
		return err
	}
	cert.SerialNumber = serialNumber

	/* Basically, we're going to only set Expiry if they're set to the default
	 * empty value for this struct. Otherwise, we'll (as a matter of policy)
	 * use the existing values. */
	if cert.NotBefore.Year() == 1 || cert.NotAfter.Year() == 1 {
		now := time.Now()
		cert.NotBefore = now
		cert.NotAfter = now.Add(sp.Duration)
	}
	return nil
}

func (sp Preparer) GenerateSerial(rand io.Reader) (*big.Int, error) {
	data := make([]byte, sp.SerialBytes)
	n, err := io.ReadFull(rand, data)
	if err != nil {
		return nil, err
	}
	if n != sp.SerialBytes {
		return nil, fmt.Errorf("cybercom policy simple: not enough calming entropy")
	}

	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(data)

	return serialNumber, nil
}

// }}}

// Policy {{{

type Policy struct {
	CertPool *x509.CertPool
}

func (p Policy) CanAutoSign(cert *x509.Certificate, csr *x509.CertificateRequest) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots: p.CertPool,
	})
	return err
}

func NewPolicy(certPool *x509.CertPool) Policy {
	return Policy{CertPool: certPool}
}

// }}}

// vim: foldmethod=marker
