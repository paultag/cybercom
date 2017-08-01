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

package policy

import (
	"io"

	"crypto/x509"
)

type Preparer interface {
	// This takes a template x509 Certificate, and prepares it for signing
	// according to CA policy.
	//
	// Bare minimum things this ought to do:
	//
	//  - Set the Serial Number to something secure
	//  - Set the NotBefore and NotAfter
	//  - Set any Key Usage bits
	//  - Set IsCA and friends
	//
	Prepare(io.Reader, *x509.Certificate) error
}

type Translator interface {
	// This defines the process by which a CSR is turned into a Certificate
	// template.
	CSRToCertificate(*x509.CertificateRequest) (*x509.Certificate, error)
}

// vim: foldmethod=marker
