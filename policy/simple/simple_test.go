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

package simple_test

import (
	"bytes"
	"io"
	"log"
	"testing"
	"time"

	"crypto/x509"
	"encoding/pem"

	"pault.ag/go/cybercom/policy/simple"
)

// CSR Test Data {{{
var csr string = `-----BEGIN CERTIFICATE REQUEST-----
MIICnTCCAYcCAQAwWjEgMB4GA1UEAwwXUGF1bCBUYWdsaWFtb250ZSAodGVzdCkx
EjAQBgNVBAoMCUJpa2UgU2hlZDEiMCAGCSqGSIb3DQEJARYTcGF1bHRhZ0BleGFt
cGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjh2lJ2xOy3
ukRwj4x17CioYsdlsjlbfTWV79NJnA/dKcOdpg3BCQTsJndx6cCVOgWlDSSFO789
KHt5ynjKTmNO7mWwgkdbqfvXgX6v0yuRhV6uB4umXHAjKna/Dns0bEDH0IytwZiY
Qt4dqAMhFB32AC/2n5xWVdrRzQByo7FSfYxot/Phmu4YBHoo5hPZkUouI7vYVNSB
2+pTbQll34PLNB1g7/Vq5VmgK4VsaTj9g5SCVBcqzh2CpO2F7myo6TodZ/4qNcgg
LONzdV7bLwOarubvWGcB5MkDdoamdMpJOWatpw2lRrhMJJWnv8q34OGKgd8FiQwN
M6lq303XyMECAwEAAaAAMAsGCSqGSIb3DQEBCwOCAQEAgEdtNnDJYWQuutj4UAD/
uUdF7BNHERHut26pATfkaoXvAarrtlxJz/ozRDe3oaByRzMlRiqLvSHUPvuhNrB8
Y8tn8kxgz8aEdrnxZLp6khEMcF3RfQ/TZ4d2RdOJn1NOd17JG2z5hsXlJ3gkxTZV
fRLcCdlfNx5cnLai6kfYFUZkSgXQDizeDA4Ipiist/60/U5DQdY9ZUiKt3npHlXR
lG0YZTyHuiFwFVlBYVvAiGI98M/K9qcqH0h6nkB3vmhewAMNEnEpGsf4YNsTMFW/
4f3q62MrgIDdULY28OqD2r6vuYkjEKfDoUFFlyHRqeqhTzSK5iU8vTK5KluxdtcY
Kw==
-----END CERTIFICATE REQUEST-----
`

func getCSR() x509.CertificateRequest {
	der, _ := pem.Decode([]byte(csr))
	csr, err := x509.ParseCertificateRequest(der.Bytes)
	if err != nil {
		panic(err)
	}
	return *csr
}

// }}}

// Helpers {{{

func isok(t *testing.T, err error) {
	if err != nil && err != io.EOF {
		log.Printf("Error! Error is not nil! %s\n", err)
		t.FailNow()
	}
}

func notok(t *testing.T, err error) {
	if err == nil {
		log.Printf("Error! Error is nil!\n")
		t.FailNow()
	}
}

func assert(t *testing.T, expr bool) {
	if !expr {
		log.Printf("Assertion failed!")
		t.FailNow()
	}
}

// }}}

// Translator {{{

func TestTranslator(t *testing.T) {
	csr := getCSR()
	cert, err := simple.Translator{}.CSRToCertificate(&csr)
	isok(t, err)
	assert(t, csr.Subject.CommonName == cert.Subject.CommonName)
}

// }}}

// Preparer {{{

func TestPreparer(t *testing.T) {
	duration, err := time.ParseDuration("1s")
	isok(t, err)
	csr := getCSR()
	cert, err := simple.Translator{}.CSRToCertificate(&csr)
	isok(t, err)
	totallyRandomReader := bytes.NewBuffer([]byte("AAAAAAAAAAAAAAAA"))
	isok(t, simple.NewPreparer(duration, 16).Prepare(totallyRandomReader, cert))
	assert(t, csr.Subject.CommonName == cert.Subject.CommonName)
	assert(t, cert.SerialNumber.BitLen() == 127)
	assert(t, cert.NotAfter.Sub(cert.NotBefore).Seconds() == 1)
}

// }}}

// vim: foldmethod=marker
