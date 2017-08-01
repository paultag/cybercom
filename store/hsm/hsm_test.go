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

package hsm_test

import (
	"io"
	"log"
	"os/exec"
	"testing"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"pault.ag/go/cybercom/store/hsm"
	"pault.ag/go/cybercom/store/memory"
)

var softHSMTestLabel = "CYBERCOM-TEST"
var softHSMModule = "/usr/lib/softhsm/libsofthsm2.so"
var hsmStore *hsm.Store

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

func assert(t *testing.T, expr bool, why string) {
	if !expr {
		log.Printf("Assertion failed: %s", why)
		t.FailNow()
	}
}

// }}}

func deleteSoftHSM() error {
	err := exec.Command(
		"softhsm2-util",
		"--delete-token",
		"--token", softHSMTestLabel,
	).Run()
	if err != nil {
		if err.Error() == "exit status 1" {
			/* This happens if we try to kill something that doesn't exist yet? */
			return nil
		}
	}
	return err
}

func initSoftHSM() error {
	if err := exec.Command(
		"softhsm2-util",
		"--init-token",
		"--label",
		softHSMTestLabel,
		"--free",
		"--pin", "1234",
		"--so-pin", "123456",
	).Run(); err != nil {
		return err
	}

	return exec.Command(
		"pkcs11-tool",
		"--module", softHSMModule,
		"--login",
		"--pin", "1234",
		"--keypairgen",
		"--label", "PIV AUTH key",
		"--key-type", "rsa:1024",
	).Run()
}

func setUp(t *testing.T) (*hsm.Store, error) {
	if hsmStore != nil {
		return hsmStore, nil
	}
	isok(t, deleteSoftHSM())
	isok(t, initSoftHSM())
	hsmPIN := "1234"
	hsm, err := hsm.New(hsm.Config{
		TokenLabel:       softHSMTestLabel,
		Module:           softHSMModule,
		CertificateLabel: "Certificate for PIV Authentication",
		PrivateKeyLabel:  "PIV AUTH key",
		PIN:              &hsmPIN,
	})
	hsmStore = hsm
	return hsm, err
}

func TestHSMCreation(t *testing.T) {
	store, err := setUp(t)
	isok(t, err)

	pubkey := store.Public()
	assert(t, pubkey != nil, "pubkey was nil")
}

func TestHSMSigning(t *testing.T) {
	store, err := setUp(t)
	isok(t, err)

	memoryStore, err := memory.New()
	isok(t, err)

	assert(t, memoryStore != nil, "memoryStore was nil")

	pubkey := store.Public()
	assert(t, pubkey != nil, "pubkey was nil")

	now := time.Now()
	oneDay, err := time.ParseDuration("24h")
	isok(t, err)

	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: "Joe"},
		NotBefore:    now,
		NotAfter:     now.Add(oneDay),
		SerialNumber: big.NewInt(10),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, store)
	isok(t, err)
	assert(t, len(cert) > 0, "cert der was nil")
}

// vim: foldmethod=marker
