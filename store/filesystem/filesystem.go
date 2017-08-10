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

package filesystem

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"pault.ag/go/cybercom/store"
)

// Create a new Filesystem Store. This is basically just a directory full
// of Certificates dumped there. Pretty boring, and a bit, well, insecure,
// but this is an example (and simple!) Store that will work for small
// and well controled deployments.
func New(path string) (*Store, error) {
	rsaPrivateKey, err := getRSAKey(filepath.Join(path, "store.key"))
	if err != nil {
		// Yikes. We couldn't even make an RSA key. Something nasty happened.
		return nil, err
	}

	return &Store{
		RootPath:   filepath.Clean(path),
		privateKey: rsaPrivateKey,
	}, nil
}

func getRSAKey(path string) (*rsa.PrivateKey, error) {
	fd, err := os.Open(path)
	if err == nil {
		/* Optimistic! Neato! Let's read this out! */
		privateKeyBytes, err := ioutil.ReadAll(fd)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(privateKeyBytes)
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	/* Right, what shit went down here */
	if !os.IsNotExist(err) {
		/* So, it's not just that it's not there, that's no beuno. Let's
		 * yell at th caller :'( */
		return nil, err
	}

	/* Fine, right, neat. Let's make an RSA Key and write it to disk */
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}

	/* Right, now let's dump the PKCS1 to disk */
	bytes := x509.MarshalPKCS1PrivateKey(privateKey)
	fd, err = os.Create(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	err = pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes})
	if err != nil {
		return nil, err
	}

	/* Just to make sure it worked, let's recurse. I wonder if we'll ever
	 * loop forever because we never sync the call or something. */
	return getRSAKey(path)
}

// Directory layout:
//
// RootPath (passed in `New`)
//  -> store.crt  (x509 Certificate)
//  -> store.key  (RSA private key)
//
type Store struct {
	RootPath   string
	privateKey *rsa.PrivateKey
}

// Read the Certificate off disk.
func (s Store) Certificate() (*x509.Certificate, error) {
	fd, err := os.Open(filepath.Join(s.RootPath, "store.crt"))
	if os.IsNotExist(err) {
		return nil, store.Uninitialized
	}
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	certificateBytes, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certificateBytes)
	return x509.ParseCertificate(block.Bytes)
}

// Write the Certificate to the disk.
func (s Store) Update(certificate x509.Certificate) error {
	fd, err := os.Create(filepath.Join(s.RootPath, "store.crt"))
	if err != nil {
		return err
	}
	return pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

// We pull the PrivateKey off disk during init, and we keep it in memory,
// since the interface has no error param passed out with it, so let's ensure
// we don't error out.
func (s Store) Public() crypto.PublicKey {
	return s.privateKey.Public()
}

// We pull the PublicKey off disk during init, and we keep it in memory.
// Proxy the Sign method of the RSA PrivateKey.
func (s Store) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privateKey.Sign(rand, digest, opts)
}

// We pull the PublicKey off disk during init, and we keep it in memory.
// Proxy the Decrypt method of the RSA PrivateKey.
func (s Store) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return s.privateKey.Decrypt(rand, msg, opts)
}

// vim: foldmethod=marker
