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

package yubikey

import (
	"io"

	"crypto"
	"crypto/x509"

	"pault.ag/go/cybercom/store"
	"pault.ag/go/ykpiv"
)

type Store struct {
	Yubikey *ykpiv.Yubikey
	SlotId  ykpiv.SlotId
	Slot    *ykpiv.Slot
}

func (s Store) Certificate() (*x509.Certificate, error) {
	cert, err := s.Yubikey.GetCertificate(s.SlotId)
	if ykpiv.GenericError.Equal(err) {
		return nil, store.Uninitialized
	}
	return cert, err
}

func (s Store) Update(cert x509.Certificate) error {
	if err := s.Yubikey.Login(); err != nil {
		return err
	}
	if err := s.Yubikey.Authenticate(); err != nil {
		return err
	}
	return s.Yubikey.SaveCertificate(s.SlotId, cert)
}

func (s Store) Public() crypto.PublicKey {
	return s.Slot.PublicKey
}

func (s Store) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := s.Yubikey.Login(); err != nil {
		return nil, err
	}
	return s.Slot.Sign(rand, digest, opts)
}

func (s Store) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if err := s.Yubikey.Login(); err != nil {
		return nil, err
	}
	return s.Slot.Decrypt(rand, msg, opts)
}

func New(yubikey *ykpiv.Yubikey, slotId ykpiv.SlotId, slot *ykpiv.Slot) (*Store, error) {
	return &Store{
		Yubikey: yubikey,
		Slot:    slot,
		SlotId:  slotId,
	}, nil
}

// vim: foldmethod=marker
