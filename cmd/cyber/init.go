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

package main

import (
	"fmt"
	"os/user"

	"crypto/rand"
	"crypto/x509"

	"github.com/chzyer/readline"
	"github.com/urfave/cli"

	"pault.ag/go/gecos"
	"pault.ag/go/ykpiv"

	"pault.ag/go/cybercom/client"
	"pault.ag/go/cybercom/store"
	"pault.ag/go/cybercom/store/yubikey"
)

func WhatsMyEmail() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return []string{}, err
	}
	g, err := gecos.Lookup(u)
	if err == gecos.NoGECOSEntry {
		return []string{}, nil
	}
	if err != nil {
		return []string{}, err
	}
	return []string{g.Other}, nil
}

func GenerateYubikeyStore(c *cli.Context, token *ykpiv.Yubikey, slotId *ykpiv.SlotId, bits int) (*yubikey.Store, error) {
	if err := token.Login(); err != nil {
		return nil, err
	}

	if err := token.Authenticate(); err != nil {
		return nil, err
	}

	slot, err := token.GenerateRSA(*slotId, bits)
	if err != nil {
		return nil, err
	}

	return yubikey.New(token, *slotId, slot)
}

func InitYubikey(c *cli.Context) ([]byte, error) {
	token, err := NewYkpiv(c)
	if err != nil {
		return nil, err
	}
	slotId, err := StringToYubikeySlotId(c.GlobalString("yubikey-slot"))
	if err != nil {
		return nil, err
	}

	rl, err := readline.New("> ")
	if err != nil {
		return nil, err
	}

	slot, _ := token.Slot(*slotId)
	if slot != nil {
		fmt.Printf("Existing CN=%s\n", slot.Certificate.Subject.CommonName)
	}

	if err := confirm(rl, fmt.Sprintf("Wipe the %s slot?", slotId)); err != nil {
		return nil, err
	}

	fmt.Printf("Hang tight, generating RSA 2048 key\n")

	store, err := GenerateYubikeyStore(c, token, slotId, 2048)
	if err != nil {
		return nil, err
	}
	client, closer, err := NewClient(c, nil)
	if err != nil {
		return nil, err
	}
	defer closer()

	csr, err := CreateCSR(rl, c, store, client)
	if err != nil {
		return nil, err
	}

	id, err := client.Register(*csr)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func CreateCSR(rl *readline.Instance, c *cli.Context, store store.Store, client *client.Client) (*x509.CertificateRequest, error) {
	configuration, err := client.GetConfiguration()
	if err != nil {
		return nil, err
	}

	subject, err := configuration.HostTemplate()
	if err != nil {
		return nil, err
	}

	emailAddresses, err := WhatsMyEmail()
	if err != nil {
		return nil, err
	}

	emailAddresses, err = promptUserList(rl, "EmailAddress", emailAddresses)
	if err != nil {
		return nil, err
	}

	subject, err = confirmSubjectName(rl, *subject)
	if err != nil {
		return nil, err
	}

	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        *subject,
		EmailAddresses: emailAddresses,
	}, store)

	return x509.ParseCertificateRequest(csrDer)
}

func InitFilesystem(c *cli.Context) ([]byte, error) {
	store, err := NewFilesystemStore(c)
	if err != nil {
		return nil, err
	}

	rl, err := readline.New("> ")
	if err != nil {
		return nil, err
	}

	client, closer, err := NewClient(c, nil)
	if err != nil {
		return nil, err
	}
	defer closer()

	csr, err := CreateCSR(rl, c, store, client)
	if err != nil {
		return nil, err
	}

	id, err := client.Register(*csr)
	if err != nil {
		return nil, err
	}
	return id, nil
}

func Init(c *cli.Context) error {
	store := c.GlobalString("store")
	var id []byte
	var err error

	switch store {
	case "yubikey":
		id, err = InitYubikey(c)
	case "filesystem":
		id, err = InitFilesystem(c)
	case "nil":
		return nil
	default:
		return fmt.Errorf("No such store: '%s'", store)
	}

	if err != nil {
		return err
	}

	fmt.Printf("Registered %x\n", id)
	return nil
}

var InitCommand = cli.Command{
	Name:   "init",
	Action: Wrapper(Init),
	Usage:  "Initialize the Store",
	Flags:  []cli.Flag{},
}

// vim: foldmethod=marker
