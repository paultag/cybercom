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
	"encoding/hex"
	"fmt"

	"crypto/rsa"

	"github.com/urfave/cli"

	"golang.org/x/crypto/ssh"
)

func SSHKeygen(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()

	for _, arg := range c.Args() {
		id, err := hex.DecodeString(arg)
		if err != nil {
			return err
		}

		entity, err := client.GetEntity(id)
		if err != nil {
			return err
		}
		pub, err := ssh.NewPublicKey(entity.CSR.PublicKey.(*rsa.PublicKey))
		if err != nil {
			return err
		}

		// XXX: if this ever gets better, fix this. this takes the newline off
		// and addes a comment with the CN. It should take a comment argument
		// or at least not end in a newline.
		encodedKey := ssh.MarshalAuthorizedKey(pub)
		fmt.Printf("%s %s\n", encodedKey[:len(encodedKey)-1], entity.CSR.Subject.CommonName)
	}

	return nil

}

var SSHKeygenCommand = cli.Command{
	Name:     "ssh-keygen",
	Action:   Wrapper(SSHKeygen),
	Category: "misc",
	Usage:    "Output the entity's public key in ssh key format",
}

// vim: foldmethod=marker
