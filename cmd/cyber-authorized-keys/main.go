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
	"crypto/rsa"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/urfave/cli"

	"golang.org/x/crypto/ssh"
	"pault.ag/go/gecos"

	"pault.ag/go/cybercom/client"
	"pault.ag/go/cybercom/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "cyber-authorized-keys"
	app.Usage = "dynamically output an authorized-keys file for a user"
	app.Version = version.Version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "server",
			Usage:  "`FQDN:PORT` to connect to",
			Value:  "localhost:2611",
			EnvVar: "CYBERCOM_SERVER",
		},
	}

	app.Action = func(c *cli.Context) error {
		if len(c.Args()) != 1 {
			return cli.ShowAppHelp(c)
		}

		username := c.Args()[0]
		u, err := user.Lookup(username)
		if err != nil {
			return err
		}
		g, err := gecos.Lookup(u)
		if err == gecos.NoGECOSEntry {
			return nil
		}
		if err != nil {
			return err
		}

		client, closer, err := client.New(c.GlobalString("server"), nil, false)
		if err != nil {
			return err
		}
		defer closer()
		entities, err := client.GetEntities()
		if err != nil {
			return err
		}
		for _, entity := range entities {
			if strings.Compare(entity.Email, g.Other) == 0 {
				pub, err := ssh.NewPublicKey(entity.CSR.PublicKey.(*rsa.PublicKey))
				if err != nil {
					return err
				}
				encodedKey := ssh.MarshalAuthorizedKey(pub)
				fmt.Printf("%s %s\n", encodedKey[:len(encodedKey)-1], entity.CSR.Subject.CommonName)
			}
		}
		return nil
	}

	app.Run(os.Args)
}

// vim: foldmethod=marker
