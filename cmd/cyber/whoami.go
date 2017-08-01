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
	"encoding/pem"
	"fmt"
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/cybercom/store/filesystem"
	"pault.ag/go/cybercom/store/yubikey"
)

func Whoami(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	switch store.(type) {
	case *filesystem.Store:
		fs := store.(*filesystem.Store)
		fmt.Printf("Type:     filesystem\n")
		fmt.Printf("Location: %s\n", fs.RootPath)
	case *yubikey.Store:
		yk := store.(*yubikey.Store)
		fmt.Printf("Type:    yubikey\n")
		fmt.Printf("Slot:    %s\n", yk.SlotId)
	default:
		fmt.Printf("Crypto store is of an unknown type\n")
	}

	fmt.Printf("\n")

	cert, err := store.Certificate()
	if err != nil {
		return err
	}

	PrintCertificate(*cert)
	if c.Bool("cert") {
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   cert.Raw,
		}); err != nil {
			return err
		}
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()

	fmt.Printf("\nConnecting to the CYBERCOM Server...\n\n")

	configuration, err := client.GetConfiguration()
	if err != nil {
		return err
	}

	fmt.Printf("Connected To: %s\n", configuration.Name())
	entity, err := configuration.Entity()
	if err != nil {
		return err
	}

	if entity == nil {
		fmt.Printf("ID:           <none>\n")
		fmt.Printf("\nThe server doesn't know who we are.\n\n")
	} else {
		PrintEntityDetails(entity)
	}

	return nil
}

var WhoamiCommand = cli.Command{
	Name:   "whoami",
	Action: Wrapper(Whoami),
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "cert",
			Usage: "Output the x509 Certificate we're issued",
		},
	},
	Usage: "Display store state and attempt to connect to the server",
}

// vim: foldmethod=marker
