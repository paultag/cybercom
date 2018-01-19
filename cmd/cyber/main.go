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
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/cybercom/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "cyber"
	app.Usage = "read, write and manage x509 Certificates"
	app.Version = version.Version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "server",
			Usage:  "`FQDN:PORT` to connect to",
			Value:  "localhost:2611",
			EnvVar: "CYBERCOM_SERVER",
		},

		cli.BoolFlag{
			Name:   "insecure",
			Usage:  "Ignore TLS verification",
			EnvVar: "CYBERCOM_INSECURE",
		},

		cli.StringFlag{
			Name:   "store",
			Usage:  "Backend store to use",
			Value:  "filesystem",
			EnvVar: "CYBERCOM_STORE",
		},

		cli.StringFlag{
			Name:   "yubikey-pin",
			Usage:  "PIN to the Yubikey",
			EnvVar: "CYBERCOM_YUBIKEY_PIN",
		},

		cli.BoolFlag{
			Name:   "yubikey-management-key-is-pin",
			Usage:  "Yubikey Management Key is PIN, as set by pivman",
			EnvVar: "CYBERCOM_YUBIKEY_MANAGEMENT_KEY_IS_PIN",
		},

		cli.StringFlag{
			Name:   "yubikey-management-key",
			Usage:  "Yubikey Management Key in Hex",
			EnvVar: "CYBERCOM_YUBIKEY_MANAGEMENT_KEY",
		},

		cli.StringFlag{
			Name:   "yubikey-reader",
			Value:  "Yubikey",
			Usage:  "Which Yubikey to work off of",
			EnvVar: "CYBERCOM_YUBIKEY_READER",
		},

		cli.StringFlag{
			Name:   "yubikey-slot",
			Value:  "authentication",
			Usage:  "Which slot of the Yubikey to use",
			EnvVar: "CYBERCOM_YUBIKEY_SLOT",
		},
	}

	app.Commands = []cli.Command{
		WhoamiCommand,
		InitCommand,
		RenewCommand,
		GetCommand,
		LsCommand,
		SSHKeygenCommand,
		GetCertificatesCommand,
		IssueCertificateCommand,
		ImportCommand,
		RemindCommand,
		SetStateCommand,
		SetLongevityCommand,
		SetExpiryCommand,
		PingCommand,
		CACommand,
		SignCSRCommand,
		CertificateBySerialCommand,
	}

	app.Run(os.Args)
}

// vim: foldmethod=marker
