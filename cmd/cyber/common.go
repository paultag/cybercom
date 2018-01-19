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
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"crypto/x509"

	"github.com/chzyer/readline"
	"github.com/dustin/go-humanize"
	"github.com/urfave/cli"

	"pault.ag/go/technicolor"
	"pault.ag/go/ykpiv"

	"pault.ag/go/cybercom/client"
	"pault.ag/go/cybercom/store"
	"pault.ag/go/cybercom/store/filesystem"
	"pault.ag/go/cybercom/store/yubikey"
	"pault.ag/go/cybercom/utils"
)

func PrintEntity(entity *client.Entity, csr bool) error {
	if csr {
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:    "CERTIFICATE REQUEST",
			Headers: map[string]string{},
			Bytes:   entity.CSR.Raw,
		}); err != nil {
			return err
		}
		return nil
	}

	output := technicolor.NewTerminalWriter(os.Stdout)
	switch entity.State.String() {
	case "APPROVED", "ONEOFF":
		output = output.Green()
	case "REVOKED", "REJECTED":
		output = output.Bold().Red()
	case "PENDING", "UNKNOWN":
		output = output.Yellow()
	}

	output.Printf(
		"%x %s %s %s\n",
		entity.Id,
		entity.State,
		entity.Email,
		entity.CSR.Subject.CommonName,
	)

	output.ResetColor().Write([]byte{})
	return nil
}

func PrintEntityDetails(entity *client.Entity) error {
	output := technicolor.NewTerminalWriter(os.Stdout)
	switch entity.State.String() {
	case "APPROVED", "ONEOFF":
		output = output.Green()
	case "REVOKED", "REJECTED":
		output = output.Bold().Red()
	case "PENDING", "UNKNOWN":
		output = output.Yellow()
	}

	fmt.Printf("ID:           %x\n", entity.Id)
	fmt.Printf("Email:        %s\n", entity.Email)
	fmt.Fprintf(output, "State:        %s\n", entity.State)
	output.ResetColor().Write([]byte{})

	if entity.Longevity != nil {
		fmt.Printf("Longevity:    %s\n", *entity.Longevity)
	}
	if entity.Expires != nil {
		output := outputTimeColor(os.Stdout, *entity.Expires)
		output.Printf("Expires:      %s\n", humanize.Time(*entity.Expires))
		output.ResetColor().Write([]byte{})
	}

	output.ResetColor().Write([]byte{})
	return nil
}

func outputTimeColor(w *os.File, when time.Time) technicolor.Writer {
	return outputDurationColor(w, when.Sub(time.Now()))
}

func outputDurationColor(w *os.File, expiryDuration time.Duration) technicolor.Writer {
	output := technicolor.NewTerminalWriter(w)
	warningDuration := time.Second * 604800
	criticalDuration := time.Second * 172800

	switch {
	case expiryDuration < criticalDuration:
		return output.Bold().Red()
	case expiryDuration < warningDuration:
		return output.Bold().Yellow()
	default:
		return output.Green()
	}
}

func PrintCertificate(cert x509.Certificate) {
	fmt.Printf("Subject:   %s\n", utils.SubjectToString(cert.Subject))
	fmt.Printf("Serial:    %x\n", cert.SerialNumber)
	fmt.Printf("NotBefore: %s\n", humanize.Time(cert.NotBefore))

	output := outputTimeColor(os.Stdout, cert.NotAfter)
	output.Printf("NotAfter:  %s\n", humanize.Time(cert.NotAfter))
	output.ResetColor().Write([]byte{})
}

func NewYkpiv(c *cli.Context) (*ykpiv.Yubikey, error) {
	pin := c.GlobalString("yubikey-pin")
	managementKeyString := c.GlobalString("yubikey-management-key")
	managementKey := []byte{}

	if pin == "" {
		pinBytes, err := readline.Password("Enter PIN: ")
		if err != nil {
			return nil, err
		}
		pin = string(pinBytes)
	}

	if len(managementKeyString) != 0 {
		var err error
		managementKey, err = hex.DecodeString(managementKeyString)
		if err != nil {
			return nil, err
		}
	}

	return ykpiv.New(ykpiv.Options{
		Reader:             c.GlobalString("yubikey-reader"),
		PIN:                &pin,
		ManagementKey:      managementKey,
		ManagementKeyIsPIN: c.GlobalBool("yubikey-management-key-is-pin"),
	})
}

func StringToYubikeySlotId(s string) (*ykpiv.SlotId, error) {
	switch s {
	case "signature":
		return &ykpiv.Signature, nil
	case "authentication":
		return &ykpiv.Authentication, nil
	default:
		return nil, fmt.Errorf("No such Slot ID: '%s'", s)
	}
}

func NewYubikeyStore(c *cli.Context) (*yubikey.Store, error) {
	token, err := NewYkpiv(c)
	if err != nil {
		return nil, err
	}
	slotId, err := StringToYubikeySlotId(c.GlobalString("yubikey-slot"))
	if err != nil {
		return nil, err
	}

	slot, err := token.Slot(*slotId)
	if err != nil && !ykpiv.GenericError.Equal(err) {
		return nil, err
	}
	return yubikey.New(token, *slotId, slot)
}

func NewFilesystemStore(c *cli.Context) (*filesystem.Store, error) {
	whoami, err := user.Current()
	if err != nil {
		return nil, err
	}

	server := c.GlobalString("server")
	root := filepath.Join(whoami.HomeDir, ".config", "cybercom", server, "store")
	err = os.MkdirAll(root, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return filesystem.New(root)
}

func NewStore(c *cli.Context) (store.Store, error) {
	store := c.GlobalString("store")
	switch store {
	case "yubikey":
		return NewYubikeyStore(c)
	case "filesystem":
		return NewFilesystemStore(c)
	case "nil":
		return nil, nil
	default:
		return nil, fmt.Errorf("No such store: '%s'", store)
	}
}

func NewClient(c *cli.Context, store store.Store) (*client.Client, func() error, error) {
	return client.New(c.GlobalString("server"), store, c.GlobalBool("insecure"))
}

func Wrapper(cmd func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if err := cmd(c); err != nil {
			panic(err)
		}
		return nil
	}
}

// vim: foldmethod=marker
