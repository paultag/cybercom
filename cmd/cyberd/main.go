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
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"time"

	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/urfave/cli"

	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"pault.ag/go/cybercom/pb"
	"pault.ag/go/cybercom/policy/simple"
	"pault.ag/go/cybercom/server"
	"pault.ag/go/cybercom/server/db"
	"pault.ag/go/cybercom/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "cyberd"
	app.Usage = "CYBERCOM Server"
	app.Version = version.Version

	var configPath string
	var config *Config

	whoami, err := user.Current()
	if err != nil {
		panic(err)
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config",
			Usage:       "Read CYBERCOM config from `PATH`",
			Value:       path.Join(whoami.HomeDir, "cybercom.json"),
			Destination: &configPath,
		},
	}

	app.Before = func(c *cli.Context) error {
		var err error
		config, err = LoadConfig(configPath)
		if err != nil {
			return err
		}
		return nil
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name: "wipe-and-init",
			Action: func(c *cli.Context) error {
				return Init(c, *config)
			},
		},

		cli.Command{
			Name: "migrateish",
			Action: func(c *cli.Context) error {
				return Migrate(c, *config)
			},
		},

		cli.Command{
			Name: "normalize",
			Action: func(c *cli.Context) error {
				return Normalize(c, *config)
			},
		},

		cli.Command{
			Name: "serve",
			Action: func(c *cli.Context) error {
				return Serve(c, *config)
			},
		},

		cli.Command{
			Name: "generate-crl",
			Action: func(c *cli.Context) error {
				return GenerateCRL(c, *config)
			},
		},
	}

    if err := app.Run(os.Args); err != nil {
        panic(err)
    }
}

type LocalhostAdminEmailACL struct {
	Administrators map[string]bool
	PublicViews    map[string]bool
	AuthedViews    map[string]bool
	AdminViews     map[string]bool
}

func listToSetish(data []string) map[string]bool {
	ret := map[string]bool{}
	for _, el := range data {
		ret[el] = true
	}
	return ret
}

func (a LocalhostAdminEmailACL) Authorize(view string, cert *x509.Certificate, client string) error {
	denied := fmt.Errorf("cybercom acl: ACL denied this action")

	tcpAddr, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		return err
	}

	if tcpAddr.IP.IsLoopback() {
		return nil
	}

	viewIsPublic, _ := a.PublicViews[view]
	if viewIsPublic {
		/* No need to go further */
		return nil
	}

	viewIsAuthed, _ := a.AuthedViews[view]
	if viewIsAuthed {
		if cert == nil {
			return denied
		}
		return nil
	}

	if cert == nil {
		return denied
	}

	var isAdmin bool = false
	for _, email := range cert.EmailAddresses {
		if a.Administrators[email] {
			isAdmin = true
			break
		}
	}

	viewIsAdmin, _ := a.AdminViews[view]
	if viewIsAdmin {
		if isAdmin {
			return nil
		}
		return denied
	}

	return denied
}

func Migrate(c *cli.Context, config Config) error {
	database, err := config.Database.New()
	if err != nil {
		return err
	}
	defer database.Close()

	if err := db.AutoMigrate(database); err != nil {
		return err
	}
	return nil
}

func Init(c *cli.Context, config Config) error {
	database, err := config.Database.New()
	if err != nil {
		return err
	}

	defer database.Close()

	if err := db.DropIfExists(database); err != nil {
		return err
	}

	if err := db.AutoMigrate(database); err != nil {
		return err
	}
	return nil
}

func Serve(c *cli.Context, config Config) error {
	ca, err := config.NewCA()
	if err != nil {
		return err
	}

	pool, err := config.CACertPool()
	if err != nil {
		return err
	}

	caCertificates, err := config.Certificates()
	if err != nil {
		return err
	}

	database, err := config.Database.New()
	if err != nil {
		return err
	}

	defer database.Close()

	reissueGrace, err := time.ParseDuration(config.Certificate.ReissueGrace)
	if err != nil {
		return err
	}

	cyberServer, err := server.New(
		server.Options{
			Name:           config.Name,
			Database:       database,
			CA:             *ca,
			CACertificates: caCertificates,
			Translator:     simple.Translator{},
			ACL: LocalhostAdminEmailACL{
				Administrators: listToSetish(config.ACL.Administrators),
				PublicViews:    listToSetish(config.ACL.PublicViews),
				AuthedViews:    listToSetish(config.ACL.AuthedViews),
				AdminViews:     listToSetish(config.ACL.AdminViews),
			},
			ReissueGrace: reissueGrace,
		},
	)
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", config.ServerAddress)
	if err != nil {
		return err
	}

	cert, err := config.TLS.New()
	if err != nil {
		return err
	}

	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	})

	fmt.Printf("Server booted and ready, serving on %s\n", config.ServerAddress)

	grpcServer := grpc.NewServer(grpc.Creds(ta))
	pb.RegisterCybercomServer(grpcServer, cyberServer)
	grpcServer.Serve(lis)

	return nil
}

func GenerateCRL(c *cli.Context, config Config) error {
	ca, err := config.NewCA()
	if err != nil {
		return err
	}

	database, err := config.Database.New()
	if err != nil {
		return err
	}
	defer database.Close()

	certs, err := db.GetRevokedCertificates(database)
	if err != nil {
		return err
	}

	revokedCertificates := []pkix.RevokedCertificate{}

	for _, cert := range certs {
		x509Cert, err := cert.ParseCertificate()
		if err != nil {
			return err
		}
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{
			SerialNumber:   x509Cert.SerialNumber,
			RevocationTime: cert.UpdatedAt,
		})
	}

	duration, err := time.ParseDuration("24h")
	if err != nil {
		return err
	}
	now := time.Now()
	expiry := now.Add(duration)

	der, err := ca.CreateCRL(rand.Reader, revokedCertificates, now, expiry)
	if err != nil {
		return err
	}

	return pem.Encode(os.Stdout, &pem.Block{
		Bytes: der,
		Type:  "X509 CRL",
	})
}

func Normalize(c *cli.Context, config Config) error {
	database, err := config.Database.New()
	if err != nil {
		return err
	}
	defer database.Close()

	certs := []db.Certificate{}
	if err := database.Find(&certs).Error; err != nil {
		return err
	}

	for _, cert := range certs {
		update := false

		if len(cert.Serial) == 0 {
			xcert, err := x509.ParseCertificate(cert.Certificate)
			if err != nil {
				return err
			}
			cert.Serial = xcert.SerialNumber.Bytes()
			update = true
		}

		if update {
			log.Printf("Updating: %s", cert.Hash)
			database.Save(cert)
		}
	}

	return nil
}

// vim: foldmethod=marker
