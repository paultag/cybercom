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

package client

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"time"

	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"golang.org/x/net/context"

	"pault.ag/go/cybercom/pb"
	"pault.ag/go/cybercom/store"
)

// Create a new CYBERCOM Client. Connect to the given `server` (with the
// server Certificate validated out of `certPool`), authenticating to the
// server as `cyberStore`, if the Store has been Initalized.
//
// This returns a tripple of a `Client`, a function to close the open
// connection (usually by `defer`ing the call, if err is nil), and
// any errors we hit during the bringup of the client.
func New(server string, cyberStore store.Store, insecure bool) (*Client, func() error, error) {
	certs := []tls.Certificate{}

	if cyberStore != nil {
		cert, err := store.TLSCertificate(cyberStore)
		if err == nil {
			certs = append(certs, *cert)
		} else {
			if err != store.Uninitialized && err != store.Expired {
				// If we have an error that we don't know we can duck, go ahead
				// and return it now.
				return nil, nil, err
			}
		}
	}

	ta := credentials.NewTLS(&tls.Config{
        Certificates: certs,
        InsecureSkipVerify: insecure,
    })

	conn, err := grpc.Dial(server, grpc.WithTransportCredentials(ta))
	if err != nil {
		return nil, nil, err
	}

	grpclog.SetLogger(log.New(ioutil.Discard, "", 0))

	client := pb.NewCybercomClient(conn)
	return &Client{
		client:        client,
		Store:         cyberStore,
		authenticated: len(certs) != 0,
	}, conn.Close, nil
}

// Encapsulation that holds internal state data. The only publically accessable
// member is the underlying Store, if access to that is helpful, it may be
// safely used.
type Client struct {
	client        pb.CybercomClient
	authenticated bool

	pool  x509.CertPool
	Store store.Store
}

// HasClientCertificate {{{

// Check to see if we sent a TLS Peer Certificate for use during mutual
// authentication. If this is `true`, the server may have still rejected our
// certifciate. To check what the Server thinks of us, you may request
// information on ourselves using the `GetConfiguration` RPC, reading the
// peer certificate off that.
func (c Client) HasClientCertificate() bool {
	return c.authenticated
}

// }}}

// EntityState {{{

// Helper function to SetEntityState to any of the known `pb.Entity_State`
// values. This isn't exposed, since users of the Client ought to only
// be bothered to use Go builtins to talk to the Cybercom server.
func (c Client) setEntityState(id []byte, state pb.Entity_State) error {
	entity, err := c.client.GetEntity(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return err
	}
	entity.State = state
	_, err = c.client.SetEntityState(context.Background(), entity)
	return err
}

// Set the entity with the ID of `id` to `APPROVED`. The exact nature of what
// this means is entirely up to the server, but commonly implies that the
// entity is fit to be issued a Certificate.
func (c Client) SetEntityStateApproved(id []byte) error {
	return c.setEntityState(id, pb.Entity_APPROVED)
}

// Set the entity with the ID of `id` to `REJECTED`. The exact nature of what
// this means is entirely up to the server, but commonly implies that the
// entity is unfit to be issued a Certificate and has never passed a basic
// check.
func (c Client) SetEntityStateRejected(id []byte) error {
	return c.setEntityState(id, pb.Entity_REJECTED)
}

// Set the entity with the ID of `id` to `PENDING`. The exact nature of what
// this means is entirely up to the server, but commonly implies that the
// entity is new, and has not been processed by an administrator.
func (c Client) SetEntityStatePending(id []byte) error {
	return c.setEntityState(id, pb.Entity_PENDING)
}

// Set the entity with the ID of `id` to `REVOKED`. The exact nature of what
// this means is entirely up to the server, but commonly implies that the
// entity was valid, but due to some issue (leaked private key, removal
// from the organization) is no longer suitable.
func (c Client) SetEntityStateRevoked(id []byte) error {
	return c.setEntityState(id, pb.Entity_REVOKED)
}

// Set the entity with the ID of `id` to `ONEOFF`. The exact nature of what
// this means is entirely up to the server, but commonly implies that the
// entity is only entitled to a single Certificate. This can be useful to
// grant an Entity time-limited access to the network, and would likely be
// used in conjuction with an end-date.
func (c Client) SetEntityStateOneOff(id []byte) error {
	return c.setEntityState(id, pb.Entity_ONEOFF)
}

// }}}

// EntityExpiry {{{

// Set the Expiry of the Entity. This means that after this point, this Entity
// is not suitable to be granted an active Certificate. Any Certificate issued
// near the end of this time will be capped at the Expiry.
func (c Client) SetEntityExpiry(id []byte, expiry *time.Time) error {
	entity, err := c.client.GetEntity(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return err
	}

	if expiry == nil {
		entity.Expires = 0
	} else {
		entity.Expires = uint64(expiry.Unix())
	}
	_, err = c.client.SetEntityExpiry(context.Background(), entity)
	return err
}

// }}}

// EntityLongevity {{{

// Set the Longevity of the Entity. This means that the Certificate we issue
// will have a NotAfter this time in the future from the given duration.
func (c Client) SetEntityLongevity(id []byte, longevity string) error {
	// XXX: time.ParseDuration on the longevity and double check it's valid
	entity, err := c.client.GetEntity(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return err
	}
	entity.Longevity = longevity
	_, err = c.client.SetEntityLongevity(context.Background(), entity)
	return err
}

// }}}

// IssueCertificate {{{

// Issue a new Certificate for the Entity. The exact rules for what this means
// are up to the server, but commonly this will throw an error if the Entity
// is not entitled to a new Certificate, or if the user preforming this action
// is not authorized to do so.
func (c Client) IssueCertificate(id []byte) (*x509.Certificate, error) {
	cert, err := c.client.IssueCertificate(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return nil, err
	}
	if cert.Der == nil {
		return nil, nil
	}
	return x509.ParseCertificate(cert.Der)
}

// }}}

// GetEntity {{{

// Get the Entity known by the ID `id`.
func (c Client) GetEntity(id []byte) (*Entity, error) {
	pbEntity, err := c.client.GetEntity(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return nil, err
	}
	return newEntity(*pbEntity)
}

// }}}

// GetEntities {{{

// Get a list of all known Entities.
func (c Client) GetEntities() ([]Entity, error) {
	stream, err := c.client.GetEntities(context.Background(), &pb.Empty{})
	if err != nil {
		return nil, err
	}
	entities := []Entity{}
	for {
		pbEntity, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		entity, err := newEntity(*pbEntity)
		if err != nil {
			return nil, err
		}
		entities = append(entities, *entity)
	}
	return entities, nil
}

// }}}

// Entity {{{

// Underlying helper to take an incoming protobuf and turn it into a Client
// Entity. This decodes the Protobuf once, and turns it into Go native
// datastructures. For example, take the Expires time and turn it into a
// time.Time, and parse the CSR.
func newEntity(entity pb.Entity) (*Entity, error) {
	csr, err := x509.ParseCertificateRequest(entity.Csr.Der)
	if err != nil {
		return nil, err
	}

	var longevity *string = nil
	if entity.Longevity != "" {
		longevity = &entity.Longevity
	}

	var expires *time.Time = nil
	if entity.Expires != 0 {
		expiresAt := time.Unix(int64(entity.Expires), 0)
		expires = &expiresAt
	}

	return &Entity{
		Id:        entity.Id.Id,
		CSR:       *csr,
		State:     entity.State,
		Email:     entity.Email,
		Longevity: longevity,
		Expires:   expires,
	}, nil
}

// Client's view of the Entity.
type Entity struct {
	Id        []byte
	CSR       x509.CertificateRequest
	State     pb.Entity_State
	Email     string
	Longevity *string
	Expires   *time.Time
}

// }}}

// GetCertificate {{{

// Get the most recently issued Certificate for the Entity.
func (c Client) GetCertificate(id []byte) (*x509.Certificate, error) {
	pbCert, err := c.client.GetCertificate(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return nil, err
	}
	if pbCert.Der == nil {
		return nil, nil
	}
	return x509.ParseCertificate(pbCert.Der)
}

// }}}

// GetCertificateBySerial {{{

// Get the most recently issued Certificate for the Entity.
func (c Client) GetCertificateBySerial(id []byte) (*x509.Certificate, error) {
	pbCert, err := c.client.GetCertificateBySerial(context.Background(), &pb.Serial{Serial: id})
	if err != nil {
		return nil, err
	}
	if pbCert.Der == nil {
		return nil, nil
	}
	return x509.ParseCertificate(pbCert.Der)
}

// }}}

// GetEntityBySerial {{{

// Get the most recently issued Certificate for the Entity.
func (c Client) GetEntityBySerial(id []byte) (*Entity, error) {
	pbEntity, err := c.client.GetEntityBySerial(context.Background(), &pb.Serial{Serial: id})
	if err != nil {
		return nil, err
	}
	return newEntity(*pbEntity)
}

// }}}

// GetCertificates {{{

// Get a list of all known issued Certifciates for the Entity.
func (c Client) GetCertificates(id []byte) ([]x509.Certificate, error) {
	stream, err := c.client.GetCertificates(context.Background(), &pb.Id{Id: id})
	if err != nil {
		return nil, err
	}
	certs := []x509.Certificate{}
	for {
		pbCertifciate, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		cert, err := x509.ParseCertificate(pbCertifciate.Der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

// }}}

// Renew {{{

// Either issue a new Certificate, if the Enity can be granted a new one, or
// get the existing one. This is a safe method to call repeatedly, and can
// be used to "pull" your Certificate from the server as needed.
func (c Client) Renew() (*x509.Certificate, error) {
	pbCsr, err := c.client.Renew(context.Background(), &pb.Empty{})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pbCsr.Der)
}

// }}}

// Register {{{

// Push a CSR to the Server, and dump your Entity ID back. Future calls
// with this ID will return information regarding the new Entity. Commonly,
// Administrators of the CYBERCOM instance will have to approve your
// Entity, and issue your first Certificate. After that point, you will
// be able to get your latest Certificate, and authenticate future requests.
func (c Client) Register(csr x509.CertificateRequest) ([]byte, error) {
	pbId, err := c.client.Register(context.Background(), &pb.CSR{
		Der: csr.Raw,
	})
	if err != nil {
		return nil, err
	}
	return pbId.Id.Id, nil
}

// }}}

// GetConfiguration {{{

// Get the Configuration the Server has sent us. This will contain goodies
// like the Subject template, CYBERCOM Server name, and our Certificate, if the
// server liked it.
func (c Client) GetConfiguration() (*Configuration, error) {
	pbConfiguration, err := c.client.GetConfiguration(context.Background(), &pb.Empty{})
	if err != nil {
		return nil, err
	}
	return &Configuration{rawPb: *pbConfiguration}, nil
}

// Configuration {{{

// Configuration type. Most fields on this will be pulled from an underlying
// protobuf.
type Configuration struct {
	rawPb pb.Configuration
}

// Get the Entity it thinks we are back.
func (c Configuration) Entity() (*Entity, error) {
	if c.rawPb.Entity == nil {
		return nil, nil
	}
	return newEntity(*c.rawPb.Entity)
}

// Get the CYBERCOM name back.
func (c Configuration) Name() string {
	return c.rawPb.Name
}

// Get our Certificate back from the server, if the Server thinks it's a good
// Certificate.
func (c Configuration) Peer() (*x509.Certificate, error) {
	if c.rawPb.Peer.Der == nil {
		return nil, nil
	}
	return x509.ParseCertificate(c.rawPb.Peer.Der)
}

// Get back the `configuration.Template()`, but additionally, auto-populate
// the `CommonName` with some values we can guess from the local environment.
func (co Configuration) HostTemplate() (*pkix.Name, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	whoami, err := user.Current()
	if err != nil {
		return nil, err
	}

	name := co.Template()
	name.CommonName = fmt.Sprintf("%s (%s)", whoami.Name, host)
	return &name, nil
}

// Get the Configuration `pkix.Name` from the Server, pre-filled with
// organization-wide defaults.
func (c Configuration) Template() pkix.Name {
	ret := pkix.Name{}
	for value, list := range map[string]*[]string{
		c.rawPb.RequestTemplate.Country:            &ret.Country,
		c.rawPb.RequestTemplate.Organization:       &ret.Organization,
		c.rawPb.RequestTemplate.OrganizationalUnit: &ret.OrganizationalUnit,
		c.rawPb.RequestTemplate.Locality:           &ret.Locality,
		c.rawPb.RequestTemplate.Province:           &ret.Province,
	} {
		if value != "" {
			*list = append(*list, value)
		}
	}
	return ret
}

func (c Configuration) Certificates() ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	for _, pbCert := range c.rawPb.Ca {
		cert, err := x509.ParseCertificate(pbCert.Der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (c Configuration) CertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	certs, err := c.Certificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool, nil
}

// }}}
// }}}

// vim: foldmethod=marker
