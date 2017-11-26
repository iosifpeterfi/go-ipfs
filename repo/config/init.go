package config

import (
	"encoding/base64"
	"encoding/base32"
	"crypto/x509"
	"crypto/sha1"
	"crypto/rsa"
	"crypto/rand"
	"encoding/asn1"
	"strings"
	"errors"
	"fmt"
	"io"
	"time"

	peer "gx/ipfs/QmXYjuNuxVzXKJCfWasQk1RqkhVLDM9jtUKhqc2WPQmFSB/go-libp2p-peer"
	ci "gx/ipfs/QmaPbCnUMBohSGo3KnxEa2bHqyJVVeEEcwtqJAYxerieBo/go-libp2p-crypto"
)

func Init(out io.Writer, nBitsForKeypair int) (*Config, error) {
	identity, err := identityConfig(out, nBitsForKeypair)
	if err != nil {
		return nil, err
	}

	bootstrapPeers, err := DefaultBootstrapPeers()
	if err != nil {
		return nil, err
	}

	datastore := DefaultDatastoreConfig()
	
	sk,err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	pk := sk.PublicKey;

	skbytes := x509.MarshalPKCS1PrivateKey(sk);
	pkbytes, err := asn1.Marshal(pk);
	pksha1 := sha1.Sum(pkbytes);
	length := len(pksha1)/2;
	pkhsha1 := pksha1[0:length];
	onionAddress := strings.ToLower(base32.StdEncoding.EncodeToString(pkhsha1));
	onionSwarmAddress := "/onion/" + onionAddress + ":4003";
	onionPrivateKey := base64.StdEncoding.EncodeToString(skbytes);
	
	conf := &Config{

		// setup the node's default addresses.
		// NOTE: two swarm listen addrs, one tcp, one utp.
		Addresses: Addresses{
			Swarm: []string{
				onionSwarmAddress,	
				"/ip4/0.0.0.0/tcp/4001",
				// "/ip4/0.0.0.0/udp/4002/utp", // disabled for now.
				"/ip6/::/tcp/4001",
			},
			Announce:   []string{},
			NoAnnounce: []string{},
			API:        "/ip4/127.0.0.1/tcp/5001",
			Gateway:    "/ip4/127.0.0.1/tcp/8080",
		},

		Datastore: datastore,
		Bootstrap: BootstrapPeerStrings(bootstrapPeers),
		Identity:  identity,
		OnionKeys: onionAddress + onionPrivateKey,
		Discovery: Discovery{MDNS{
			Enabled:  true,
			Interval: 10,
		}},

		// setup the node mount points.
		Mounts: Mounts{
			IPFS: "/ipfs",
			IPNS: "/ipns",
		},

		Ipns: Ipns{
			ResolveCacheSize: 128,
		},

		Gateway: Gateway{
			RootRedirect: "",
			Writable:     false,
			PathPrefixes: []string{},
			HTTPHeaders: map[string][]string{
				"Access-Control-Allow-Origin":  []string{"*"},
				"Access-Control-Allow-Methods": []string{"GET"},
				"Access-Control-Allow-Headers": []string{"X-Requested-With", "Range"},
			},
		},
		Reprovider: Reprovider{
			Interval: "12h",
			Strategy: "all",
		},
		Swarm: SwarmConfig{
			ConnMgr: ConnMgr{
				LowWater:    DefaultConnMgrLowWater,
				HighWater:   DefaultConnMgrHighWater,
				GracePeriod: DefaultConnMgrGracePeriod.String(),
				Type:        "basic",
			},
		},
	}

	return conf, nil
}

// DefaultConnMgrHighWater is the default value for the connection managers
// 'high water' mark
const DefaultConnMgrHighWater = 900

// DefaultConnMgrLowWater is the default value for the connection managers 'low
// water' mark
const DefaultConnMgrLowWater = 600

// DefaultConnMgrGracePeriod is the default value for the connection managers
// grace period
const DefaultConnMgrGracePeriod = time.Second * 20

// DefaultDatastoreConfig is an internal function exported to aid in testing.
func DefaultDatastoreConfig() Datastore {
	return Datastore{
		StorageMax:         "10GB",
		StorageGCWatermark: 90, // 90%
		GCPeriod:           "1h",
		BloomFilterSize:    0,
		Spec: map[string]interface{}{
			"type": "mount",
			"mounts": []interface{}{
				map[string]interface{}{
					"mountpoint": "/blocks",
					"type":       "measure",
					"prefix":     "flatfs.datastore",
					"child": map[string]interface{}{
						"type":      "flatfs",
						"path":      "blocks",
						"sync":      true,
						"shardFunc": "/repo/flatfs/shard/v1/next-to-last/2",
					},
				},
				map[string]interface{}{
					"mountpoint": "/",
					"type":       "measure",
					"prefix":     "leveldb.datastore",
					"child": map[string]interface{}{
						"type":        "levelds",
						"path":        "datastore",
						"compression": "none",
					},
				},
			},
		},
	}
}

// identityConfig initializes a new identity.
func identityConfig(out io.Writer, nbits int) (Identity, error) {
	// TODO guard higher up
	ident := Identity{}
	if nbits < 1024 {
		return ident, errors.New("Bitsize less than 1024 is considered unsafe.")
	}

	fmt.Fprintf(out, "generating %v-bit RSA keypair...", nbits)
	sk, pk, err := ci.GenerateKeyPair(ci.RSA, nbits)
	if err != nil {
		return ident, err
	}
	fmt.Fprintf(out, "done\n")

	// currently storing key unencrypted. in the future we need to encrypt it.
	// TODO(security)
	skbytes, err := sk.Bytes()
	if err != nil {
		return ident, err
	}
	ident.PrivKey = base64.StdEncoding.EncodeToString(skbytes)

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return ident, err
	}
	ident.PeerID = id.Pretty()
	fmt.Fprintf(out, "peer identity: %s\n", ident.PeerID)
	return ident, nil
}
