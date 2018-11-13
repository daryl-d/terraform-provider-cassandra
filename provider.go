package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
)

var (
	allowedTlsProtocols = map[string]uint16{
		"SSL3.0": tls.VersionSSL30,
		"TLS1.0": tls.VersionTLS10,
		"TLS1.1": tls.VersionTLS11,
		"TLS1.2": tls.VersionTLS12,
	}
)

func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"cassandra_keyspace": resourceCassandraKeyspace(),
			"cassandra_role":     resourceCassandraRole(),
			"cassandra_grant":    resourceCassandraGrant(),
		},
		ConfigureFunc: configureProvider,
		Schema: map[string]*schema.Schema{
			"username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Cassandra Username",
				Sensitive:   true,
			},
			"password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Cassandra Password",
				Sensitive:   true,
			},
			"port": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     9042,
				Description: "Cassandra CQL Port",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					port := i.(int)

					if port <= 0 || port >= 65535 {
						errors = append(errors, fmt.Errorf("%d: invalid value - must be between 1 and 65535", port))
					}

					return
				},
			},
			"hosts": &schema.Schema{
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				MinItems: 1,
				Required: true,
			},
			"connection_timeout": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1000,
				Description: "Connection timeout in milliseconds",
			},
			"root_ca": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Use root CA to connect to Cluster. Applies only when useSSL is enabled",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					rootCA := i.(string)

					if rootCA == "" {
						return
					}

					caPool := x509.NewCertPool()
					ok := caPool.AppendCertsFromPEM([]byte(rootCA))

					if !ok {
						errors = append(errors, fmt.Errorf("%s: invalid PEM", rootCA))
					}

					return
				},
			},
			"use_ssl": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Use SSL when connecting to cluster",
			},
			"min_tls_version": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "TLS1.2",
				Description: "Minimum TLS Version used to connect to the cluster - allowed values are SSL3.0, TLS1.0, TLS1.1, TLS1.2. Applies only when useSSL is enabled",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					minTlsVersion := i.(string)

					if allowedTlsProtocols[minTlsVersion] == 0 {
						errors = append(errors, fmt.Errorf("%s: invalid value - must be one of SSL3.0, TLS1.0, TLS1.1, TLS1.2", minTlsVersion))
					}

					return
				},
			},
			"protocol_version": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     4,
				Description: "CQL Binary Protocol Version",
			},
		},
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {

	log.Printf("Creating provider")

	useSSL := d.Get("use_ssl").(bool)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	port := d.Get("port").(int)
	connectionTimeout := d.Get("connection_timeout").(int)
	protocolVersion := d.Get("protocol_version").(int)

	log.Printf("Using port %d", port)
	log.Printf("Using use_ssl %v", useSSL)
	log.Printf("Using username %s", username)

	rawHosts := d.Get("hosts").([]interface{})

	hosts := make([]string, len(rawHosts))

	for _, value := range rawHosts {
		hosts = append(hosts, value.(string))

		log.Printf("Using host %v", value.(string))
	}

	cluster := gocql.NewCluster()

	cluster.Hosts = hosts

	cluster.Port = port

	cluster.Authenticator = &gocql.PasswordAuthenticator{
		Username: username,
		Password: password,
	}

	cluster.ConnectTimeout = time.Millisecond * time.Duration(connectionTimeout)

	cluster.Timeout = time.Minute * time.Duration(1)

	cluster.CQLVersion = "3.0.0"

	cluster.Keyspace = "system"

	cluster.ProtoVersion = protocolVersion

	cluster.HostFilter = gocql.WhiteListHostFilter(hosts...)

	cluster.DisableInitialHostLookup = true

	if useSSL {

		rootCA := d.Get("root_ca").(string)
		minTLSVersion := d.Get("min_tls_version").(string)

		tlsConfig := &tls.Config{
			MinVersion: allowedTlsProtocols[minTLSVersion],
		}

		if rootCA != "" {
			caPool := x509.NewCertPool()
			ok := caPool.AppendCertsFromPEM([]byte(rootCA))

			if !ok {
				return nil, errors.New("Unable to load rootCA")
			}

			tlsConfig.RootCAs = caPool
		}

		cluster.SslOpts = &gocql.SslOptions{
			Config: tlsConfig,
		}
	}

	return cluster, nil
}
