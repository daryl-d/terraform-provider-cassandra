package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
	"regexp"
	"sort"
	"strings"
	"log"
)

const (
	keyspaceliteralPattern = `^[a-zA-Z0-9_]{1,48}$`
	strategyLiteralPatten  = `^SimpleStrategy|NetworkTopologyStrategy$`
)

var (
	keyspaceRegex, _ = regexp.Compile(keyspaceliteralPattern)
	strategyRegex, _ = regexp.Compile(strategyLiteralPatten)
	boolToAction     = map[bool]string{
		true:  "CREATE",
		false: "UPDATE",
	}
)

func resourceCassandraKeyspace() *schema.Resource {
	return &schema.Resource{
		Create: resourceKeyspaceCreate,
		Read:   resourceKeyspaceRead,
		Update: resourceKeyspaceUpdate,
		Delete: resourceKeyspaceDelete,
		Exists: resourceKeyspaceExists,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of keyspace",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					name := i.(string)

					if !keyspaceRegex.MatchString(name) {
						errors = append(errors, fmt.Errorf("%s: invalid keyspace name - must match %s", name, keyspaceliteralPattern))
					}

					if name == "system" {
						errors = append(errors, fmt.Errorf("cannot manage system keyspace, it is internal to Cassandra"))
					}

					return
				},
			},
			"replication_strategy": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    false,
				Description: "Keyspace replication strategy - must be one of SimpleStrategy or NetworkTopologyStrategy",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					strategy := i.(string)

					if !strategyRegex.MatchString(strategy) {
						errors = append(errors, fmt.Errorf("%s: invalid replication strategy - must match %s", strategy, strategyLiteralPatten))
					}

					return
				},
			},
			"strategy_options": &schema.Schema{
				Type:        schema.TypeMap,
				Required:    true,
				ForceNew:    false,
				Description: "strategy options used with replication strategy",
				Elem:        &schema.Schema{
					Type: schema.TypeString,
				},
				StateFunc: func(v interface{}) string {
					strategyOptions := v.(map[string]interface{})

					keys := make([]string, len(strategyOptions))

					for key, value := range strategyOptions {

						strValue := value.(string)

						keys = append(keys, fmt.Sprintf("%q=%q", key, strValue))
					}

					sort.Strings(keys)

					return hash(strings.Join(keys, ", "))
				},
			},
			"durable_writes": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:     true,
				ForceNew:    false,
				Description: "Enable or disable durable writes - disabling is not recommended",
				Default:     true,
			},
		},
	}
}

// taken from here - http://techblog.d2-si.eu/2018/02/23/my-first-terraform-provider.html
func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}

func resourceKeyspaceExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	name := d.Get("name").(string)

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return false, sessionCreationError
	}

	defer session.Close()

	_, keyspaceDoesNotExist := session.KeyspaceMetadata(name)

	if keyspaceDoesNotExist == nil {
		return false, keyspaceDoesNotExist
	}

	return true, nil
}

func generateCreateOrUpdateKeyspaceQueryString(name string, create bool, replicationStrategy string, strategyOptions map[string]interface{}, durableWrites bool) (string, error) {

	numberOfStrategyOptions := len(strategyOptions)

	if numberOfStrategyOptions == 0 {
		return "", fmt.Errorf("Must specify stratgey options - see https://docs.datastax.com/en/cql/3.3/cql/cql_reference/cqlCreateKeyspace.html")
	}

	query := fmt.Sprintf(`%s KEYSPACE %s WITH REPLICATION = { 'class' : '%s'`, boolToAction[create], name, replicationStrategy)

	for key, value := range strategyOptions {
		query += fmt.Sprintf(`, '%s' : '%s'`, key, value.(string))
	}

	query += fmt.Sprintf(` } AND DURABLE_WRITES = %t`, durableWrites)

	log.Println( "query", query)

	return query, nil
}

func resourceKeyspaceCreate(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)
	replicationStrategy := d.Get("replication_strategy").(string)
	strategyOptions := d.Get("strategy_options").(map[string]interface{})
	durableWrites := d.Get("durable_writes").(bool)

	query, err := generateCreateOrUpdateKeyspaceQueryString(name, true, replicationStrategy, strategyOptions, durableWrites)

	if err != nil {
		return err
	}

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return sessionCreationError
	}

	defer session.Close()

	d.SetId(name)

	return session.Query(query).Exec()
}

func resourceKeyspaceRead(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return sessionCreationError
	}

	defer session.Close()

	keyspaceMetadata, err := session.KeyspaceMetadata(name)

	if err != nil {
		return err
	}

	strategyOptions := make(map[string]string)

	for key, value := range keyspaceMetadata.StrategyOptions {
		strategyOptions[key] = value.(string)
	}

	strategyClass := strings.TrimPrefix(keyspaceMetadata.StrategyClass, "org.apache.cassandra.locator.")

	d.Set("replication_strategy", strategyClass)
	d.Set("durable_writes", keyspaceMetadata.DurableWrites)
	d.Set("strategy_options", strategyOptions)
	d.SetId(name)

	return nil
}

func resourceKeyspaceDelete(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	session := meta.(*gocql.Session)

	return session.Query(fmt.Sprintf(`DROP KEYSPACE %s`, name)).Exec()
}

func resourceKeyspaceUpdate(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)
	replicationStrategy := d.Get("replication_strategy").(string)
	strategyOptions := d.Get("strategy_options").(map[string]interface{})
	durableWrites := d.Get("durable_writes").(bool)

	query, err := generateCreateOrUpdateKeyspaceQueryString(name, false, replicationStrategy, strategyOptions, durableWrites)

	if err != nil {
		return err
	}

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return sessionCreationError
	}

	defer session.Close()

	return session.Query(query).Exec()
}
