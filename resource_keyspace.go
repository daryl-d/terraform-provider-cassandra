package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

func resourceKeyspace() *schema.Resource {
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
			"replicationStrategy": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    false,
				Description: "Keyspace replication strategy - must be one of SimpleStrategy or NetworkTopologyStrategy",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					strategy := i.(string)

					if !keyspaceRegex.MatchString(strategy) {
						errors = append(errors, fmt.Errorf("%s: invalid replication strategy - must match %s", strategy, strategyLiteralPatten))
					}

					return
				},
			},
			"strategyOptions": &schema.Schema{
				Type:        schema.TypeMap,
				Required:    true,
				ForceNew:    false,
				Description: "strategy options used with replication strategy",
				Elem:        schema.TypeInt,
				StateFunc: func(v interface{}) string {
					strategyOptions := v.(map[string]int)

					keys := make([]string, len(strategyOptions))

					for key, value := range strategyOptions {
						keys = append(keys, fmt.Sprintf("%q=%q", key, value))
					}

					sort.Strings(keys)

					return hash(strings.Join(keys, ", "))
				},
			},
			"durableWrites": &schema.Schema{
				Type:        schema.TypeBool,
				Required:    true,
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

	session := meta.(gocql.Session)

	_, err := session.KeyspaceMetadata(name)

	if err == nil {
		return false, err
	}

	return true, nil
}

func generateCreateOrUpdateKeyspaceQueryString(name string, create bool, replicationStrategy string, strategyOptions map[string]int, durableWrites bool) (string, []interface{}, error) {

	numberOfStrategyOptions := len(strategyOptions)

	if numberOfStrategyOptions == 0 {
		return "", make([]interface{}, 0), fmt.Errorf("Must specify stratgey options - see https://docs.datastax.com/en/cql/3.3/cql/cql_reference/cqlCreateKeyspace.html")
	}

	if replicationStrategy == "SimpleStrategy" && strategyOptions["replication_factor"] <= 0 {
		return "", make([]interface{}, 0), fmt.Errorf("Must specify replication_factor greater than zero with %s", strategyOptions)
	}

	size := numberOfStrategyOptions*2 + 3

	args := make([]interface{}, size)
	args[0] = name
	args[1] = replicationStrategy
	args[size-1] = durableWrites

	pos := 2

	action := boolToAction[create]

	statement := fmt.Sprintf(`
		%s KEYSPACE ? WITH REPLICATION = { 'class' : '?'`, action)

	for key, value := range strategyOptions {
		args[pos] = key
		args[pos+1] = value
		statement += `, ? = '?'`
		pos += 2
	}

	statement += ` } AND DURABLE_WRITES = ?`

	return statement, args, nil
}

func resourceKeyspaceCreate(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)
	replicationStrategy := d.Get("replicationStrategy").(string)
	strategyOptions := d.Get("strategyOptions").(map[string]int)
	durableWrites := d.Get("durableWrites").(bool)

	statement, args, err := generateCreateOrUpdateKeyspaceQueryString(name, true, replicationStrategy, strategyOptions, durableWrites)

	if err != nil {
		return err
	}

	session := meta.(gocql.Session)

	return session.Query(statement, args).Exec()
}

func resourceKeyspaceRead(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	session := meta.(gocql.Session)

	keyspaceMetadata, err := session.KeyspaceMetadata(name)

	if err != nil {
		return err
	}

	strategyOptions := make(map[string]int)

	for key, value := range keyspaceMetadata.StrategyOptions {
		intVal, err := strconv.Atoi(value.(string))

		if err != nil {
			return fmt.Errorf("Could not convert strategy option [%s] = %s to an integer", key, value)
		}

		strategyOptions[key] = intVal
	}

	strategyClass := strings.TrimPrefix(keyspaceMetadata.StrategyClass, "org.apache.cassandra.locator.")

	d.Set("replicationStrategy", strategyClass)
	d.Set("durableWrites", keyspaceMetadata.DurableWrites)
	d.Set("strategyOptions", strategyOptions)

	return nil
}

func resourceKeyspaceDelete(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	session := meta.(gocql.Session)

	return session.Query(`DROP KEYSPACE ?`, name).Exec()
}

func resourceKeyspaceUpdate(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)
	replicationStrategy := d.Get("replicationStrategy").(string)
	strategyOptions := d.Get("strategyOptions").(map[string]int)
	durableWrites := d.Get("durableWrites").(bool)

	statement, args, err := generateCreateOrUpdateKeyspaceQueryString(name, false, replicationStrategy, strategyOptions, durableWrites)

	if err != nil {
		return err
	}

	session := meta.(gocql.Session)

	return session.Query(statement, args).Exec()
}
