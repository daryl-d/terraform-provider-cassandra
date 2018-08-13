package main

import (
	"fmt"
	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
	"log"
	"regexp"
	"time"
)

const (
	validPasswordRegexLiteral = `^[^']{40,512}$`
	validRoleRegexLiteral     = `^[^']{1,256}$`
)

var (
	validPasswordRegex, _ = regexp.Compile(validPasswordRegexLiteral)
	validRoleRegex, _     = regexp.Compile(validRoleRegexLiteral)
)

func resourceCassandraRole() *schema.Resource {
	return &schema.Resource{
		Create: resourceRoleCreate,
		Read:   resourceRoleRead,
		Update: resourceRoleUpdate,
		Delete: resourceRoleDelete,
		Exists: resourceRoleExists,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of role - must contain between 1 and 256 characters",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					name := i.(string)

					if !validRoleRegex.MatchString(name) {
						errors = append(errors, fmt.Errorf("name must contain between 1 and 256 chars and must not contain single quote character"))
					}

					return
				},
			},
			"super_user": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    false,
				Description: "Allow role to create and manage other roles",
			},
			"login": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				ForceNew:    false,
				Description: "Enables role to be able to login",
			},
			"password": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    false,
				Description: "Password for user when using Cassandra internal authentication",
				Sensitive:   true,
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					password := i.(string)

					if !validPasswordRegex.MatchString(password) {
						errors = append(errors, fmt.Errorf("password must contain between 40 and 512 chars and must not contain single quote character"))
					}

					return
				},
			},
		},
	}
}

func readRole(session *gocql.Session, name string) (string, bool, bool, string, error) {

	var (
		role        string
		canLogin    bool
		isSuperUser bool
		saltedHash  string
	)

	iter := session.Query(`select role, can_login, is_superuser, salted_hash from system_auth.roles where role = ?`, name).Iter()

	defer iter.Close()

	log.Printf("read role query returned %d", iter.NumRows())

	for iter.Scan(&role, &canLogin, &isSuperUser, &saltedHash) {
		return role, canLogin, isSuperUser, saltedHash, nil
	}

	return "", false, false, "", nil
}

func resourceRoleExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	name := d.Get("name").(string)

	cluster := meta.(*gocql.ClusterConfig)

	start := time.Now()

	session, sessionCreateError := cluster.CreateSession()

	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return false, sessionCreateError
	}

	defer session.Close()

	_name, _, _, _, err := readRole(session, name)

	condition := _name == name && err == nil

	log.Printf("name = %s, _name = %s, err = %v, condition = %v", name, _name, err, condition)

	return condition, err
}

func resourceRoleCreate(d *schema.ResourceData, meta interface{}) error {
	return resourceRoleCreateOrUpdate(d, meta, true)
}

func resourceRoleCreateOrUpdate(d *schema.ResourceData, meta interface{}, createRole bool) error {
	name := d.Get("name").(string)
	superUser := d.Get("super_user").(bool)
	login := d.Get("login").(bool)
	password := d.Get("password").(string)

	cluster := meta.(*gocql.ClusterConfig)

	start := time.Now()

	session, sessionCreateError := cluster.CreateSession()

	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return sessionCreateError
	}

	defer session.Close()

	createErr := session.Query(fmt.Sprintf(`%s ROLE '%s' WITH PASSWORD = '%s' AND LOGIN = %v AND SUPERUSER = %v`, boolToAction[createRole], name, password, login, superUser)).Exec()
	if createErr != nil {
		return createErr
	}

	_, _, _, saltedHash, readRoleErr := readRole(session, name)

	d.SetId(name)
	d.Set("name", name)
	d.Set("super_user", superUser)
	d.Set("login", login)

	if readRoleErr != nil {
		return readRoleErr
	}

	d.Set("password", saltedHash)

	return nil
}

func resourceRoleRead(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	cluster := meta.(*gocql.ClusterConfig)

	start := time.Now()

	session, sessionCreateError := cluster.CreateSession()

	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return sessionCreateError
	}

	defer session.Close()
	_name, login, superUser, saltedHash, readRoleErr := readRole(session, name)

	if readRoleErr != nil {
		return readRoleErr
	}

	d.SetId(_name)
	d.Set("name", _name)
	d.Set("super_user", superUser)
	d.Set("login", login)
	d.Set("password", saltedHash)

	return nil
}

func resourceRoleDelete(d *schema.ResourceData, meta interface{}) error {
	name := d.Get("name").(string)

	cluster := meta.(*gocql.ClusterConfig)

	start := time.Now()

	session, sessionCreateError := cluster.CreateSession()

	elapsed := time.Since(start)

	log.Printf("Getting a session took %s", elapsed)

	if sessionCreateError != nil {
		return sessionCreateError
	}

	defer session.Close()

	return session.Query(fmt.Sprintf(`DROP ROLE '%s'`, name)).Exec()
}

func resourceRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	return resourceRoleCreateOrUpdate(d, meta, false)
}
