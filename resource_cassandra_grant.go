package main

import (
	"fmt"
	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
	"strings"
	"regexp"
)

const (

	create_grant_raw_template = `CREATE GRANT {{ .Priviledge }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} TO "{{.Grantee}}"`
	read_grant_raw_template = `LIST {{ .Priviledge }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace }}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} OF "{{.Grantee}}"`

	priviledge_all       = "all"
	priviledge_create    = "create"
	priviledge_alter     = "alter"
	priviledge_drop      = "drop"
	priviledge_select    = "select"
	priviledge_modify    = "modify"
	priviledge_authorize = "authorize"
	priviledge_describe  = "describe"
	priviledge_execute   = "execute"

	resource_all_functions             = "all functions"
	resource_all_functions_in_keyspace = "all functions in keyspace"
	resource_function                  = "function"
	resource_all_keyspaces             = "all keyspaces"
	resource_keyspace                  = "keyspace"
	resource_table                     = "table"
	resource_all_roles                 = "all roles"
	resource_role                      = "role"
	resource_roles                     = "roles"
	resource_mbean                     = "mbean"
	resource_mbeans                    = "mbeans"
	resource_all_mbeans                = "all mbeans"

	identifier_function_name = "function_name"
	identifier_table_name = "table_name"
	identifier_mbean_name = "mbean_name"
	identifier_mbean_pattern = "mbean_pattern"
	identifier_role_name = "role_name"
	identifier_keyspace_name = "keyspace_name"
	identifier_grantee = "grantee"
	identifier_priviledge = "priviledge"
	identifier_resource_type = "resource_type"

)

var (

	validIdentifierRegex, _   = regexp.Compile(`^[^"]{1,256}$`)
	validTableNameRegex, _ = regexp.Compile(`^[a-zA-Z0-9][a-zA-Z0-9_]{0,255}$`)

	all_priviledges = []string{priviledge_select, priviledge_create, priviledge_alter, priviledge_drop, priviledge_modify, priviledge_authorize, priviledge_describe, priviledge_execute}

	all_resources = []string{resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_keyspaces, resource_keyspace, resource_table, resource_all_roles, resource_role, resource_roles, resource_mbean, resource_mbeans, resource_all_mbeans}

	privilegeToResourceTypesMap = map[string][]string{
		priviledge_all:       {resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_keyspaces, resource_keyspace, resource_table, resource_all_roles, resource_role},
		priviledge_create:    {resource_all_keyspaces, resource_keyspace, resource_all_functions, resource_all_functions_in_keyspace, resource_all_roles},
		priviledge_alter:     {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_roles, resource_role},
		priviledge_drop:      {resource_keyspace, resource_table, resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_roles, resource_role},
		priviledge_select:    {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_mbeans, resource_mbeans, resource_mbean},
		priviledge_modify:    {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_mbeans, resource_mbeans, resource_mbean},
		priviledge_authorize: {resource_all_keyspaces, resource_keyspace, resource_table, resource_function, resource_all_functions, resource_all_functions_in_keyspace, resource_all_roles, resource_roles},
		priviledge_describe:  {resource_all_roles, resource_all_mbeans},
		priviledge_execute:   {resource_all_functions, resource_all_functions_in_keyspace, resource_function},
	}

	validResources = map[string]bool{
		resource_all_functions:             true,
		resource_all_functions_in_keyspace: true,
		resource_function:                  true,
		resource_all_keyspaces:             true,
		resource_keyspace:                  true,
		resource_table:                     true,
		resource_all_roles:                 true,
		resource_role:                      true,
		resource_roles:                     true,
		resource_mbean:                     true,
		resource_mbeans:                    true,
		resource_all_mbeans:                true,
	}

	resources_that_require_keyspace_qualifier = []string{ resource_all_functions_in_keyspace, resource_function, resource_keyspace, resource_table }

	resource_type_to_identifier = map[string]string{
		resource_function  : identifier_function_name,
		resource_mbean: identifier_mbean_name,
		resource_mbeans: identifier_mbean_pattern,
		resource_table: identifier_table_name,
		resource_role: identifier_role_name,
	}
)

type Grant struct {
	Priviledge string
	Grantee string
	Keyspace string
	Identifier string
}


func validIdentifier(i interface{}, s string, identifer_name string, regular_expression *regexp.Regexp) (ws []string, errors []error) {
	identifier := i.(string)

	if identifer_name != "" && !regular_expression.MatchString(identifier) {
		errors = append(errors, fmt.Errorf("%s in not a valid %s name", identifier, identifer_name))
	}

	return
}

func resourceCassandraGrant() *schema.Resource {
	return &schema.Resource{
		Create: resourceGrantCreate,
		Read:   resourceGrantRead,
		Update: resourceGrantUpdate,
		Delete: resourceGrantDelete,
		Exists: resourceGrantExists,
		Schema: map[string]*schema.Schema{
			identifier_priviledge: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew: true,
				Description: fmt.Sprintf("One of %s", strings.Join(all_priviledges, ", ")),

				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					priviledge := i.(string)

					if len(privilegeToResourceTypesMap[priviledge]) <= 0 {
						errors = append(errors, fmt.Errorf("%s not one of %s", priviledge, strings.Join(all_priviledges, ", ")))
					}

					return
				},
			},
			identifier_grantee: &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "role name who we are granting priviledge(s) to",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "grantee", validRoleRegex)
				},
			},
			identifier_resource_type: &schema.Schema{
				Type:        schema.TypeBool,
				Required: true,
				ForceNew: true,
				Description: fmt.Sprintf("Resource type we are granting priviledge to. Must be one of %s", strings.Join(all_resources, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					resource_type := i.(string)

					if !validResources[resource_type] {
						errors = append(errors, fmt.Errorf("%s in not a valid resource_type, must be one of %s", resource_type, strings.Join(all_resources, ", ")))
					}

					return
				},
			},
			identifier_keyspace_name : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf("keyspace qualifier to the resource, only applicable for resource %s", strings.Join(resources_that_require_keyspace_qualifier, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					keyspace_name := i.(string)

					if !keyspaceRegex.MatchString(keyspace_name) {
						errors = append(errors, fmt.Errorf("%s in not a valid keyspace name", keyspace_name))
					}

					return
				},
				ConflictsWith: []string{identifier_role_name, identifier_mbean_name, identifier_mbean_pattern},
			},
			identifier_function_name : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf("keyspace qualifier to the resource, only applicable for resource %s", strings.Join(resources_that_require_keyspace_qualifier, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "function name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifier_table_name, identifier_role_name, identifier_mbean_name, identifier_mbean_pattern},
			},
			identifier_table_name : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf("name of the table, applicable only for resource %s", resource_table),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "table name", validTableNameRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_role_name, identifier_mbean_name, identifier_mbean_pattern},
			},
			identifier_role_name : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf("name of the role, applicable only for resource %s", resource_role),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "role name", validRoleRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_table_name, identifier_mbean_name, identifier_mbean_pattern, identifier_keyspace_name},
			},
			identifier_mbean_name : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf( "name of mbean, only applicable for resource %s", resource_mbean),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "mbean name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_table_name, identifier_role_name, identifier_mbean_pattern, identifier_keyspace_name},
			},
			identifier_mbean_pattern : &schema.Schema{
				Type: schema.TypeString,
				Optional: true,
				Description: fmt.Sprintf( "pattern for selecting mbeans, only valid for resource %s", resource_mbeans),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					mbean_pattern_raw := i.(string)

					_, err := regexp.Compile(mbean_pattern_raw)

					if err != nil {
						errors = append(errors, fmt.Errorf("%s in not a valid pattern", mbean_pattern_raw))
					}

					return
				},
				ConflictsWith: []string{identifier_function_name, identifier_table_name, identifier_role_name, identifier_mbean_name, identifier_keyspace_name},
			},
		},
	}
}

func parseData(d *schema.ResourceData) (*Grant, error) {
	priviledge := d.Get("priviledge").(string)
	grantee := d.Get("grantee").(string)
	resource_type := d.Get("resource_type").(string)

	allowedResouceTypesForPriviledge := privilegeToResourceTypesMap[priviledge]

	if len(allowedResouceTypesForPriviledge) <= 0 {
		return nil, fmt.Errorf("%s resource not applicable for priviledge %s", resource_type, priviledge)
	}

	var match_found = false

	for _, value := range allowedResouceTypesForPriviledge {
		if value == resource_type {
			match_found = true
		}
	}

	if !match_found {
		return nil, fmt.Errorf("%s resource not applicable for priviledge %s - valid resource_types are %s", resource_type, priviledge, strings.Join(allowedResouceTypesForPriviledge, ", "))
	}

	var requires_keyspace_qualifier = false


	for _, _resource_type := range( resources_that_require_keyspace_qualifier) {
		if resource_type == _resource_type {
			requires_keyspace_qualifier = true
		}
	}

	var keyspace_name = ""

	if requires_keyspace_qualifier {
		keyspace_name = d.Get("keyspace_name").(string)

		if keyspace_name == "" {
			return nil, fmt.Errorf("keyspace name must be set for resource_type %s", resource_type)
		}
	}

	identifier_key := resource_type_to_identifier[resource_type]

	var identifier = ""

	if identifier_key != "" {
		identifier = d.Get(identifier_key).(string)

		if identifier == "" {
			return nil, fmt.Errorf( "%s needs to be set when resource_type = %s", identifier_key, resource_type)
		}
	}

	return &Grant{priviledge, grantee, keyspace_name, identifier}, nil
}

func resourceGrantExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	grant, err := parseData(d)

	if err != nil {
		return false, err
	}

	cluster := meta.(gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return false, sessionCreationError
	}

	defer session.Close()


	session.Query()


}

func resourceGrantCreate(d *schema.ResourceData, meta interface{}) error {

}

func resourceGrantCreateOrUpdate(d *schema.ResourceData, meta interface{}, createRole bool) error {
	return nil
}

func resourceGrantRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceGrantDelete(d *schema.ResourceData, meta interface{}) error {

}

func resourceGrantUpdate(d *schema.ResourceData, meta interface{}) error {

}
