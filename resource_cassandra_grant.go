package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"regexp"
	"strings"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform/helper/schema"
)

const (
	delete_grant_raw_template = `REVOKE {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} FROM "{{.Grantee}}"`
	create_grant_raw_template = `GRANT {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} TO "{{.Grantee}}"`
	read_grant_raw_template   = `LIST {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace }}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} OF "{{.Grantee}}"`

	privilege_all       = "all"
	privilege_create    = "create"
	privilege_alter     = "alter"
	privilege_drop      = "drop"
	privilege_select    = "select"
	privilege_modify    = "modify"
	privilege_authorize = "authorize"
	privilege_describe  = "describe"
	privilege_execute   = "execute"

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
	identifier_table_name    = "table_name"
	identifier_mbean_name    = "mbean_name"
	identifier_mbean_pattern = "mbean_pattern"
	identifier_role_name     = "role_name"
	identifier_keyspace_name = "keyspace_name"
	identifier_grantee       = "grantee"
	identifier_privilege    = "privilege"
	identifier_resource_type = "resource_type"
)

var (
	template_delete, _ = template.New("delete_grant").Parse(delete_grant_raw_template)
	template_create, _ = template.New("create_grant").Parse(create_grant_raw_template)
	template_read, _   = template.New("read_grant").Parse(read_grant_raw_template)

	validIdentifierRegex, _ = regexp.Compile(`^[^"]{1,256}$`)
	validTableNameRegex, _  = regexp.Compile(`^[a-zA-Z0-9][a-zA-Z0-9_]{0,255}$`)

	all_privileges = []string{privilege_select, privilege_create, privilege_alter, privilege_drop, privilege_modify, privilege_authorize, privilege_describe, privilege_execute}

	all_resources = []string{resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_keyspaces, resource_keyspace, resource_table, resource_all_roles, resource_role, resource_roles, resource_mbean, resource_mbeans, resource_all_mbeans}

	privilegeToResourceTypesMap = map[string][]string{
		privilege_all:       {resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_keyspaces, resource_keyspace, resource_table, resource_all_roles, resource_role},
		privilege_create:    {resource_all_keyspaces, resource_keyspace, resource_all_functions, resource_all_functions_in_keyspace, resource_all_roles},
		privilege_alter:     {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_roles, resource_role},
		privilege_drop:      {resource_keyspace, resource_table, resource_all_functions, resource_all_functions_in_keyspace, resource_function, resource_all_roles, resource_role},
		privilege_select:    {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_mbeans, resource_mbeans, resource_mbean},
		privilege_modify:    {resource_all_keyspaces, resource_keyspace, resource_table, resource_all_mbeans, resource_mbeans, resource_mbean},
		privilege_authorize: {resource_all_keyspaces, resource_keyspace, resource_table, resource_function, resource_all_functions, resource_all_functions_in_keyspace, resource_all_roles, resource_roles},
		privilege_describe:  {resource_all_roles, resource_all_mbeans},
		privilege_execute:   {resource_all_functions, resource_all_functions_in_keyspace, resource_function},
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

	resources_that_require_keyspace_qualifier = []string{resource_all_functions_in_keyspace, resource_function, resource_keyspace, resource_table}

	resource_type_to_identifier = map[string]string{
		resource_function: identifier_function_name,
		resource_mbean:    identifier_mbean_name,
		resource_mbeans:   identifier_mbean_pattern,
		resource_table:    identifier_table_name,
		resource_role:     identifier_role_name,
	}
)

type Grant struct {
	Privilege   string
	ResourceType string
	Grantee      string
	Keyspace     string
	Identifier   string
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
			identifier_privilege: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("One of %s", strings.Join(all_privileges, ", ")),

				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					privilege := i.(string)

					if len(privilegeToResourceTypesMap[privilege]) <= 0 {
						errors = append(errors, fmt.Errorf("%s not one of %s", privilege, strings.Join(all_privileges, ", ")))
					}

					return
				},
			},
			identifier_grantee: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "role name who we are granting privilege(s) to",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "grantee", validRoleRegex)
				},
			},
			identifier_resource_type: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("Resource type we are granting privilege to. Must be one of %s", strings.Join(all_resources, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					resource_type := i.(string)

					if !validResources[resource_type] {
						errors = append(errors, fmt.Errorf("%s in not a valid resource_type, must be one of %s", resource_type, strings.Join(all_resources, ", ")))
					}

					return
				},
			},
			identifier_keyspace_name: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
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
			identifier_function_name: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: fmt.Sprintf("keyspace qualifier to the resource, only applicable for resource %s", strings.Join(resources_that_require_keyspace_qualifier, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "function name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifier_table_name, identifier_role_name, identifier_mbean_name, identifier_mbean_pattern},
			},
			identifier_table_name: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of the table, applicable only for resource %s", resource_table),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "table name", validTableNameRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_role_name, identifier_mbean_name, identifier_mbean_pattern},
			},
			identifier_role_name: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of the role, applicable only for resource %s", resource_role),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "role name", validRoleRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_table_name, identifier_mbean_name, identifier_mbean_pattern, identifier_keyspace_name},
			},
			identifier_mbean_name: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of mbean, only applicable for resource %s", resource_mbean),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "mbean name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifier_function_name, identifier_table_name, identifier_role_name, identifier_mbean_pattern, identifier_keyspace_name},
			},
			identifier_mbean_pattern: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("pattern for selecting mbeans, only valid for resource %s", resource_mbeans),
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
	privilege := d.Get(identifier_privilege).(string)
	grantee := d.Get(identifier_grantee).(string)
	resource_type := d.Get(identifier_resource_type).(string)

	allowedResouceTypesForPrivilege := privilegeToResourceTypesMap[privilege]

	if len(allowedResouceTypesForPrivilege) <= 0 {
		return nil, fmt.Errorf("%s resource not applicable for privilege %s", resource_type, privilege)
	}

	var match_found = false

	for _, value := range allowedResouceTypesForPrivilege {
		if value == resource_type {
			match_found = true
		}
	}

	if !match_found {
		return nil, fmt.Errorf("%s resource not applicable for privilege %s - valid resource_types are %s", resource_type, privilege, strings.Join(allowedResouceTypesForPrivilege, ", "))
	}

	var requires_keyspace_qualifier = false

	for _, _resource_type := range resources_that_require_keyspace_qualifier {
		if resource_type == _resource_type {
			requires_keyspace_qualifier = true
		}
	}

	var keyspace_name = ""

	if requires_keyspace_qualifier {
		keyspace_name = d.Get(identifier_keyspace_name).(string)

		if keyspace_name == "" {
			return nil, fmt.Errorf("keyspace name must be set for resource_type %s", resource_type)
		}
	}

	identifier_key := resource_type_to_identifier[resource_type]

	var identifier = ""

	if identifier_key != "" {
		identifier = d.Get(identifier_key).(string)

		if identifier == "" {
			return nil, fmt.Errorf("%s needs to be set when resource_type = %s", identifier_key, resource_type)
		}
	}

	return &Grant{privilege, resource_type, grantee, keyspace_name, identifier}, nil
}

func resourceGrantExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	grant, err := parseData(d)

	if err != nil {
		return false, err
	}

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return false, sessionCreationError
	}

	defer session.Close()

	var buffer bytes.Buffer
	templateRenderError := template_read.Execute(&buffer, grant)

	if templateRenderError != nil {
		return false, templateRenderError
	}

	query := buffer.String()

	iter := session.Query(query).Iter()

	row_count := iter.NumRows()

	iterError := iter.Close()

	return row_count > 0, iterError
}

func resourceGrantCreate(d *schema.ResourceData, meta interface{}) error {
	grant, err := parseData(d)

	if err != nil {
		return err
	}

	cluster := meta.(*gocql.ClusterConfig)

	session, sessionCreationError := cluster.CreateSession()

	if sessionCreationError != nil {
		return sessionCreationError
	}

	defer session.Close()

	var buffer bytes.Buffer

	templateRenderError := template_create.Execute(&buffer, grant)

	if templateRenderError != nil {
		return templateRenderError
	}

	query := buffer.String()

	log.Printf("Executing query %v", query)

	d.SetId(hash(fmt.Sprintf("%+v", grant)))

	return session.Query(query).Exec()
}

func resourceGrantRead(d *schema.ResourceData, meta interface{}) error {
	exists, err := resourceGrantExists(d, meta)

	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("Grant does not exist")
	}

	grant, err := parseData(d)

	if err != nil {
		return err
	}

	d.Set(identifier_resource_type, grant.ResourceType)
	d.Set(identifier_grantee, grant.Grantee)
	d.Set(identifier_privilege, grant.Privilege)

	if grant.Keyspace != "" {
		d.Set(identifier_keyspace_name, grant.Keyspace)
	}

	if grant.Identifier != "" {
		identifier_name := resource_type_to_identifier[grant.ResourceType]

		d.Set(identifier_name, grant.Identifier)
	}

	return nil
}

func resourceGrantDelete(d *schema.ResourceData, meta interface{}) error {
	grant, err := parseData(d)

	if err != nil {
		return err
	}

	var buffer bytes.Buffer

	err = template_delete.Execute(&buffer, grant)

	if err != nil {
		return err
	}

	cluster := meta.(*gocql.ClusterConfig)

	session, err := cluster.CreateSession()

	if err != nil {
		return err
	}

	query := buffer.String()

	defer session.Close()

	return session.Query(query).Exec()
}

func resourceGrantUpdate(d *schema.ResourceData, meta interface{}) error {
	return fmt.Errorf("Updating of grants is not supported")
}
