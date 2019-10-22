package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"regexp"
	"strings"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

const (
	deleteGrantRawTemplate = `REVOKE {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} FROM "{{.Grantee}}"`
	createGrantRawTemplate = `GRANT {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace}}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} TO "{{.Grantee}}"`
	readGrantRawTemplate   = `LIST {{ .Privilege }} ON {{.ResourceType}} {{if .Keyspace }}"{{ .Keyspace }}"{{end}}{{if and .Keyspace .Identifier}}.{{end}}{{if .Identifier}}"{{.Identifier}}"{{end}} OF "{{.Grantee}}"`

	privilegeAll       = "all"
	privilegeCreate    = "create"
	privilegeAlter     = "alter"
	privilegeDrop      = "drop"
	privilegeSelect    = "select"
	privilegeModify    = "modify"
	privilegeAuthorize = "authorize"
	privilegeDescribe  = "describe"
	privilegeExecute   = "execute"

	resourceAllFunctions           = "all functions"
	resourceAllFunctionsInKeyspace = "all functions in keyspace"
	resourceFunction               = "function"
	resourceAllKeyspaces           = "all keyspaces"
	resourceKeyspace               = "keyspace"
	resourceTable                  = "table"
	resourceAllRoles               = "all roles"
	resourceRole                   = "role"
	resourceRoles                  = "roles"
	resourceMbean                  = "mbean"
	resourceMbeans                 = "mbeans"
	resourceAllMbeans              = "all mbeans"

	identifierFunctionName = "function_name"
	identifierTableName    = "table_name"
	identifierMbeanName    = "mbean_name"
	identifierMbeanPattern = "mbean_pattern"
	identifierRoleName     = "role_name"
	identifierKeyspaceName = "keyspace_name"
	identifierGrantee      = "grantee"
	identifierPrivilege    = "privilege"
	identifierResourceType = "resource_type"
)

var (
	templateDelete, _ = template.New("delete_grant").Parse(deleteGrantRawTemplate)
	templateCreate, _ = template.New("create_grant").Parse(createGrantRawTemplate)
	templateRead, _   = template.New("read_grant").Parse(readGrantRawTemplate)

	validIdentifierRegex, _ = regexp.Compile(`^[^"]{1,256}$`)
	validTableNameRegex, _  = regexp.Compile(`^[a-zA-Z0-9][a-zA-Z0-9_]{0,255}$`)

	allPrivileges = []string{privilegeSelect, privilegeCreate, privilegeAlter, privilegeDrop, privilegeModify, privilegeAuthorize, privilegeDescribe, privilegeExecute}

	allResources = []string{resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllRoles, resourceRole, resourceRoles, resourceMbean, resourceMbeans, resourceAllMbeans}

	privilegeToResourceTypesMap = map[string][]string{
		privilegeAll:       {resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllRoles, resourceRole},
		privilegeCreate:    {resourceAllKeyspaces, resourceKeyspace, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceAllRoles},
		privilegeAlter:     {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllRoles, resourceRole},
		privilegeDrop:      {resourceKeyspace, resourceTable, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction, resourceAllRoles, resourceRole},
		privilegeSelect:    {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllMbeans, resourceMbeans, resourceMbean},
		privilegeModify:    {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceAllMbeans, resourceMbeans, resourceMbean},
		privilegeAuthorize: {resourceAllKeyspaces, resourceKeyspace, resourceTable, resourceFunction, resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceAllRoles, resourceRoles},
		privilegeDescribe:  {resourceAllRoles, resourceAllMbeans},
		privilegeExecute:   {resourceAllFunctions, resourceAllFunctionsInKeyspace, resourceFunction},
	}

	validResources = map[string]bool{
		resourceAllFunctions:           true,
		resourceAllFunctionsInKeyspace: true,
		resourceFunction:               true,
		resourceAllKeyspaces:           true,
		resourceKeyspace:               true,
		resourceTable:                  true,
		resourceAllRoles:               true,
		resourceRole:                   true,
		resourceRoles:                  true,
		resourceMbean:                  true,
		resourceMbeans:                 true,
		resourceAllMbeans:              true,
	}

	resourcesThatRequireKeyspaceQualifier = []string{resourceAllFunctionsInKeyspace, resourceFunction, resourceKeyspace, resourceTable}

	resourceTypeToIdentifier = map[string]string{
		resourceFunction: identifierFunctionName,
		resourceMbean:    identifierMbeanName,
		resourceMbeans:   identifierMbeanPattern,
		resourceTable:    identifierTableName,
		resourceRole:     identifierRoleName,
	}
)

// Grant represents a Cassandra Grant
type Grant struct {
	Privilege    string
	ResourceType string
	Grantee      string
	Keyspace     string
	Identifier   string
}

func validIdentifier(i interface{}, s string, identifierName string, regularExpression *regexp.Regexp) (ws []string, errors []error) {
	identifier := i.(string)

	if identifierName != "" && !regularExpression.MatchString(identifier) {
		errors = append(errors, fmt.Errorf("%s in not a valid %s name", identifier, identifierName))
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
			identifierPrivilege: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("One of %s", strings.Join(allPrivileges, ", ")),

				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					privilege := i.(string)

					if len(privilegeToResourceTypesMap[privilege]) <= 0 {
						errors = append(errors, fmt.Errorf("%s not one of %s", privilege, strings.Join(allPrivileges, ", ")))
					}

					return
				},
			},
			identifierGrantee: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "role name who we are granting privilege(s) to",
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "grantee", validRoleRegex)
				},
			},
			identifierResourceType: &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("Resource type we are granting privilege to. Must be one of %s", strings.Join(allResources, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					resourceType := i.(string)

					if !validResources[resourceType] {
						errors = append(errors, fmt.Errorf("%s in not a valid resourceType, must be one of %s", resourceType, strings.Join(allResources, ", ")))
					}

					return
				},
			},
			identifierKeyspaceName: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("keyspace qualifier to the resource, only applicable for resource %s", strings.Join(resourcesThatRequireKeyspaceQualifier, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					keyspaceName := i.(string)

					if !keyspaceRegex.MatchString(keyspaceName) {
						errors = append(errors, fmt.Errorf("%s in not a valid keyspace name", keyspaceName))
					}

					return
				},
				ConflictsWith: []string{identifierRoleName, identifierMbeanName, identifierMbeanPattern},
			},
			identifierFunctionName: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: fmt.Sprintf("keyspace qualifier to the resource, only applicable for resource %s", strings.Join(resourcesThatRequireKeyspaceQualifier, ", ")),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "function name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifierTableName, identifierRoleName, identifierMbeanName, identifierMbeanPattern},
			},
			identifierTableName: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of the table, applicable only for resource %s", resourceTable),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "table name", validTableNameRegex)
				},
				ConflictsWith: []string{identifierFunctionName, identifierRoleName, identifierMbeanName, identifierMbeanPattern},
			},
			identifierRoleName: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of the role, applicable only for resource %s", resourceRole),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "role name", validRoleRegex)
				},
				ConflictsWith: []string{identifierFunctionName, identifierTableName, identifierMbeanName, identifierMbeanPattern, identifierKeyspaceName},
			},
			identifierMbeanName: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("name of mbean, only applicable for resource %s", resourceMbean),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					return validIdentifier(i, s, "mbean name", validIdentifierRegex)
				},
				ConflictsWith: []string{identifierFunctionName, identifierTableName, identifierRoleName, identifierMbeanPattern, identifierKeyspaceName},
			},
			identifierMbeanPattern: &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: fmt.Sprintf("pattern for selecting mbeans, only valid for resource %s", resourceMbeans),
				ValidateFunc: func(i interface{}, s string) (ws []string, errors []error) {
					mbeanPatternRaw := i.(string)

					_, err := regexp.Compile(mbeanPatternRaw)

					if err != nil {
						errors = append(errors, fmt.Errorf("%s in not a valid pattern", mbeanPatternRaw))
					}

					return
				},
				ConflictsWith: []string{identifierFunctionName, identifierTableName, identifierRoleName, identifierMbeanName, identifierKeyspaceName},
			},
		},
	}
}

func parseData(d *schema.ResourceData) (*Grant, error) {
	privilege := d.Get(identifierPrivilege).(string)
	grantee := d.Get(identifierGrantee).(string)
	resourceType := d.Get(identifierResourceType).(string)

	allowedResouceTypesForPrivilege := privilegeToResourceTypesMap[privilege]

	if len(allowedResouceTypesForPrivilege) <= 0 {
		return nil, fmt.Errorf("%s resource not applicable for privilege %s", resourceType, privilege)
	}

	var matchFound = false

	for _, value := range allowedResouceTypesForPrivilege {
		if value == resourceType {
			matchFound = true
		}
	}

	if !matchFound {
		return nil, fmt.Errorf("%s resource not applicable for privilege %s - valid resourceTypes are %s", resourceType, privilege, strings.Join(allowedResouceTypesForPrivilege, ", "))
	}

	var requiresKeyspaceQualifier = false

	for _, _resourceType := range resourcesThatRequireKeyspaceQualifier {
		if resourceType == _resourceType {
			requiresKeyspaceQualifier = true
		}
	}

	var keyspaceName = ""

	if requiresKeyspaceQualifier {
		keyspaceName = d.Get(identifierKeyspaceName).(string)

		if keyspaceName == "" {
			return nil, fmt.Errorf("keyspace name must be set for resourceType %s", resourceType)
		}
	}

	identifierKey := resourceTypeToIdentifier[resourceType]

	var identifier = ""

	if identifierKey != "" {
		identifier = d.Get(identifierKey).(string)

		if identifier == "" {
			return nil, fmt.Errorf("%s needs to be set when resourceType = %s", identifierKey, resourceType)
		}
	}

	return &Grant{privilege, resourceType, grantee, keyspaceName, identifier}, nil
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
	templateRenderError := templateRead.Execute(&buffer, grant)

	if templateRenderError != nil {
		return false, templateRenderError
	}

	query := buffer.String()

	iter := session.Query(query).Iter()

	rowCount := iter.NumRows()

	iterError := iter.Close()

	return rowCount > 0, iterError
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

	templateRenderError := templateCreate.Execute(&buffer, grant)

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

	d.Set(identifierResourceType, grant.ResourceType)
	d.Set(identifierGrantee, grant.Grantee)
	d.Set(identifierPrivilege, grant.Privilege)

	if grant.Keyspace != "" {
		d.Set(identifierKeyspaceName, grant.Keyspace)
	}

	if grant.Identifier != "" {
		identifierName := resourceTypeToIdentifier[grant.ResourceType]

		d.Set(identifierName, grant.Identifier)
	}

	return nil
}

func resourceGrantDelete(d *schema.ResourceData, meta interface{}) error {
	grant, err := parseData(d)

	if err != nil {
		return err
	}

	var buffer bytes.Buffer

	err = templateDelete.Execute(&buffer, grant)

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
