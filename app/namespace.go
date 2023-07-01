package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/cjrd/allocate"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/kylelemons/godebug/diff"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/namespaceservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"github.com/urfave/cli/v2"
	"go.uber.org/multierr"
	"google.golang.org/grpc"
)

const (
	namespaceRegionFlagName          = "region"
	CaCertificateFlagName            = "ca-certificate"
	CaCertificateFileFlagName        = "ca-certificate-file"
	caCertificateFingerprintFlagName = "ca-certificate-fingerprint"
	SpecFileFlagName                 = "spec-file"
	SpecFlagName                     = "spec"
	searchAttributeFlagName          = "search-attribute"
	userNamespacePermissionFlagName  = "user-namespace-permission"
)

var (
	CaCertificateFlag = &cli.StringFlag{
		Name:    CaCertificateFlagName,
		Usage:   "The base64 encoded ca certificate",
		Aliases: []string{"c"},
	}
	CaCertificateFileFlag = &cli.PathFlag{
		Name:    CaCertificateFileFlagName,
		Usage:   "The path to the ca pem file",
		Aliases: []string{"f"},
	}
	caCertificateFingerprintFlag = &cli.StringFlag{
		Name:    caCertificateFingerprintFlagName,
		Usage:   "The fingerprint of to the ca certificate",
		Aliases: []string{"fp"},
	}
	namespaceRegions = []string{
		"ap-northeast-1",
		"ap-southeast-1",
		"ap-southeast-2",
		"ca-central-1",
		"eu-central-1",
		"eu-west-1",
		"eu-west-2",
		"us-east-1",
		"us-west-2",
	}
)

type NamespaceClient struct {
	client     namespaceservice.NamespaceServiceClient
	authClient authservice.AuthServiceClient
	ctx        context.Context
}

func NewNamespaceClient(ctx context.Context, conn *grpc.ClientConn) *NamespaceClient {
	return &NamespaceClient{
		client:     namespaceservice.NewNamespaceServiceClient(conn),
		authClient: authservice.NewAuthServiceClient(conn),
		ctx:        ctx,
	}
}

type GetNamespaceClientFn func(ctx *cli.Context) (*NamespaceClient, error)

func GetNamespaceClient(ctx *cli.Context) (*NamespaceClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return NewNamespaceClient(ct, conn), nil
}

func (c *NamespaceClient) deleteNamespace(ctx *cli.Context, n *namespace.Namespace) (*request.RequestStatus, error) {
	resourceVersion := n.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}
	res, err := c.client.DeleteNamespace(c.ctx, &namespaceservice.DeleteNamespaceRequest{
		RequestId:       ctx.String(RequestIDFlagName),
		Namespace:       n.Namespace,
		ResourceVersion: resourceVersion,
	})
	if err != nil {
		return nil, err
	}
	return res.RequestStatus, nil
}

func (c *NamespaceClient) createNamespace(n *namespace.Namespace, p []*auth.UserNamespacePermissions) (*request.RequestStatus, error) {
	res, err := c.client.CreateNamespace(c.ctx, &namespaceservice.CreateNamespaceRequest{
		RequestId:                n.RequestId,
		Namespace:                n.Namespace,
		Spec:                     n.Spec,
		UserNamespacePermissions: p,
	})
	if err != nil {
		return nil, err
	}
	return res.RequestStatus, nil
}

func (c *NamespaceClient) listNamespaces() error {
	totalRes := &namespaceservice.ListNamespacesResponse{}
	pageToken := ""
	for {
		res, err := c.client.ListNamespaces(c.ctx, &namespaceservice.ListNamespacesRequest{
			PageToken: pageToken,
		})
		if err != nil {
			return err
		}
		totalRes.Namespaces = append(totalRes.Namespaces, res.Namespaces...)
		// Check if we should continue paging
		pageToken = res.NextPageToken
		if len(pageToken) == 0 {
			return PrintProto(totalRes)
		}
	}
}

func (c *NamespaceClient) getNamespace(namespace string) (*namespace.Namespace, error) {
	res, err := c.client.GetNamespace(c.ctx, &namespaceservice.GetNamespaceRequest{
		Namespace: namespace,
	})
	if err != nil {
		return nil, err
	}
	if res.Namespace == nil || res.Namespace.Namespace == "" {
		// this should never happen, the server should return an error when the namespace is not found
		return nil, fmt.Errorf("invalid namespace returned by server")
	}
	return res.Namespace, nil
}

func (c *NamespaceClient) updateNamespace(ctx *cli.Context, n *namespace.Namespace) (*request.RequestStatus, error) {
	resourceVersion := n.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}

	res, err := c.client.UpdateNamespace(c.ctx, &namespaceservice.UpdateNamespaceRequest{
		RequestId:       ctx.String(RequestIDFlagName),
		Namespace:       n.Namespace,
		ResourceVersion: resourceVersion,
		Spec:            n.Spec,
	})
	if err != nil {
		return nil, err
	}

	return res.RequestStatus, nil
}

func (c *NamespaceClient) renameSearchAttribute(ctx *cli.Context, n *namespace.Namespace, existingName string, newName string) (*request.RequestStatus, error) {
	resourceVersion := n.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}
	res, err := c.client.RenameCustomSearchAttribute(c.ctx, &namespaceservice.RenameCustomSearchAttributeRequest{
		RequestId:                         ctx.String(RequestIDFlagName),
		Namespace:                         ctx.String(NamespaceFlagName),
		ResourceVersion:                   resourceVersion,
		ExistingCustomSearchAttributeName: existingName,
		NewCustomSearchAttributeName:      newName,
	})
	if err != nil {
		return nil, err
	}
	return res.RequestStatus, nil
}

func (c *NamespaceClient) parseExistingCerts(ctx *cli.Context) (namespace *namespace.Namespace, existing caCerts, err error) {
	n, err := c.getNamespace(ctx.String(NamespaceFlagName))
	if err != nil {
		return nil, nil, err
	}
	existingCerts, err := parseCertificates(n.Spec.AcceptedClientCa)
	if err != nil {
		return nil, nil, err
	}
	return n, existingCerts, nil
}

func (c *NamespaceClient) toUserNamespacePermissions(userPermissionsInput map[string]string) ([]*auth.UserNamespacePermissions, error) {
	var res []*auth.UserNamespacePermissions
	var errs error
	for email, actionGroup := range userPermissionsInput {
		u, err := c.authClient.GetUser(c.ctx, &authservice.GetUserRequest{
			UserEmail: email,
		})
		if err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
		if len(u.GetUser().GetId()) == 0 {
			errs = multierr.Append(errs, fmt.Errorf("user not found for: %s", email))
			continue
		}
		actionGroupID, ok := auth.NamespaceActionGroup_value[actionGroup]
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"namespace permission type \"%s\" does not exist, acceptable types are: %s",
				actionGroup,
				getNamespacePermissionTypes(),
			))
			continue
		}
		res = append(res, &auth.UserNamespacePermissions{
			UserId:      u.GetUser().GetId(),
			ActionGroup: auth.NamespaceActionGroup(actionGroupID),
		})
	}
	return res, errs
}

func readAndParseCACerts(ctx *cli.Context) (read caCerts, err error) {
	cert, err := ReadCACerts(ctx)
	if err != nil {
		return nil, err
	}
	return parseCertificates(cert)
}

// ReadCACerts reads ca certs based on cli flags.
func ReadCACerts(ctx *cli.Context) (string, error) {
	cert := ctx.String(CaCertificateFlagName)
	if cert == "" {
		if ctx.Path(CaCertificateFileFlagName) != "" {
			data, err := os.ReadFile(ctx.Path(CaCertificateFileFlagName))
			if err != nil {
				return "", err
			}
			cert = base64.StdEncoding.EncodeToString(data)
		}
	}
	if cert == "" {
		return "", fmt.Errorf("no ca certificate provided")
	}
	return cert, nil
}

func ReadCertFilters(ctx *cli.Context) ([]byte, error) {
	certFilterFilepath := ctx.Path(certificateFilterFileFlagName)
	certFilterInput := ctx.String(certificateFilterInputFlagName)
	if len(certFilterFilepath) > 0 && len(certFilterInput) > 0 {
		return nil, fmt.Errorf("only one of the %s or %s flags can be specified", certificateFilterFileFlagName, certificateFilterInputFlagName)
	}
	var certFilterBytes []byte
	var err error
	if len(certFilterFilepath) > 0 {
		certFilterBytes, err = os.ReadFile(certFilterFilepath)
		if err != nil {
			return nil, err
		}
	}
	if len(certFilterInput) > 0 {
		certFilterBytes = []byte(certFilterInput)
	}
	return certFilterBytes, nil
}

func readNamespaceSpecification(ctx *cli.Context) (*namespace.NamespaceSpec, error) {
	spec := ctx.String(SpecFlagName)
	if spec == "" {
		if ctx.Path(SpecFileFlagName) != "" {
			data, err := os.ReadFile(ctx.Path(SpecFileFlagName))
			if err != nil {
				return nil, err
			}
			spec = string(data)
		}
	}
	if spec == "" {
		return nil, fmt.Errorf("no specification provided")
	}
	var specProto namespace.NamespaceSpec
	unmarshaler := jsonpb.Unmarshaler{}
	err := unmarshaler.Unmarshal(strings.NewReader(spec), &specProto)
	if err != nil {
		return nil, err
	}
	return &specProto, nil
}

func NewNamespaceCommand(getNamespaceClientFn GetNamespaceClientFn, getRequestClientFn GetRequestClientFn) (CommandOut, error) {
	var (
		nc *NamespaceClient
		rc *RequestClient
	)

	subCommands := []*cli.Command{
		{
			Name:    "create",
			Usage:   "Create a temporal namespace",
			Aliases: []string{"c"},
			Flags: []cli.Flag{
				RequestIDFlag,
				CaCertificateFlag,
				WaitForRequestFlag,
				RequestTimeoutFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.StringFlag{
					Name:     namespaceRegionFlagName,
					Usage:    fmt.Sprintf("Create namespace in this region; valid regions are: %v", namespaceRegions),
					Aliases:  []string{"re"},
					Required: true,
				},
				&cli.IntFlag{
					Name:    RetentionDaysFlagName,
					Usage:   "The retention of the namespace in days",
					Aliases: []string{"rd"},
					Value:   30,
				},
				&cli.PathFlag{
					Name:    CaCertificateFileFlagName,
					Usage:   "The path to the ca pem file",
					Aliases: []string{"cf"},
				},
				&cli.PathFlag{
					Name:    certificateFilterFileFlagName,
					Usage:   `Path to a JSON file that defines the certificate filters that will be added to the namespace. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
					Aliases: []string{"cff"},
				},
				&cli.StringFlag{
					Name:    certificateFilterInputFlagName,
					Usage:   `JSON that defines the certificate filters that will be added to the namespace. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
					Aliases: []string{"cfi"},
				},
				&cli.StringSliceFlag{
					Name:    searchAttributeFlagName,
					Usage:   fmt.Sprintf("Flag can be used multiple times; value must be \"name=type\"; valid types are: %v", getSearchAttributeTypes()),
					Aliases: []string{"sa"},
				},
				&cli.StringSliceFlag{
					Name:    userNamespacePermissionFlagName,
					Usage:   fmt.Sprintf("Flag can be used multiple times; value must be \"email=permission\"; valid permissions are: %v", getNamespacePermissionTypes()),
					Aliases: []string{"p"},
				},
			},
			Action: func(ctx *cli.Context) error {
				n := &namespace.Namespace{
					RequestId: ctx.String(RequestIDFlagName),
					Namespace: ctx.String(NamespaceFlagName),
				}

				// region (required)
				region := ctx.String(namespaceRegionFlagName)
				if err := validateNamespaceRegion(region); err != nil {
					return err
				}
				n.Spec = &namespace.NamespaceSpec{
					Region: region,
				}

				// certs (required)
				cert, err := ReadCACerts(ctx)
				if err != nil {
					return err
				}
				n.Spec.AcceptedClientCa = cert

				// retention (required)
				retention := ctx.Int(RetentionDaysFlagName)
				if retention < 1 {
					return fmt.Errorf("retention cannot be 0 or negative")
				}
				n.Spec.RetentionDays = int32(retention)

				// user namespace permissions (optional)
				var unp []*auth.UserNamespacePermissions
				userNamespacePermissionFlags := ctx.StringSlice(userNamespacePermissionFlagName)
				if len(userNamespacePermissionFlags) > 0 {
					unpMap, err := toUserNamespacePermissionsMap(userNamespacePermissionFlags)
					if err != nil {
						return err
					}
					unp, err = nc.toUserNamespacePermissions(unpMap)
					if err != nil {
						return err
					}
				}

				// cert filters (optional)
				certFilterBytes, err := ReadCertFilters(ctx)
				if err != nil {
					return err
				}
				if len(certFilterBytes) > 0 {
					newFilters, err := parseCertificateFilters(certFilterBytes)
					if err != nil {
						return err
					}
					n.Spec.CertificateFilters = append(n.Spec.CertificateFilters, newFilters.toSpec()...)
				}

				// search attributes (optional)
				searchAttributes := ctx.StringSlice(searchAttributeFlagName)
				if len(searchAttributes) > 0 {
					csa, err := toSearchAttributes(searchAttributes)
					if err != nil {
						return err
					}
					if n.Spec.SearchAttributes == nil {
						n.Spec.SearchAttributes = make(map[string]namespace.SearchAttributeType)
					}
					for attrName, attrType := range csa {
						if _, ok := n.Spec.SearchAttributes[attrName]; ok {
							return fmt.Errorf("attribute with name '%s' already exists", attrName)
						} else {
							n.Spec.SearchAttributes[attrName] = attrType
						}
					}
				}
				status, err := nc.createNamespace(n, unp)
				if err != nil {
					return err
				}
				return rc.HandleRequestStatus(ctx, "create namespace", status)
			},
		},
		{
			Name:    "delete",
			Usage:   "Delete a temporal namespace",
			Aliases: []string{"d"},
			Flags: []cli.Flag{
				RequestIDFlag,
				ResourceVersionFlag,
				WaitForRequestFlag,
				RequestTimeoutFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
			},
			Action: func(ctx *cli.Context) error {
				namespaceName := ctx.String(NamespaceFlagName)
				yes, err := ConfirmPrompt(ctx,
					fmt.Sprintf(
						"Deleting a namespace will remove it completely and is not reversible.\nDo you still want to delete namespace \"%s\"?",
						namespaceName,
					),
				)
				if err != nil {
					return err
				}
				if !yes {
					return nil
				}
				n, err := nc.getNamespace(namespaceName)
				if err != nil {
					return err
				}
				status, err := nc.deleteNamespace(ctx, n)
				if err != nil {
					return err
				}
				return rc.HandleRequestStatus(ctx, "delete namespace", status)
			},
		},
		{
			Name:    "list",
			Usage:   "List all known namespaces",
			Aliases: []string{"l"},
			Flags:   []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				return nc.listNamespaces()
			},
		},
		{
			Name:    "get",
			Usage:   "Get namespace information",
			Aliases: []string{"g"},
			Flags: []cli.Flag{
				NamespaceFlag,
				&cli.BoolFlag{
					Name:  "spec",
					Usage: "get only the specification of the namespace",
				},
			},
			Action: func(ctx *cli.Context) error {
				n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
				if err != nil {
					return err
				}
				if ctx.Bool("spec") {
					return PrintProto(n.Spec)
				}
				return PrintProto(n)
			},
		},
		{
			Name:    "apply",
			Usage:   "Apply specification to namespace",
			Aliases: []string{"a"},
			Flags: []cli.Flag{
				NamespaceFlag,
				&cli.StringFlag{
					Name:  SpecFlagName,
					Usage: "the specification in JSON format to update the namespace to",
				},
				&cli.PathFlag{
					Name:  SpecFileFlagName,
					Usage: "the path to the file containing the specification in JSON format to update the namespace to",
				},
				RequestIDFlag,
				ResourceVersionFlag,
				WaitForRequestFlag,
				RequestTimeoutFlag,
			},
			Action: func(ctx *cli.Context) error {
				spec, err := readNamespaceSpecification(ctx)
				if err != nil {
					return err
				}
				n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
				if err != nil {
					return err
				}
				// allocate the pointers in the specs to get a correct diff
				allocate.MustZero(n.Spec)
				allocate.MustZero(spec)
				diff, err := ProtoDiff(n.Spec, spec)
				if err != nil {
					return err
				}
				if diff == "" {
					fmt.Printf("nothing to change\n")
					return nil
				}
				fmt.Printf("Changes: \n%s\n", diff)
				yes, err := ConfirmPrompt(ctx, fmt.Sprintf("Confirm changes for '%s' namespace?", ctx.String(NamespaceFlagName)))
				if err != nil {
					return err
				}
				if !yes {
					fmt.Printf("cancelled\n")
					return nil
				}
				n.Spec = spec
				status, err := nc.updateNamespace(ctx, n)
				if err != nil {
					return err
				}
				return rc.HandleRequestStatus(ctx, "update namespace", status)
			},
		},
		{
			Name:    "accepted-client-ca",
			Usage:   "Manage client ca certificate used to verify client connections",
			Aliases: []string{"ca"},
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List the accepted client ca certificates currently configured for the namespace",
					Flags: []cli.Flag{
						NamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						out, err := parseCertificates(n.Spec.AcceptedClientCa)
						if err != nil {
							return err
						}
						return PrintObj(out)
					},
				},
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new ca accepted client ca certificate",
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						CaCertificateFlag,
						CaCertificateFileFlag,
					},
					Action: func(ctx *cli.Context) error {
						newCerts, err := readAndParseCACerts(ctx)
						if err != nil {
							return err
						}
						n, existingCerts, err := nc.parseExistingCerts(ctx)
						if err != nil {
							return err
						}
						existingCerts, err = addCerts(existingCerts, newCerts)
						if err != nil {
							return err
						}
						bundle, err := existingCerts.bundle()
						if err != nil {
							return err
						}
						if n.Spec.AcceptedClientCa == bundle {
							return errors.New("nothing to change")
						}
						n.Spec.AcceptedClientCa = bundle
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "add ca certificate", status)
					},
				},
				{
					Name:    "remove",
					Aliases: []string{"r"},
					Usage:   "Remove existing certificates",
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						CaCertificateFlag,
						CaCertificateFileFlag,
						caCertificateFingerprintFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, existingCerts, err := nc.parseExistingCerts(ctx)
						if err != nil {
							return err
						}
						var certs caCerts
						if ctx.String(caCertificateFingerprintFlagName) != "" {
							certs, err = removeCertWithFingerprint(
								existingCerts,
								ctx.String(caCertificateFingerprintFlagName),
							)
							if err != nil {
								return err
							}
						} else {
							readCerts, err := readAndParseCACerts(ctx)
							if err != nil {
								return err
							}
							certs, err = removeCerts(existingCerts, readCerts)
							if err != nil {
								return err
							}
						}
						bundle, err := certs.bundle()
						if err != nil {
							return err
						}
						if n.Spec.AcceptedClientCa == bundle {
							return errors.New("nothing to change")
						}
						n.Spec.AcceptedClientCa = bundle
						y, err := ConfirmPrompt(ctx, "removing ca certificates can cause connectivity disruption if there are any clients using certificates that cannot be verified. confirm remove?")
						if err != nil || !y {
							return err
						}
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "remove ca certificate", status)
					},
				},
				{
					Name:    "set",
					Aliases: []string{"s"},
					Usage:   "Set the accepted client ca certificate",
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						CaCertificateFlag,
						CaCertificateFileFlag,
					},
					Action: func(ctx *cli.Context) error {
						cert, err := ReadCACerts(ctx)
						if err != nil {
							return err
						}
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if n.Spec.AcceptedClientCa == cert {
							return errors.New("nothing to change")
						}
						n.Spec.AcceptedClientCa = cert
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "set ca certificates", status)
					},
				},
			},
		},
		{
			Name:    "certificate-filters",
			Usage:   "Manage optional certificate filters used by namespace to authorize client certificates based on distinguished name fields",
			Aliases: []string{"cf"},
			Subcommands: []*cli.Command{
				{
					Name:    "import",
					Usage:   "Sets the certificate filters on the namespace. Existing filters will be replaced.",
					Aliases: []string{"imp"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.PathFlag{
							Name:    certificateFilterFileFlagName,
							Usage:   `Path to a JSON file that defines the certificate filters that will be configured on the namespace. This will replace the existing filter configuration. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
							Aliases: []string{"file", "f"},
						},
						&cli.StringFlag{
							Name:    certificateFilterInputFlagName,
							Usage:   `JSON that defines the certificate filters that will be configured on the namespace. This will replace the existing filter configuration. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
							Aliases: []string{"input", "i"},
						},
					},
					Action: func(ctx *cli.Context) error {
						fileFlagSet := ctx.Path(certificateFilterFileFlagName) != ""
						inputFlagSet := ctx.String(certificateFilterInputFlagName) != ""

						if fileFlagSet == inputFlagSet {
							return errors.New("exactly one of the certificate-filter-file or certificate-filter-input flags must be specified")
						}

						var jsonBytes []byte
						var err error

						if fileFlagSet {
							jsonBytes, err = os.ReadFile(ctx.Path(certificateFilterFileFlagName))
							if err != nil {
								return err
							}
						}

						if inputFlagSet {
							jsonBytes = []byte(ctx.String(certificateFilterInputFlagName))
						}

						replacementFilters, err := parseCertificateFilters(jsonBytes)
						if err != nil {
							return err
						}

						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}

						difference, err := compareCertificateFilters(fromSpec(n.Spec.CertificateFilters), replacementFilters)
						if err != nil {
							return err
						}

						fmt.Println("this import will result in the following changes to certificate filters:")
						fmt.Println(difference)

						confirmed, err := ConfirmPrompt(ctx, "confirm certificate filter import operation")
						if err != nil {
							return err
						}

						if !confirmed {
							fmt.Println("operation canceled")
							return nil
						}

						n.Spec.CertificateFilters = replacementFilters.toSpec()
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "import certificate filters", status)
					},
				},
				{
					Name:    "export",
					Usage:   "Exports existing certificate filters on the namespace",
					Aliases: []string{"exp"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.PathFlag{
							Name:    certificateFilterFileFlagName,
							Usage:   "Path to a JSON file where tcld will export the certificate filter configuration to",
							Aliases: []string{"file", "f"},
						},
					},
					Action: func(ctx *cli.Context) error {
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}

						filters := fromSpec(n.Spec.CertificateFilters)
						if err := PrintObj(filters); err != nil {
							return err
						}

						jsonString, err := FormatJson(filters)
						if err != nil {
							return err
						}

						exportFile := ctx.Path(certificateFilterFileFlagName)
						if exportFile != "" {
							if err := os.WriteFile(exportFile, []byte(jsonString), 0644); err != nil {
								return err
							}
						}

						return nil
					},
				},
				{
					Name:    "clear",
					Usage:   "Clears all certificate filters on the namespace. Note that this will allow *any* client certificate that chains up to a configured CA in the bundle to connect to the namespace",
					Aliases: []string{"c"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}

						fmt.Println("all certificate filters will be removed:")
						if err := PrintObj(fromSpec(n.Spec.CertificateFilters)); err != nil {
							return err
						}

						confirmed, err := ConfirmPrompt(ctx, "this will allow any client certificate that chains up to a configured CA in the bundle to connect to the namespace. confirm clear operation")
						if err != nil {
							return err
						}

						if !confirmed {
							fmt.Println("operation canceled")
							return nil
						}

						n.Spec.CertificateFilters = nil
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "clear certificate filters", status)
					},
				},
				{
					Name:    "add",
					Usage:   "Adds additional certificate filters to the namespace",
					Aliases: []string{"a"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.PathFlag{
							Name:    certificateFilterFileFlagName,
							Usage:   `Path to a JSON file that defines the certificate filters that will be added to the namespace. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
							Aliases: []string{"file", "f"},
						},
						&cli.StringFlag{
							Name:    certificateFilterInputFlagName,
							Usage:   `JSON that defines the certificate filters that will be added to the namespace. Sample JSON: { "filters": [ { "commonName": "test1" } ] }`,
							Aliases: []string{"input", "i"},
						},
					},
					Action: func(ctx *cli.Context) error {
						fileFlagSet := ctx.Path(certificateFilterFileFlagName) != ""
						inputFlagSet := ctx.String(certificateFilterInputFlagName) != ""

						if fileFlagSet == inputFlagSet {
							return errors.New("exactly one of the certificate-filter-file or certificate-filter-input flags must be specified")
						}

						var jsonBytes []byte
						var err error

						if fileFlagSet {
							jsonBytes, err = os.ReadFile(ctx.Path(certificateFilterFileFlagName))
							if err != nil {
								return err
							}
						}

						if inputFlagSet {
							jsonBytes = []byte(ctx.String(certificateFilterInputFlagName))
						}

						newFilters, err := parseCertificateFilters(jsonBytes)
						if err != nil {
							return err
						}

						if len(newFilters.toSpec()) == 0 {
							return errors.New("no new filters to add")
						}

						fmt.Println("the following certificate filters will be added to the namespace:")
						if err := PrintObj(newFilters); err != nil {
							return err
						}

						confirmed, err := ConfirmPrompt(ctx, "confirm add operation")
						if err != nil {
							return err
						}

						if !confirmed {
							fmt.Println("operation canceled")
							return nil
						}
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}

						n.Spec.CertificateFilters = append(n.Spec.CertificateFilters, newFilters.toSpec()...)
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "add certificate filters", status)

					},
				},
			},
		},
		{
			Name:    "retention",
			Usage:   "Manages configuration of the length of time (in days) a closed workflow will be preserved before deletion",
			Aliases: []string{"r"},
			Subcommands: []*cli.Command{
				{
					Name:    "set",
					Aliases: []string{"s"},
					Usage:   "Set the length of time (in days) a closed workflow will be preserved before deletion for a given namespace",
					Flags: []cli.Flag{
						NamespaceFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						RetentionDaysFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						retention := ctx.Int(RetentionDaysFlagName)
						if retention == 0 {
							return fmt.Errorf("retention must be at least 1 day in duration")
						}
						if retention < 0 {
							return fmt.Errorf("retention cannot be negative")
						}
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if int32(retention) == n.Spec.RetentionDays {
							return fmt.Errorf("retention for namespace is already set at %d days", ctx.Int(RetentionDaysFlagName))
						}
						n.Spec.RetentionDays = int32(retention)
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "set retention", status)
					},
				},
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "Retrieve the length of time (in days) a closed workflow will be preserved before deletion for a given namespace",
					Flags: []cli.Flag{
						NamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						fmt.Println(n.Spec.RetentionDays)
						return nil
					},
				},
			},
		},
		{
			Name:    "search-attributes",
			Usage:   "Manage search attributes used by namespace",
			Aliases: []string{"sa"},
			Subcommands: []*cli.Command{
				{
					Name:    "add",
					Usage:   "Add a new namespace custom search attribute",
					Aliases: []string{"a"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.StringSliceFlag{
							Name:     "search-attribute",
							Usage:    fmt.Sprintf("Flag can be used multiple times; value must be \"name=type\"; valid types are: %v", getSearchAttributeTypes()),
							Aliases:  []string{"sa"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						csa, err := toSearchAttributes(ctx.StringSlice(searchAttributeFlagName))
						if err != nil {
							return err
						}
						n, err := nc.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if n.Spec.SearchAttributes == nil {
							n.Spec.SearchAttributes = make(map[string]namespace.SearchAttributeType)
						}
						for attrName, attrType := range csa {
							if _, ok := n.Spec.SearchAttributes[attrName]; ok {
								return fmt.Errorf("attribute with name '%s' already exists", attrName)
							} else {
								n.Spec.SearchAttributes[attrName] = attrType
							}
						}
						status, err := nc.updateNamespace(ctx, n)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "add search attribute", status)
					},
				},
				{
					Name:    "rename",
					Usage:   "Update the name of an existing custom search attribute",
					Aliases: []string{"rn"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.StringFlag{
							Name:     "existing-name",
							Usage:    "The name of an existing search attribute",
							Aliases:  []string{"en"},
							Required: true,
						},
						&cli.StringFlag{
							Name:     "new-name",
							Usage:    "The new name for the search attribute",
							Aliases:  []string{"nn"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						n, err := nc.getNamespace(
							ctx.String(NamespaceFlagName),
						)
						if err != nil {
							return err
						}
						existingName := ctx.String("existing-name")
						if _, exists := n.Spec.SearchAttributes[existingName]; !exists {
							return fmt.Errorf("search attribute with name '%s' does not exist", ctx.String("existing-name"))
						}
						newName := ctx.String("new-name")
						if _, exists := n.Spec.SearchAttributes[newName]; exists {
							return fmt.Errorf("search attribute with new name '%s' already exists", ctx.String("new-name"))
						}
						y, err := ConfirmPrompt(ctx, "renaming search attribute may cause failures if any worker is still using the old name of the search-attributes. confirm rename?")
						if err != nil || !y {
							return err
						}
						status, err := nc.renameSearchAttribute(ctx, n, existingName, newName)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "rename search attribute", status)

					},
				},
			},
		},
	}

	// ----------- Commands for private review feature, only available when feature flag turns on -----------
	// Export Command
	if IsFeatureEnabled(ExportFeatureFlag) {
		subCommands = append(subCommands, &cli.Command{
			Name:    "export",
			Usage:   "Manage export sinks",
			Aliases: []string{"es"},
		})
	}

	command := &cli.Command{
		Name:    "namespace",
		Aliases: []string{"n"},
		Usage:   "Namespace operations",
		Before: func(ctx *cli.Context) error {
			var err error
			nc, err = getNamespaceClientFn(ctx)
			if err != nil {
				return err
			}
			rc, err = getRequestClientFn(ctx)
			return err
		},
		Subcommands: subCommands,
	}

	return CommandOut{Command: command}, nil
}

func getSearchAttributeTypes() []string {
	validTypes := []string{}
	for i := 1; i < len(namespace.SearchAttributeType_name); i++ {
		validTypes = append(validTypes, namespace.SearchAttributeType_name[int32(i)])
	}
	return validTypes
}

func toSearchAttributes(keyValues []string) (map[string]namespace.SearchAttributeType, error) {
	res := map[string]namespace.SearchAttributeType{}
	for _, kv := range keyValues {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid search attribute \"%s\" must be of format: \"name=type\"", kv)
		}

		val, ok := namespace.SearchAttributeType_value[parts[1]]
		if !ok {
			return nil, fmt.Errorf(
				"search attribute type \"%s\" does not exist, acceptable types are: %s",
				parts[1],
				getSearchAttributeTypes(),
			)
		}

		res[parts[0]] = namespace.SearchAttributeType(val)
	}
	return res, nil
}

func getNamespacePermissionTypes() []string {
	validTypes := []string{}
	for i := 1; i < len(auth.NamespaceActionGroup_name); i++ {
		validTypes = append(validTypes, auth.NamespaceActionGroup_name[int32(i)])
	}
	return validTypes
}

func toUserNamespacePermissionsMap(keyValues []string) (map[string]string, error) {
	res := map[string]string{}
	for _, kv := range keyValues {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid user namespace permission \"%s\" must be of format: \"email=permission\"", kv)
		}

		email := parts[0]
		actionGroupValue := parts[1]

		if len(email) == 0 {
			return nil, errors.New("email address must not be empty in user namespace permission")
		}
		if _, err := mail.ParseAddress(email); err != nil {
			return nil, fmt.Errorf("unable to parse email address in user namespace permission: %w", err)
		}

		res[email] = actionGroupValue
	}
	return res, nil
}

func compareCertificateFilters(existing, replacement certificateFiltersConfig) (string, error) {
	existingBytes, err := FormatJson(existing)
	if err != nil {
		return "", err
	}

	replacementBytes, err := FormatJson(replacement)
	if err != nil {
		return "", err
	}

	return diff.Diff(string(existingBytes), string(replacementBytes)), nil
}

func validateNamespaceRegion(region string) error {
	for _, r := range namespaceRegions {
		if r == region {
			return nil
		}
	}
	return fmt.Errorf("namespace region: %s not allowed", region)
}
