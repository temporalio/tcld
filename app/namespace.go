package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/multierr"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	v14 "github.com/temporalio/tcld/protogen/api/common/v1"
	"github.com/temporalio/tcld/protogen/api/sink/v1"

	"github.com/kylelemons/godebug/diff"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"

	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/namespaceservice/v1"
)

const (
	namespaceRegionFlagName          = "region"
	CaCertificateFlagName            = "ca-certificate"
	CaCertificateFileFlagName        = "ca-certificate-file"
	caCertificateFingerprintFlagName = "ca-certificate-fingerprint"
	searchAttributeFlagName          = "search-attribute"
	userNamespacePermissionFlagName  = "user-namespace-permission"
	codecEndpointFlagName            = "endpoint"
	codecPassAccessTokenFlagName     = "pass-access-token"
	codecIncludeCredentialsFlagName  = "include-credentials"
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

	sinkNameFlag = &cli.StringFlag{
		Name:     "sink-name",
		Usage:    "Provide a name for the export sink",
		Required: true,
	}
	sinkAssumedRoleFlagOptional = &cli.StringFlag{
		Name:  "role-arn",
		Usage: "Provide role arn for the IAM Role",
	}
	sinkAssumedRoleFlagRequired = &cli.StringFlag{
		Name:     "role-arn",
		Usage:    "Provide role arn for the IAM Role",
		Required: true,
	}
	s3BucketFlagOptional = &cli.StringFlag{
		Name:  "s3-bucket-name",
		Usage: "Provide the name of an AWS S3 bucket that Temporal will send closed workflow histories to",
	}
	s3BucketFlagRequired = &cli.StringFlag{
		Name:     "s3-bucket-name",
		Usage:    "Provide the name of an AWS S3 bucket that Temporal will send closed workflow histories to",
		Required: true,
	}
	sinkEnabledFlag = &cli.StringFlag{
		Name:  "enabled",
		Usage: "Whether export is enabled",
	}
	kmsArnFlag = &cli.StringFlag{
		Name:  "kms-arn",
		Usage: "Provide the ARN of the KMS key to use for encryption. Note: If the KMS ARN needs to be added or updated, user should create the IAM Role with KMS or modify the created IAM Role accordingly. Provided it as part of the input won't help",
	}
	pageSizeFlag = &cli.IntFlag{
		Name:  "page-size",
		Usage: "The page size for list operations",
		Value: 100,
	}
	pageTokenFlag = &cli.StringFlag{
		Name:  "page-token",
		Usage: "The page token for list operations",
	}
	codecIncludeCredentialsFlag = &cli.BoolFlag{
		Name:    codecIncludeCredentialsFlagName,
		Usage:   "Include cross-origin credentials",
		Aliases: []string{"ic"},
	}
	codecPassAccessTokenFlag = &cli.BoolFlag{
		Name:    codecPassAccessTokenFlagName,
		Usage:   "Pass the user access token to the remote endpoint",
		Aliases: []string{"pat"},
	}
	codecEndpointFlag = &cli.StringFlag{
		Name:    codecEndpointFlagName,
		Usage:   "The codec server endpoint to decode payloads for all users interacting with this Namespace, must be https",
		Aliases: []string{"e"},
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

func (c *NamespaceClient) getExportSink(ctx *cli.Context, namespaceName, sinkName string) (*sink.ExportSink, error) {
	getRequest := &namespaceservice.GetExportSinkRequest{
		Namespace: namespaceName,
		SinkName:  sinkName,
	}

	getResp, err := c.client.GetExportSink(c.ctx, getRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get export sink: %w", err)
	}
	return getResp.Sink, nil
}

func (c *NamespaceClient) selectExportSinkResourceVersion(ctx *cli.Context, sink *sink.ExportSink) string {
	if ctx.String(ResourceVersionFlagName) != "" {
		return ctx.String(ResourceVersionFlagName)
	}
	return sink.ResourceVersion
}

func (c *NamespaceClient) isS3BucketChange(ctx *cli.Context, sink *sink.ExportSink) bool {
	if !ctx.IsSet(s3BucketFlagRequired.Name) {
		return false
	}

	return sink.GetSpec().GetS3Sink().GetBucketName() != ctx.String(s3BucketFlagRequired.Name)
}

func (c *NamespaceClient) isAssumedRoleChange(ctx *cli.Context, sink *sink.ExportSink) bool {
	if !ctx.IsSet(sinkAssumedRoleFlagRequired.Name) {
		return false
	}

	roleArn := getAssumedRoleArn(sink.GetSpec().GetS3Sink().GetAwsAccountId(), sink.GetSpec().GetS3Sink().GetRoleName())
	return roleArn != ctx.String(sinkAssumedRoleFlagRequired.Name)

}

func (c *NamespaceClient) isKmsArnChange(ctx *cli.Context, sink *sink.ExportSink) bool {
	if !ctx.IsSet(kmsArnFlag.Name) {
		return false
	}

	return sink.GetSpec().GetS3Sink().GetKmsArn() != ctx.String(kmsArnFlag.Name)
}

func (c *NamespaceClient) isSinkEnabledChange(ctx *cli.Context, sink *sink.ExportSink) (bool, error) {
	if !ctx.IsSet(sinkEnabledFlag.Name) {
		return false, nil
	}

	enabledValue, err := strconv.ParseBool(ctx.String(sinkEnabledFlag.Name))
	if err != nil {
		return false, fmt.Errorf("invalid value for enabled flag: %w. Only allowed true or false", err)
	}

	if sink.GetSpec().GetEnabled() == enabledValue {
		return false, nil
	}
	return true, nil
}

func (c *NamespaceClient) getExportSinkResourceVersion(ctx *cli.Context, namespaceName, sinkName string) (string, error) {
	sink, err := c.getExportSink(ctx, namespaceName, sinkName)
	if err != nil {
		return "", err
	}

	resourceVersion := c.selectExportSinkResourceVersion(ctx, sink)

	return resourceVersion, nil
}
func (c *NamespaceClient) deleteNamespace(ctx *cli.Context, n *namespace.Namespace) error {
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
		return err
	}
	return PrintProto(res)
}
func (c *NamespaceClient) failoverNamespace(ctx *cli.Context) error {
	namespaceName := ctx.String(NamespaceFlagName)
	targetRegion := ctx.String("target-region")
	skipGracefulFailover := ctx.Bool("skip-graceful-failover")
	res, err := c.client.FailoverNamespace(c.ctx, &namespaceservice.FailoverNamespaceRequest{
		Namespace: namespaceName,
		RequestId: uuid.NewString(),
		TargetRegion: &v14.RegionID{
			CloudProvider: "aws",
			Name:          targetRegion,
		},
		SkipGracefulFailover: skipGracefulFailover,
	})
	if err != nil {
		return err
	}
	return PrintProto(res)
}

func (c *NamespaceClient) createNamespace(n *namespace.Namespace, p []*auth.UserNamespacePermissions) error {
	res, err := c.client.CreateNamespace(c.ctx, &namespaceservice.CreateNamespaceRequest{
		RequestId:                n.RequestId,
		Namespace:                n.Namespace,
		Spec:                     n.Spec,
		UserNamespacePermissions: p,
	})
	if err != nil {
		return err
	}
	return PrintProto(res)
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

func (c *NamespaceClient) updateNamespace(ctx *cli.Context, n *namespace.Namespace) error {
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
		return err
	}

	return PrintProto(res)
}

func (c *NamespaceClient) renameSearchAttribute(ctx *cli.Context, n *namespace.Namespace, existingName string, newName string) error {
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
		return err
	}
	return PrintProto(res)
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

func NewNamespaceCommand(getNamespaceClientFn GetNamespaceClientFn) (CommandOut, error) {
	var c *NamespaceClient
	subCommands := []*cli.Command{
		{
			Name:    "create",
			Usage:   "Create a temporal namespace",
			Aliases: []string{"c"},
			Flags: []cli.Flag{
				RequestIDFlag,
				CaCertificateFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.StringFlag{
					Name:     namespaceRegionFlagName,
					Usage:    "Create namespace in specified region; see 'tcld account list-regions' to get a list of available regions for your account",
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
				codecEndpointFlag,
				codecPassAccessTokenFlag,
				codecIncludeCredentialsFlag,
			},
			Action: func(ctx *cli.Context) error {
				n := &namespace.Namespace{
					RequestId: ctx.String(RequestIDFlagName),
					Namespace: ctx.String(NamespaceFlagName),
				}

				n.Spec = &namespace.NamespaceSpec{
					Region: ctx.String(namespaceRegionFlagName),
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
					unp, err = c.toUserNamespacePermissions(unpMap)
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

				codecEndpoint := ctx.String(codecEndpointFlagName)
				// codec server spec is optional, if specified, we need to create the spec and pass along to the API
				if codecEndpoint != "" {
					err = validateCodecEndpoint(codecEndpoint)
					if err != nil {
						return err
					}
					n.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
						Endpoint:           codecEndpoint,
						PassAccessToken:    ctx.Bool(codecPassAccessTokenFlagName),
						IncludeCredentials: ctx.Bool(codecIncludeCredentialsFlagName),
					}
				} else {
					if ctx.Bool(codecPassAccessTokenFlagName) || ctx.Bool(codecIncludeCredentialsFlagName) {
						return errors.New("pass-access-token or include-credentials cannot be specified when codec endpoint is not specified")
					}
				}

				return c.createNamespace(n, unp)
			},
		},
		{
			Name:    "delete",
			Usage:   "Delete a temporal namespace",
			Aliases: []string{"d"},
			Flags: []cli.Flag{
				RequestIDFlag,
				ResourceVersionFlag,
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
				n, err := c.getNamespace(namespaceName)
				if err != nil {
					return err
				}
				return c.deleteNamespace(ctx, n)
			},
		},
		{
			Name:    "failover",
			Usage:   "[Experimental feature] Failover changes a temporal global namespace's active region",
			Aliases: []string{"fo"},
			Flags: []cli.Flag{
				RequestIDFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.StringFlag{
					Name:     "target-region",
					Usage:    "The region to be primary",
					Required: true,
				},
				&cli.BoolFlag{
					Name:  "skip-graceful-failover",
					Usage: "Skip Graceful failover",
				},
			},
			Action: func(ctx *cli.Context) error {
				yes, err := ConfirmPrompt(ctx,
					fmt.Sprintf(
						"Failover a namespace will change the namespace primary region.\nDo you still want to continue ?",
					),
				)
				if err != nil {
					return err
				}
				if !yes {
					return nil
				}
				return c.failoverNamespace(ctx)
			},
		},
		{
			Name:    "list",
			Usage:   "List all known namespaces",
			Aliases: []string{"l"},
			Flags:   []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				return c.listNamespaces()
			},
		},
		{
			Name:    "get",
			Usage:   "Get namespace information",
			Aliases: []string{"g"},
			Flags: []cli.Flag{
				NamespaceFlag,
			},
			Action: func(ctx *cli.Context) error {
				n, err := c.getNamespace(ctx.String(NamespaceFlagName))
				if err != nil {
					return err
				}
				return PrintProto(n)
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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
						CaCertificateFlag,
						CaCertificateFileFlag,
					},
					Action: func(ctx *cli.Context) error {
						newCerts, err := readAndParseCACerts(ctx)
						if err != nil {
							return err
						}
						n, existingCerts, err := c.parseExistingCerts(ctx)
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
						return c.updateNamespace(ctx, n)
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
						CaCertificateFlag,
						CaCertificateFileFlag,
						caCertificateFingerprintFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, existingCerts, err := c.parseExistingCerts(ctx)
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
						return c.updateNamespace(ctx, n)
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
						CaCertificateFlag,
						CaCertificateFileFlag,
					},
					Action: func(ctx *cli.Context) error {
						cert, err := ReadCACerts(ctx)
						if err != nil {
							return err
						}
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if n.Spec.AcceptedClientCa == cert {
							return errors.New("nothing to change")
						}
						n.Spec.AcceptedClientCa = cert
						return c.updateNamespace(ctx, n)
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

						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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

						if confirmed {
							n.Spec.CertificateFilters = replacementFilters.toSpec()
							return c.updateNamespace(ctx, n)
						}

						fmt.Println("operation canceled")
						return nil
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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

						if confirmed {
							n.Spec.CertificateFilters = nil
							return c.updateNamespace(ctx, n)
						}

						fmt.Println("operation canceled")
						return nil
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

						if confirmed {
							n, err := c.getNamespace(ctx.String(NamespaceFlagName))
							if err != nil {
								return err
							}

							n.Spec.CertificateFilters = append(n.Spec.CertificateFilters, newFilters.toSpec()...)
							return c.updateNamespace(ctx, n)
						}

						fmt.Println("operation canceled")
						return nil
					},
				},
			},
		},
		{
			Name:    "update-codec-server",
			Usage:   "Update codec server config used to decode encoded payloads through remote endpoint",
			Aliases: []string{"ucs"},
			Flags: []cli.Flag{
				NamespaceFlag,
				&cli.StringFlag{
					Name:     codecEndpointFlag.Name,
					Usage:    codecEndpointFlag.Usage,
					Aliases:  codecEndpointFlag.Aliases,
					Required: true,
				},
				codecPassAccessTokenFlag,
				codecIncludeCredentialsFlag,
			},
			Action: func(ctx *cli.Context) error {
				n, err := c.getNamespace(ctx.String(NamespaceFlagName))
				if err != nil {
					return err
				}

				codecEndpoint := ctx.String(codecEndpointFlagName)
				err = validateCodecEndpoint(codecEndpoint)
				if err != nil {
					return err
				}
				replacement := &namespace.CodecServerPropertySpec{
					Endpoint:           codecEndpoint,
					PassAccessToken:    ctx.Bool(codecPassAccessTokenFlagName),
					IncludeCredentials: ctx.Bool(codecIncludeCredentialsFlagName),
				}

				difference, err := compareCodecSpec(n.Spec.CodecSpec, replacement)
				if err != nil {
					return err
				}

				fmt.Println("this update will result in the following changes to the codec server config:")
				fmt.Println(difference)

				confirmed, err := ConfirmPrompt(ctx, "confirm codec server update operation")
				if err != nil {
					return err
				}

				if confirmed {
					n.Spec.CodecSpec = replacement
					return c.updateNamespace(ctx, n)
				}

				fmt.Println("operation canceled")
				return nil
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if int32(retention) == n.Spec.RetentionDays {
							return fmt.Errorf("retention for namespace is already set at %d days", ctx.Int(RetentionDaysFlagName))
						}
						n.Spec.RetentionDays = int32(retention)
						return c.updateNamespace(ctx, n)
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
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

						return c.updateNamespace(ctx, n)
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
						n, err := c.getNamespace(
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
						return c.renameSearchAttribute(ctx, n, existingName, newName)
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
			Subcommands: []*cli.Command{
				{
					Name:    "create",
					Aliases: []string{"c"},
					Usage:   "Create export sink",
					Flags: []cli.Flag{
						NamespaceFlag,
						sinkNameFlag,
						sinkAssumedRoleFlagRequired,
						s3BucketFlagRequired,
						RequestIDFlag,
						kmsArnFlag,
					},
					Action: func(ctx *cli.Context) error {
						awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagRequired.Name))
						if err != nil {
							return err
						}

						namespace := ctx.String(NamespaceFlagName)
						ns, err := c.getNamespace(namespace)
						if err != nil {
							return fmt.Errorf("unable to get namespace: %v", err)
						}

						request := &namespaceservice.CreateExportSinkRequest{
							Namespace: namespace,
							Spec: &sink.ExportSinkSpec{
								Name:            ctx.String(sinkNameFlag.Name),
								Enabled:         true,
								DestinationType: sink.EXPORT_DESTINATION_TYPE_S3,
								S3Sink: &sink.S3Spec{
									RoleName:     roleName,
									BucketName:   ctx.String(s3BucketFlagRequired.Name),
									Region:       ns.Spec.Region,
									KmsArn:       ctx.String(kmsArnFlag.Name),
									AwsAccountId: awsAccountID,
								},
							},
							RequestId: ctx.String(RequestIDFlagName),
						}

						res, err := c.client.CreateExportSink(c.ctx, request)
						if err != nil {
							return err
						}

						return PrintProto(res.RequestStatus)
					},
				},
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "Get export sink",
					Flags: []cli.Flag{
						NamespaceFlag,
						sinkNameFlag,
					},
					Action: func(ctx *cli.Context) error {
						sink, err := c.getExportSink(ctx, ctx.String(NamespaceFlagName), ctx.String(sinkNameFlag.Name))

						if err != nil {
							return err
						}

						return PrintProto(sink)
					},
				},
				{
					Name:  "validate",
					Usage: "Validate export sink",
					Flags: []cli.Flag{
						NamespaceFlag,
						sinkNameFlag,
						sinkAssumedRoleFlagRequired,
						s3BucketFlagRequired,
						kmsArnFlag,
					},
					Action: func(ctx *cli.Context) error {
						namespace := ctx.String(NamespaceFlagName)
						ns, err := c.getNamespace(namespace)
						if err != nil {
							return fmt.Errorf("validation failed: unable to get namespace: %v", err)
						}

						awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagRequired.Name))
						if err != nil {
							return fmt.Errorf("validation failed: %v", err)
						}

						validateRequest := &namespaceservice.ValidateExportSinkRequest{
							Namespace: ctx.String(NamespaceFlagName),
							Spec: &sink.ExportSinkSpec{
								Name:            ctx.String(sinkNameFlag.Name),
								DestinationType: sink.EXPORT_DESTINATION_TYPE_S3,
								S3Sink: &sink.S3Spec{
									RoleName:     roleName,
									BucketName:   ctx.String(s3BucketFlagRequired.Name),
									Region:       ns.Spec.Region,
									KmsArn:       ctx.String(kmsArnFlag.Name),
									AwsAccountId: awsAccountID,
								},
							},
						}

						_, err = c.client.ValidateExportSink(c.ctx, validateRequest)

						if err != nil {
							return fmt.Errorf("validation failed with error %v", err)
						}

						fmt.Println("Validate test file can be written to the sink successfully")
						return nil
					},
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete export sink",
					Flags: []cli.Flag{
						NamespaceFlag,
						sinkNameFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						namespaceName := ctx.String(NamespaceFlagName)
						sinkName := ctx.String(sinkNameFlag.Name)
						resourceVersion, err := c.getExportSinkResourceVersion(ctx, namespaceName, sinkName)
						if err != nil {
							return err
						}

						deleteRequest := &namespaceservice.DeleteExportSinkRequest{
							Namespace:       namespaceName,
							SinkName:        sinkName,
							ResourceVersion: resourceVersion,
							RequestId:       ctx.String(RequestIDFlagName),
						}

						deleteResp, err := c.client.DeleteExportSink(c.ctx, deleteRequest)
						if err != nil {
							return err
						}

						return PrintProto(deleteResp.RequestStatus)
					},
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List export sinks",
					Flags: []cli.Flag{
						NamespaceFlag,
						pageSizeFlag,
						pageTokenFlag,
					},
					Action: func(ctx *cli.Context) error {
						request := &namespaceservice.ListExportSinksRequest{
							Namespace: ctx.String(NamespaceFlagName),
							PageSize:  int32(pageSizeFlag.Value),
							PageToken: ctx.String(pageTokenFlag.Name),
						}

						resp, err := c.client.ListExportSinks(c.ctx, request)
						if err != nil {
							return err
						}

						return PrintProto(resp)
					},
				},
				{
					Name:    "update",
					Aliases: []string{"u"},
					Usage:   "Update export sink",
					Flags: []cli.Flag{
						NamespaceFlag,
						sinkNameFlag,
						sinkEnabledFlag,
						sinkAssumedRoleFlagOptional,
						s3BucketFlagOptional,
						ResourceVersionFlag,
						kmsArnFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						namespaceName := ctx.String(NamespaceFlagName)
						sinkName := ctx.String(sinkNameFlag.Name)
						sink, err := c.getExportSink(ctx, namespaceName, sinkName)
						if err != nil {
							return err
						}
						resourceVersion := c.selectExportSinkResourceVersion(ctx, sink)

						isEnabledChange, err := c.isSinkEnabledChange(ctx, sink)
						if err != nil {
							return err
						}

						if !isEnabledChange && !c.isAssumedRoleChange(ctx, sink) && !c.isKmsArnChange(ctx, sink) && !c.isS3BucketChange(ctx, sink) {
							fmt.Println("nothing to update")
							return nil
						}

						if isEnabledChange {
							sink.Spec.Enabled = !sink.Spec.Enabled
						}

						if c.isAssumedRoleChange(ctx, sink) {
							awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagOptional.Name))
							if err != nil {
								return err
							}
							sink.Spec.S3Sink.RoleName = roleName
							sink.Spec.S3Sink.AwsAccountId = awsAccountID
						}

						if c.isKmsArnChange(ctx, sink) {
							sink.Spec.S3Sink.KmsArn = ctx.String(kmsArnFlag.Name)
						}

						if c.isS3BucketChange(ctx, sink) {
							sink.Spec.S3Sink.BucketName = ctx.String(s3BucketFlagOptional.Name)
						}

						request := &namespaceservice.UpdateExportSinkRequest{
							Namespace:       ctx.String(NamespaceFlagName),
							Spec:            sink.Spec,
							ResourceVersion: resourceVersion,
							RequestId:       ctx.String(RequestIDFlagName),
						}

						resp, err := c.client.UpdateExportSink(c.ctx, request)
						if err != nil {
							return err
						}

						return PrintProto(resp.RequestStatus)
					},
				},
			},
		})
	}

	command := &cli.Command{
		Name:    "namespace",
		Aliases: []string{"n"},
		Usage:   "Namespace operations",
		Before: func(ctx *cli.Context) error {
			var err error
			c, err = getNamespaceClientFn(ctx)
			return err
		},
		Subcommands: subCommands,
	}

	return CommandOut{Command: command}, nil
}

func validateCodecEndpoint(codecEndpoint string) error {
	if !strings.HasPrefix(codecEndpoint, "https://") {
		return errors.New("field Endpoint has to use https")
	}
	return nil
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

func compareCodecSpec(existing, replacement *namespace.CodecServerPropertySpec) (string, error) {
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
