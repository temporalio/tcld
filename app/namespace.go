package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/temporalio/tcld/protogen/api/common/v1"

	"go.uber.org/multierr"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/utils"

	"github.com/kylelemons/godebug/diff"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"

	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	cloudNamespace "github.com/temporalio/tcld/protogen/api/cloud/namespace/v1"
	cloudSink "github.com/temporalio/tcld/protogen/api/cloud/sink/v1"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/namespaceservice/v1"
)

const (
	namespaceRegionFlagName          = "region"
	cloudProviderFlagName            = "cloud-provider"
	authMethodFlagName               = "auth-method"
	CaCertificateFlagName            = "ca-certificate"
	CaCertificateFileFlagName        = "ca-certificate-file"
	caCertificateFingerprintFlagName = "ca-certificate-fingerprint"
	searchAttributeFlagName          = "search-attribute"
	userNamespacePermissionFlagName  = "user-namespace-permission"
	codecEndpointFlagName            = "endpoint"
	codecPassAccessTokenFlagName     = "pass-access-token"
	codecIncludeCredentialsFlagName  = "include-credentials"
	sinkRegionFlagName               = "region"
	disableFailoverFlagName          = "disable-auto-failover"
	enableDeleteProtectionFlagName   = "enable-delete-protection"
	tagFlagName                      = "tag"

	capacityModeFlagName  = "capacity-mode"
	capacityValueFlagName = "capacity-value"

	provisionedCapacityMode = "provisioned"
	onDemandCapacityMode    = "on_demand"
)

const (
	AuthMethodRestricted   = "restricted"
	AuthMethodMTLS         = "mtls"
	AuthMethodAPIKey       = "api_key"
	AuthMethodAPIKeyOrMTLS = "api_key_or_mtls"
)

const (
	MaxPageSize     = 1000
	DefaultPageSize = 100
)

var (
	AuthMethods = []string{
		AuthMethodRestricted,
		AuthMethodMTLS,
		AuthMethodAPIKey,
		AuthMethodAPIKeyOrMTLS,
	}
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
		Usage:    "Provide a name for the sink",
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
		Usage: "Whether the sink is enabled",
	}
	kmsArnFlag = &cli.StringFlag{
		Name:  "kms-arn",
		Usage: "Provide the ARN of the KMS key to use for encryption. Note: If the KMS ARN needs to be added or updated, user must create the IAM Role with KMS or modify the created IAM Role accordingly.",
	}
	pageSizeFlag = &cli.IntFlag{
		Name:  "page-size",
		Usage: "The page size for list operations",
		Value: DefaultPageSize,
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
	saPrincipalFlagRequired = &cli.StringFlag{
		Name:     "service-account-email",
		Usage:    "Service account that has access to the sink",
		Required: true,
	}
	saPrincipalFlagOptional = &cli.StringFlag{
		Name:  "service-account-email",
		Usage: "Service account that has access to the sink",
	}
	gcsBucketFlagRequired = &cli.StringFlag{
		Name:     "gcs-bucket",
		Usage:    "GCS bucket of the sink",
		Required: true,
	}
	gcsBucketFlagOptional = &cli.StringFlag{
		Name:  "gcs-bucket",
		Usage: "GCS bucket of the sink",
	}
	sinkRegionFlag = &cli.StringFlag{
		Name:     sinkRegionFlagName,
		Usage:    "The region to use for the request, if not set the server will use the namespace's region",
		Aliases:  []string{"re"},
		Required: false,
	}
	connectivityRuleIdsFlag = &cli.StringSliceFlag{
		Name:     connectivityRuleIdsFlagName,
		Usage:    "The list of connectivity rule IDs, can be used in create namespace and update namespace. example: --ids id1 --ids id2 --ids id3",
		Aliases:  []string{"ids"},
		Required: false,
	}

	capacityModeFlag = &cli.StringFlag{
		Name:     capacityModeFlagName,
		Usage:    fmt.Sprintf("The capacity mode to use for the namespace. Valid values are '%s' and '%s'", onDemandCapacityMode, provisionedCapacityMode),
		Aliases:  []string{"cm"},
		Required: false,
		Action: func(_ *cli.Context, s string) error {
			switch s {
			case "", onDemandCapacityMode, provisionedCapacityMode:
				return nil
			default:
				return fmt.Errorf("invalid capacity mode %s, valid values are 'on_demand' and 'provisioned'", s)
			}
		},
	}

	capacityValueFlag = &cli.Float64Flag{
		Name:     capacityValueFlagName,
		Usage:    "The capacity value to use for the namespace. Required if capacity mode is 'provisioned', ignored otherwise",
		Aliases:  []string{"cv"},
		Required: false,
	}
)

type NamespaceClient struct {
	client         namespaceservice.NamespaceServiceClient
	cloudAPIClient cloudservice.CloudServiceClient
	authClient     authservice.AuthServiceClient
	ctx            context.Context
}

func NewNamespaceClient(ctx context.Context, conn *grpc.ClientConn) *NamespaceClient {
	return &NamespaceClient{
		client:         namespaceservice.NewNamespaceServiceClient(conn),
		cloudAPIClient: cloudservice.NewCloudServiceClient(conn),
		authClient:     authservice.NewAuthServiceClient(conn),
		ctx:            ctx,
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

func (c *NamespaceClient) isSinkToggleChange(ctx *cli.Context, sink *cloudNamespace.ExportSink) (bool, error) {
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

func (c *NamespaceClient) createNamespace(n *namespace.Namespace, p []*auth.UserNamespacePermissions, tags map[string]string) error {
	res, err := c.client.CreateNamespace(c.ctx, &namespaceservice.CreateNamespaceRequest{
		RequestId:                n.RequestId,
		Namespace:                n.Namespace,
		Spec:                     n.Spec,
		UserNamespacePermissions: p,
		Tags:                     tags,
	})
	if err != nil {
		return err
	}
	return PrintProto(res)
}

func (c *NamespaceClient) addRegion(ctx *cli.Context) error {
	ns, err := c.getNamespace(ctx.String(NamespaceFlagName))
	if err != nil {
		return err
	}

	region := ctx.String(namespaceRegionFlagName)
	if len(region) == 0 {
		return fmt.Errorf("namespace region is required")
	}

	cloudProvider := ctx.String(cloudProviderFlagName)
	if len(cloudProvider) == 0 {
		return fmt.Errorf("namespace cloud provider is required")
	}

	targetRegion := fmt.Sprintf("%s-%s", cloudProvider, region)
	if err := utils.ValidateCloudProviderAndRegion(targetRegion); err != nil {
		return err
	}

	res, err := c.cloudAPIClient.AddNamespaceRegion(c.ctx, &cloudservice.AddNamespaceRegionRequest{
		Namespace:        ctx.String(NamespaceFlagName),
		Region:           targetRegion,
		ResourceVersion:  ns.GetResourceVersion(),
		AsyncOperationId: ctx.String(RequestIDFlagName),
	})
	if err != nil {
		return err
	}
	return PrintProto(res.GetAsyncOperation())
}

func (c *NamespaceClient) deleteRegion(ctx *cli.Context) error {
	ns, err := c.getNamespace(ctx.String(NamespaceFlagName))
	if err != nil {
		return err
	}

	region := ctx.String(namespaceRegionFlagName)
	if len(region) == 0 {
		return fmt.Errorf("namespace region is required")
	}

	cloudProvider := ctx.String(cloudProviderFlagName)
	if len(cloudProvider) == 0 {
		return fmt.Errorf("namespace cloud provider is required")
	}

	deleteRegion := fmt.Sprintf("%s-%s", cloudProvider, region)
	if err := utils.ValidateCloudProviderAndRegion(deleteRegion); err != nil {
		return err
	}

	res, err := c.cloudAPIClient.DeleteNamespaceRegion(c.ctx, &cloudservice.DeleteNamespaceRegionRequest{
		Namespace:        ns.GetNamespace(),
		Region:           deleteRegion,
		ResourceVersion:  ns.GetResourceVersion(),
		AsyncOperationId: ctx.String(RequestIDFlagName),
	})
	if err != nil {
		return err
	}

	return PrintProto(res.GetAsyncOperation())
}

func (c *NamespaceClient) listNamespaces(requestedPageToken string, pageSize int) error {
	// Fetch a single page of namespaces.
	if len(requestedPageToken) > 0 || pageSize > 0 {
		res, err := c.client.ListNamespaces(c.ctx, &namespaceservice.ListNamespacesRequest{
			PageToken: requestedPageToken,
			PageSize:  int32(pageSize),
		})
		if err != nil {
			return err
		}
		return PrintProto(res)
	}

	// Fetch all namespaces.
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

func (c *NamespaceClient) getNamespaceCloudApi(namespace string) (*cloudNamespace.Namespace, error) {
	res, err := c.cloudAPIClient.GetNamespace(c.ctx, &cloudservice.GetNamespaceRequest{
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

func (c *NamespaceClient) getNamespaceCapacityInfoCloudApi(namespace string) (*cloudNamespace.NamespaceCapacityInfo, error) {
	res, err := c.cloudAPIClient.GetNamespaceCapacityInfo(c.ctx, &cloudservice.GetNamespaceCapacityInfoRequest{
		Namespace: namespace,
	})
	if err != nil {
		return nil, err
	}
	if res.GetCapacityInfo() == nil || res.GetCapacityInfo().Namespace == "" {
		// this should never happen, the server should return an error when the namespace capacity info is not found or invalid
		return nil, fmt.Errorf("invalid namespace capacity info returned by server")
	}
	return res.CapacityInfo, nil
}

// TODO: deprecate this and use getNamespaceCloudApi everywhere
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
		if isNothingChangedErr(ctx, err) {
			return nil
		}
		return err
	}

	return PrintProto(res)
}

func (c *NamespaceClient) updateNamespaceCloudApi(ctx *cli.Context, n *cloudNamespace.Namespace) error {
	resourceVersion := n.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}

	res, err := c.cloudAPIClient.UpdateNamespace(c.ctx, &cloudservice.UpdateNamespaceRequest{
		AsyncOperationId: ctx.String(RequestIDFlagName),
		Namespace:        n.Namespace,
		ResourceVersion:  resourceVersion,
		Spec:             n.Spec,
	})
	if err != nil {
		if isNothingChangedErr(ctx, err) {
			return nil
		}
		return err
	}

	return PrintProto(res)
}

func (c *NamespaceClient) updateNamespaceTags(ctx *cli.Context, tagsToUpsert map[string]string, tagsToRemove []string) error {
	namespace := ctx.String(NamespaceFlagName)
	if len(namespace) == 0 {
		return fmt.Errorf("namespace is required")
	}

	res, err := c.cloudAPIClient.UpdateNamespaceTags(c.ctx, &cloudservice.UpdateNamespaceTagsRequest{
		Namespace:        namespace,
		TagsToUpsert:     tagsToUpsert,
		TagsToRemove:     tagsToRemove,
		AsyncOperationId: ctx.String(RequestIDFlagName),
	})
	if err != nil {
		return err
	}
	return PrintProto(res.GetAsyncOperation())
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

func (c *NamespaceClient) failoverNamespace(ctx *cli.Context) error {
	namespace := ctx.String(NamespaceFlagName)
	if len(namespace) == 0 {
		return fmt.Errorf("namespace is required")
	}

	region := ctx.String(namespaceRegionFlagName)
	if len(region) == 0 {
		return fmt.Errorf("region is required")
	}

	cloudProvider := ctx.String(cloudProviderFlagName)
	if len(cloudProvider) == 0 {
		return fmt.Errorf("cloud provider is required")
	}

	targetRegion := fmt.Sprintf("%s-%s", cloudProvider, region)
	if err := utils.ValidateCloudProviderAndRegion(targetRegion); err != nil {
		return err
	}

	res, err := c.cloudAPIClient.FailoverNamespaceRegion(c.ctx, &cloudservice.FailoverNamespaceRegionRequest{
		Namespace:        namespace,
		Region:           targetRegion,
		AsyncOperationId: ctx.String(RequestIDFlagName),
	})
	if err != nil {
		return err
	}
	return PrintProto(res.GetAsyncOperation())
}

// ReadCACerts reads ca certs based on cli flags.
func ReadCACerts(ctx *cli.Context) (string, error) {
	return ReadCACertsRequired(ctx, true)
}

func ReadCACertsRequired(ctx *cli.Context, required bool) (string, error) {
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
	if cert == "" && required {
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

func getCreateNamespaceFlags() []cli.Flag {
	baseFlags := []cli.Flag{
		RequestIDFlag,
		CaCertificateFlag,
		&cli.StringFlag{
			Name:     NamespaceFlagName,
			Usage:    "The namespace hosted on temporal cloud",
			Aliases:  []string{"n"},
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:     namespaceRegionFlagName,
			Usage:    "Create namespace in specified regions; if multiple regions are selected, the first one will be the active region. See 'tcld account list-regions' to get a list of available regions for your account",
			Aliases:  []string{"re"},
			Required: true,
		},
		&cli.IntFlag{
			Name:    RetentionDaysFlagName,
			Usage:   "The retention of the namespace in days",
			Aliases: []string{"rd"},
			Value:   30,
		},
		&cli.StringFlag{
			Name:  authMethodFlagName,
			Usage: "The authentication method to use for the namespace (e.g. 'mtls', 'api_key')",
			Value: AuthMethodMTLS,
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
		&cli.BoolFlag{
			Name:    enableDeleteProtectionFlagName,
			Usage:   "Enable delete protection on the namespace",
			Aliases: []string{"edp"},
		},
		codecEndpointFlag,
		codecPassAccessTokenFlag,
		codecIncludeCredentialsFlag,
		&cli.StringFlag{
			Name:    cloudProviderFlagName,
			Usage:   `Cloud provider for the namespace to be created for, currently support [aws, gcp].  For this version, if not specified, we default to aws`,
			Aliases: []string{"cp"},
			// this is a temporary solution, we will have a follow up version update to make the cloud provider mandatory
			Value: CloudProviderAWS,
		},
		&cli.StringSliceFlag{
			Name:    tagFlagName,
			Usage:   "Add tags to the namespace (format: key=value). Flag can be used multiple times.",
			Aliases: []string{"t"},
		},
		connectivityRuleIdsFlag,
	}

	return baseFlags
}

func NewNamespaceCommand(getNamespaceClientFn GetNamespaceClientFn) (CommandOut, error) {
	var c *NamespaceClient
	subCommands := []*cli.Command{
		{
			Name:    "create",
			Usage:   "Create a temporal namespace",
			Aliases: []string{"c"},
			Flags:   getCreateNamespaceFlags(),
			Action: func(ctx *cli.Context) error {
				n := &namespace.Namespace{
					RequestId: ctx.String(RequestIDFlagName),
					Namespace: ctx.String(NamespaceFlagName),
					Spec:      &namespace.NamespaceSpec{},
				}

				regions := ctx.StringSlice(namespaceRegionFlagName)
				if len(regions) == 0 {
					return fmt.Errorf("namespace region is required")
				}
				if len(regions) > 2 {
					return fmt.Errorf("namespace can only be replicated up to 2 regions")
				}

				// Check if any region has cloud provider prefix
				hasCloudPrefix := false
				var regionIDs []string
				for _, region := range regions {
					if strings.HasPrefix(region, CloudProviderAWS) || strings.HasPrefix(region, CloudProviderGCP) {
						hasCloudPrefix = true
						regionIDs = append(regionIDs, region)
					} else {
						cloudProvider := ctx.String(cloudProviderFlagName)
						if len(cloudProvider) == 0 {
							return fmt.Errorf("namespace cloud provider is required when regions don't have cloud provider prefix")
						}
						regionIDs = append(regionIDs, fmt.Sprintf("%s-%s", cloudProvider, region))
					}
				}

				// If any region has cloud prefix, validate all regions have the same prefix
				if hasCloudPrefix {
					for _, region := range regions {
						if !strings.HasPrefix(region, CloudProviderAWS) && !strings.HasPrefix(region, CloudProviderGCP) {
							return fmt.Errorf("all regions must have the same cloud provider prefix. Found %s ", region)
						}
					}
				}

				// Set active region
				activeRegionID := regionIDs[0]
				activeRegion, err := regionIDFromString(activeRegionID)
				if err != nil {
					return err
				}
				n.Spec.RegionId = activeRegion

				// Set passive regions if any
				if len(regions) > 1 {
					passiveRegionIDs := make([]*common.RegionID, len(regionIDs)-1)
					for i, regionID := range regionIDs[1:] {
						passiveRegionID, err := regionIDFromString(regionID)
						if err != nil {
							return err
						}
						passiveRegionIDs[i] = passiveRegionID
					}
					n.Spec.PassiveRegionIds = passiveRegionIDs
				}

				authMethod, err := toAuthMethod(ctx.String(authMethodFlagName))
				if err != nil {
					return err
				}
				n.Spec.AuthMethod = authMethod

				// certs (required if mTLS is enabled)
				cert, err := ReadCACertsRequired(ctx, authMethod == namespace.AUTH_METHOD_MTLS ||
					authMethod == namespace.AUTH_METHOD_API_KEY_OR_MTLS,
				)
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

				n.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: ctx.Bool(enableDeleteProtectionFlagName),
				}

				connectivityRuleIds := ctx.StringSlice(connectivityRuleIdsFlagName)
				if len(connectivityRuleIds) > 0 {
					n.Spec.ConnectivityRuleIds = connectivityRuleIds
				}

				tags := ctx.StringSlice(tagFlagName)
				tagsToCreate := make(map[string]string)
				for _, tag := range tags {
					parts := strings.Split(tag, "=")
					if len(parts) != 2 {
						return fmt.Errorf("invalid tag format '%s', must be 'key=value'", tag)
					}
					key := parts[0]
					if _, exists := tagsToCreate[key]; exists {
						return fmt.Errorf("duplicate tag key '%s' found", key)
					}
					tagsToCreate[key] = parts[1]
				}

				return c.createNamespace(n, unp, tagsToCreate)
			},
		},
		{
			Name:  "add-region",
			Usage: "Add a new region to a namespace",
			Flags: []cli.Flag{
				RequestIDFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.StringFlag{
					Name:     namespaceRegionFlagName,
					Usage:    "New region to add to the namespace.",
					Aliases:  []string{"re"},
					Required: true,
				},
				&cli.StringFlag{
					Name:  cloudProviderFlagName,
					Usage: "The cloud provider of the region. Default: aws",
					Value: CloudProviderAWS,
				},
			},
			Action: func(ctx *cli.Context) error {
				return c.addRegion(ctx)
			},
		},
		{
			Name:  "delete-region",
			Usage: "Delete a region from a namespace",
			Flags: []cli.Flag{
				RequestIDFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.StringFlag{
					Name:     namespaceRegionFlagName,
					Usage:    "The region to remove from a namespace.",
					Aliases:  []string{"re"},
					Required: true,
				},
				&cli.StringFlag{
					Name:  cloudProviderFlagName,
					Usage: "The cloud provider of the region. Default: aws",
					Value: CloudProviderAWS,
				},
			},
			Action: func(ctx *cli.Context) error {
				return c.deleteRegion(ctx)
			},
		},
		{
			Name:    "lifecycle",
			Usage:   "Enable delete protection on a temporal namespace",
			Aliases: []string{"lc"},
			Subcommands: []*cli.Command{
				{
					Name:  "get",
					Usage: "Get the lifecycle spec for the namespace",
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
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						return PrintProto(n.Spec.Lifecycle)
					},
				},
				{
					Name:  "set",
					Usage: "Set the lifecycle spec for the namespace",
					Flags: []cli.Flag{
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringFlag{
							Name:     NamespaceFlagName,
							Usage:    "The namespace hosted on temporal cloud",
							Aliases:  []string{"n"},
							Required: true,
						},
						&cli.StringFlag{
							Name:    enableDeleteProtectionFlagName,
							Usage:   "Enable delete protection on the namespace, value must be true or false",
							Aliases: []string{"edp"},
						},
					},
					Action: func(ctx *cli.Context) error {
						// for now this is the only option but add more here in the future
						if !ctx.IsSet(enableDeleteProtectionFlagName) {
							return errors.New("at least one option for lifecycle spec must be set")
						}

						enable, err := strconv.ParseBool(ctx.String(enableDeleteProtectionFlagName))
						if err != nil {
							return fmt.Errorf("not a valid boolean: %s", err.Error())
						}

						namespaceName := ctx.String(NamespaceFlagName)
						n, err := c.getNamespace(namespaceName)
						if err != nil {
							return err
						}

						if enable {
							if n.Spec.Lifecycle != nil && n.Spec.Lifecycle.EnableDeleteProtection {
								if ctx.Bool(IdempotentFlagName) {
									return nil
								}

								return errors.New("delete protection is already enabled")
							}
							n.Spec.Lifecycle = &namespace.LifecycleSpec{
								EnableDeleteProtection: true,
							}
						} else {
							if n.Spec.Lifecycle == nil || !n.Spec.Lifecycle.EnableDeleteProtection {
								if ctx.Bool(IdempotentFlagName) {
									return nil
								}
								return errors.New("delete protection is already disabled")
							}
							y, err := ConfirmPrompt(ctx, "disabling namespace delete protection may be prone to accidental deletion. confirm?")
							if err != nil || !y {
								return err
							}
							n.Spec.Lifecycle = &namespace.LifecycleSpec{
								EnableDeleteProtection: false,
							}
						}
						return c.updateNamespace(ctx, n)
					},
				},
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
			Name:    "list",
			Usage:   "List all known namespaces",
			Aliases: []string{"l"},
			Flags: []cli.Flag{
				pageTokenFlag,
				&cli.IntFlag{
					Name:  pageSizeFlagName,
					Usage: "Number of namespaces to list per page",
				},
			},
			Action: func(ctx *cli.Context) error {
				if ctx.IsSet(pageSizeFlagName) {
					if ctx.Int(pageSizeFlagName) <= 0 {
						return fmt.Errorf("page size cannot be less than or equal to 0")
					}
					if ctx.Int(pageSizeFlagName) > MaxPageSize {
						return fmt.Errorf("page size cannot be greater than %d", MaxPageSize)
					}
				}
				return c.listNamespaces(ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName))
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
							if ctx.Bool(IdempotentFlagName) {
								return nil
							}
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
						&cli.BoolFlag{
							Name:  "all",
							Usage: "If set, all existing certificates will be removed",
						},
					},
					Action: func(ctx *cli.Context) error {
						removeAll := ctx.Bool("all")
						if removeAll && (ctx.String(caCertificateFingerprintFlagName) != "" ||
							ctx.String(CaCertificateFlagName) != "" ||
							ctx.Path(CaCertificateFileFlagName) != "") {
							return fmt.Errorf("cannot use --all with other certificate flags")
						}

						n, existingCerts, err := c.parseExistingCerts(ctx)
						if err != nil {
							return err
						}

						if removeAll && (n.Spec.AuthMethod == namespace.AUTH_METHOD_MTLS ||
							n.Spec.AuthMethod == namespace.AUTH_METHOD_API_KEY_OR_MTLS) {
							return fmt.Errorf("cannot remove all certificates when mTLS is enabled")
						}

						var certBundle string
						if !removeAll {
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
							certBundle, err = certs.bundle()
							if err != nil {
								return err
							}
						}

						if n.Spec.AcceptedClientCa == certBundle {
							if ctx.Bool(IdempotentFlagName) {
								return nil
							}
							return errors.New("nothing to change")
						}

						n.Spec.AcceptedClientCa = certBundle
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
							if ctx.Bool(IdempotentFlagName) {
								return nil
							}
							return errors.New("nothing to change")
						}
						n.Spec.AcceptedClientCa = cert
						return c.updateNamespace(ctx, n)
					},
				},
			},
		},
		{
			Name:    "auth-method",
			Usage:   "Manage the authentication method for the namespace",
			Aliases: []string{"am"},
			Subcommands: []*cli.Command{
				{
					Name:  "set",
					Usage: "Set the authentication method for the namespace",
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringFlag{
							Name:     authMethodFlagName,
							Aliases:  []string{"am"},
							Usage:    fmt.Sprintf("The authentication method used for the namespace (i.e. %s)", formatStringSlice(AuthMethods)),
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						authMethod, err := toAuthMethod(ctx.String(authMethodFlagName))
						if err != nil {
							return err
						}
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						if n.Spec.AuthMethod == authMethod {
							if ctx.Bool(IdempotentFlagName) {
								return nil
							}
							return errors.New("nothing to change")
						}
						if disruptiveChange(n.Spec.AuthMethod, authMethod) {
							yes, err := ConfirmPrompt(ctx,
								fmt.Sprintf("setting auth method from '%s' to '%s' will cause existing client connections to fail. "+
									"are you sure you want to continue?", n.Spec.AuthMethod, authMethod))
							if err != nil {
								return err
							}
							if !yes {
								return nil
							}
						}
						n.Spec.AuthMethod = authMethod
						return c.updateNamespace(ctx, n)
					},
				},
				{
					Name:  "get",
					Usage: "Retrieve the authentication method for namespace",
					Flags: []cli.Flag{
						NamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						fmt.Println(toString(n.Spec.AuthMethod))
						return nil
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
					Name:    "remove",
					Usage:   "Remove an existing namespace custom search attribute",
					Aliases: []string{"rm"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringFlag{
							Name:     "search-attribute",
							Usage:    "The name of the search attribute to remove",
							Aliases:  []string{"sa"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						n, err := c.getNamespace(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						attrName := ctx.String("search-attribute")
						if _, exists := n.Spec.SearchAttributes[attrName]; !exists {
							return fmt.Errorf("search attribute with name '%s' does not exist", attrName)
						}
						delete(n.Spec.SearchAttributes, attrName)
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
		{
			Name:    "failover",
			Usage:   "Failover a temporal namespace",
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
					Name:     namespaceRegionFlagName,
					Usage:    "The region to failover to",
					Aliases:  []string{"re"},
					Required: true,
				},
				&cli.StringFlag{
					Name:  cloudProviderFlagName,
					Usage: "The cloud provider of the region. Default: aws",
					Value: CloudProviderAWS,
				},
			},
			Action: func(ctx *cli.Context) error {
				namespaceName := ctx.String(NamespaceFlagName)
				region := ctx.String(namespaceRegionFlagName)
				yes, err := ConfirmPrompt(ctx,
					fmt.Sprintf(
						"Do you want to failover namespace \"%s\" to region \"%s\"?",
						namespaceName,
						region,
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
			Name:    "update-high-availability",
			Usage:   "Update Temporal namespace high availability setting",
			Aliases: []string{"uha"},
			Flags: []cli.Flag{
				RequestIDFlag,
				&cli.StringFlag{
					Name:     NamespaceFlagName,
					Usage:    "The namespace hosted on temporal cloud",
					Aliases:  []string{"n"},
					Required: true,
				},
				&cli.BoolFlag{
					Name:  disableFailoverFlagName,
					Usage: "Disable Temporal-managed failover on a replicated namespace (use --disable-auto-failover=false to enable)",
				},
			},
			Action: func(ctx *cli.Context) error {
				n, err := c.getNamespace(ctx.String(NamespaceFlagName))
				if err != nil {
					return err
				}
				nsUpdated := false
				if ctx.IsSet(disableFailoverFlagName) {
					disableAutoFailover := ctx.Bool(disableFailoverFlagName)
					n.Spec.HighAvailability.DisableManagedFailover = disableAutoFailover
					nsUpdated = true
				}

				if nsUpdated {
					return c.updateNamespace(ctx, n)
				}
				fmt.Println("No changes to apply to Namespace:", ctx.String(NamespaceFlagName))
				return nil
			},
		},
		{
			Name:    "tags",
			Usage:   "Manage namespace tags",
			Aliases: []string{"t"},
			Subcommands: []*cli.Command{
				{
					Name:    "upsert",
					Usage:   "Add new tags or update existing tag values",
					Aliases: []string{"u"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						&cli.StringSliceFlag{
							Name:     "tag",
							Usage:    "Add new or update existing namespace tags (format: key=value). Flag can be used multiple times.",
							Aliases:  []string{"t"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						tags := ctx.StringSlice("tag")

						tagsToUpsert := make(map[string]string)
						for _, tag := range tags {
							parts := strings.Split(tag, "=")
							if len(parts) != 2 {
								return fmt.Errorf("invalid tag format '%s', must be 'key=value'", tag)
							}
							key := parts[0]
							if _, exists := tagsToUpsert[key]; exists {
								return fmt.Errorf("duplicate tag key '%s' found", key)
							}
							tagsToUpsert[key] = parts[1]
						}

						return c.updateNamespaceTags(ctx, tagsToUpsert, nil)
					},
				},
				{
					Name:    "remove",
					Usage:   "Remove existing tags by key",
					Aliases: []string{"rm"},
					Flags: []cli.Flag{
						NamespaceFlag,
						RequestIDFlag,
						&cli.StringSliceFlag{
							Name:     "tag-key",
							Usage:    "Remove namespace tags by key. Flag can be used multiple times.",
							Aliases:  []string{"tk"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						keysToRemove := ctx.StringSlice("tag-key")
						return c.updateNamespaceTags(ctx, nil, keysToRemove)
					},
				},
			},
		},
		{
			Name:    "capacity",
			Usage:   "Manage namespace capacity",
			Aliases: []string{"cap"},
			Subcommands: []*cli.Command{
				{
					Name:    "get",
					Usage:   "Get namespace capacity information",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						NamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						capacityInfo, err := c.getNamespaceCapacityInfoCloudApi(ctx.String(NamespaceFlagName))
						if err != nil {
							return err
						}
						return PrintProto(capacityInfo)
					},
				},
				{
					Name:    "update",
					Usage:   "Set the capacity of a given namespace.",
					Aliases: []string{"u"},
					Flags: []cli.Flag{
						NamespaceFlag,
						capacityModeFlag,
						capacityValueFlag,
						RequestIDFlag,
						ResourceVersionFlag,
					},
					Action: func(ctx *cli.Context) error {
						nsID := ctx.String(NamespaceFlagName)
						mode := ctx.String(capacityModeFlagName)
						value := ctx.Float64(capacityValueFlagName)
						if mode == "" {
							return fmt.Errorf("capacity mode must be specified (either '%s' or '%s')", onDemandCapacityMode, provisionedCapacityMode)
						}
						if mode == provisionedCapacityMode && value <= 0 {
							return fmt.Errorf("capacity value must be greater than 0 when capacity mode is '%s'", provisionedCapacityMode)
						}
						var capacitySpec *cloudNamespace.CapacitySpec
						switch mode {
						case onDemandCapacityMode:
							capacitySpec = &cloudNamespace.CapacitySpec{
								Spec: &cloudNamespace.CapacitySpec_OnDemand_{
									OnDemand: &cloudNamespace.CapacitySpec_OnDemand{},
								},
							}
						case provisionedCapacityMode:
							capacitySpec = &cloudNamespace.CapacitySpec{
								Spec: &cloudNamespace.CapacitySpec_Provisioned_{
									Provisioned: &cloudNamespace.CapacitySpec_Provisioned{
										Value: value,
									},
								},
							}
						}
						ns, err := c.getNamespaceCloudApi(nsID)
						if err != nil {
							return err
						}

						if ns != nil && ns.Spec == nil {
							ns.Spec = &cloudNamespace.NamespaceSpec{}
						}
						ns.Spec.CapacitySpec = capacitySpec
						return c.updateNamespaceCloudApi(ctx, ns)
					},
				},
			},
		},
	}

	// Export Related Command
	exportCommand := &cli.Command{
		Name:    "export",
		Usage:   "Manage export",
		Aliases: []string{"es"},
	}
	exportGeneralCommands := []*cli.Command{
		{
			Name:    "get",
			Aliases: []string{"g"},
			Usage:   "Get export sink",
			Flags: []cli.Flag{
				NamespaceFlag,
				sinkNameFlag,
			},
			Action: func(ctx *cli.Context) error {
				getExportSinkRes, err := c.cloudAPIClient.GetNamespaceExportSink(c.ctx, &cloudservice.GetNamespaceExportSinkRequest{
					Namespace: ctx.String(NamespaceFlag.Name),
					Name:      ctx.String(sinkNameFlag.Name),
				})
				if err != nil {
					return fmt.Errorf("unable to get export sink: %v", err)
				}
				return PrintProto(getExportSinkRes)
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
				namespaceName := ctx.String(NamespaceFlag.Name)
				sinkName := ctx.String(sinkNameFlag.Name)
				resourceVersion := ctx.String(ResourceVersionFlag.Name)

				if resourceVersion == "" {
					getExportSinkRes, err := c.cloudAPIClient.GetNamespaceExportSink(c.ctx, &cloudservice.GetNamespaceExportSinkRequest{
						Namespace: namespaceName,
						Name:      sinkName,
					})
					if err != nil {
						return fmt.Errorf("unable to get export sink: %v", err)
					}
					resourceVersion = getExportSinkRes.GetSink().GetResourceVersion()
				}

				deleteRequest := &cloudservice.DeleteNamespaceExportSinkRequest{
					Namespace:       namespaceName,
					Name:            sinkName,
					ResourceVersion: resourceVersion,
				}

				deleteResp, err := c.cloudAPIClient.DeleteNamespaceExportSink(c.ctx, deleteRequest)
				if err != nil {
					return err
				}
				return PrintProto(deleteResp.GetAsyncOperation())
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
				request := &cloudservice.GetNamespaceExportSinksRequest{
					Namespace: ctx.String(NamespaceFlag.Name),
					PageSize:  int32(ctx.Int(pageSizeFlag.Name)),
					PageToken: ctx.String(pageTokenFlag.Name),
				}
				resp, err := c.cloudAPIClient.GetNamespaceExportSinks(c.ctx, request)
				if err != nil {
					return err
				}
				return PrintProto(resp)
			},
		},
	}

	exportS3Commands := &cli.Command{
		Name:  "s3",
		Usage: "Manage S3 export sink",
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
					kmsArnFlag,
					sinkRegionFlag,
				},
				Action: func(ctx *cli.Context) error {
					awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagRequired.Name))
					if err != nil {
						return err
					}
					namespace := ctx.String(NamespaceFlagName)
					region := ctx.String(sinkRegionFlagName)

					if len(region) == 0 {
						ns, err := c.getNamespace(namespace)
						if err != nil {
							return fmt.Errorf("unable to get namespace: %v", err)
						}
						region = ns.Spec.RegionId.Name
					}

					createRequest := &cloudservice.CreateNamespaceExportSinkRequest{
						Namespace: ctx.String(NamespaceFlag.Name),
						Spec: &cloudNamespace.ExportSinkSpec{
							Name:    ctx.String(sinkNameFlag.Name),
							Enabled: true,
							S3: &cloudSink.S3Spec{
								BucketName:   ctx.String(s3BucketFlagRequired.Name),
								RoleName:     roleName,
								AwsAccountId: awsAccountID,
								KmsArn:       ctx.String(kmsArnFlag.Name),
								Region:       region,
							},
						},
					}

					createResp, err := c.cloudAPIClient.CreateNamespaceExportSink(c.ctx, createRequest)
					if err != nil {
						return err
					}

					return PrintProto(createResp.GetAsyncOperation())
				},
			},
			{
				Name:    "validate",
				Usage:   "Validate export sink",
				Aliases: []string{"v"},
				Flags: []cli.Flag{
					NamespaceFlag,
					sinkNameFlag,
					sinkAssumedRoleFlagRequired,
					s3BucketFlagRequired,
					kmsArnFlag,
					sinkRegionFlag,
				},
				Action: func(ctx *cli.Context) error {
					namespace := ctx.String(NamespaceFlagName)
					region := ctx.String(sinkRegionFlagName)
					if len(region) == 0 {
						ns, err := c.getNamespace(namespace)
						if err != nil {
							return fmt.Errorf("validation failed: unable to get namespace: %v", err)
						}
						region = ns.Spec.RegionId.Name
					}
					awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagRequired.Name))
					if err != nil {
						return fmt.Errorf("validation failed: %v", err)
					}

					validateRequest := &cloudservice.ValidateNamespaceExportSinkRequest{
						Namespace: ctx.String(NamespaceFlag.Name),
						Spec: &cloudNamespace.ExportSinkSpec{
							Name: ctx.String(sinkNameFlag.Name),
							S3: &cloudSink.S3Spec{
								BucketName:   ctx.String(s3BucketFlagRequired.Name),
								RoleName:     roleName,
								Region:       region,
								AwsAccountId: awsAccountID,
								KmsArn:       ctx.String(kmsArnFlag.Name),
							},
						},
					}

					_, err = c.cloudAPIClient.ValidateNamespaceExportSink(c.ctx, validateRequest)
					if err != nil {
						return fmt.Errorf("validation failed with error %v", err)
					}

					fmt.Println("Temporal Cloud was able to write test data to the sink")
					return nil

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
				},
				Action: func(ctx *cli.Context) error {
					namespaceName := ctx.String(NamespaceFlag.Name)
					sinkName := ctx.String(sinkNameFlag.Name)
					getExportSinkRes, err := c.cloudAPIClient.GetNamespaceExportSink(c.ctx, &cloudservice.GetNamespaceExportSinkRequest{
						Namespace: namespaceName,
						Name:      sinkName,
					})

					if err != nil {
						return fmt.Errorf("unable to get export sink: %v", err)
					}

					resourceVersion := ctx.String(ResourceVersionFlag.Name)
					if resourceVersion == "" {
						resourceVersion = getExportSinkRes.GetSink().GetResourceVersion()
					}

					spec := getExportSinkRes.GetSink().GetSpec()
					isToggleChanged, err := c.isSinkToggleChange(ctx, getExportSinkRes.GetSink())
					if err != nil {
						return err
					}

					if !isToggleChanged && !ctx.IsSet(saPrincipalFlagOptional.Name) && !ctx.IsSet(gcsBucketFlagOptional.Name) {
						fmt.Println("nothing to update")
						return nil
					}

					if isToggleChanged {
						spec.Enabled = !spec.Enabled
					}

					if ctx.IsSet(sinkAssumedRoleFlagOptional.Name) {
						awsAccountID, roleName, err := parseAssumedRole(ctx.String(sinkAssumedRoleFlagRequired.Name))
						if err != nil {
							return err
						}

						spec.S3.RoleName = roleName
						spec.S3.AwsAccountId = awsAccountID
					}

					if ctx.IsSet(s3BucketFlagOptional.Name) {
						spec.S3.BucketName = ctx.String(s3BucketFlagOptional.Name)
					}

					if ctx.IsSet(kmsArnFlag.Name) {
						spec.S3.KmsArn = ctx.String(kmsArnFlag.Name)
					}

					updateRequest := &cloudservice.UpdateNamespaceExportSinkRequest{
						Namespace:       namespaceName,
						ResourceVersion: resourceVersion,
						Spec:            spec,
					}

					updateResp, err := c.cloudAPIClient.UpdateNamespaceExportSink(c.ctx, updateRequest)
					if err != nil {
						return err
					}
					return PrintProto(updateResp.GetAsyncOperation())
				},
			},
		},
	}

	exportGCSCommands := &cli.Command{
		Name:  "gcs",
		Usage: "Manage GCS export sink",
		Subcommands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "Create export sink",
				Flags: []cli.Flag{
					NamespaceFlag,
					sinkNameFlag,
					saPrincipalFlagRequired,
					gcsBucketFlagRequired,
				},
				Action: func(ctx *cli.Context) error {
					SaId, projectName, err := parseSAPrincipal(ctx.String(saPrincipalFlagRequired.Name))
					if err != nil {
						return err
					}
					namespace := ctx.String(NamespaceFlagName)
					_, err = c.getNamespace(namespace)
					if err != nil {
						return fmt.Errorf("unable to get namespace: %v", err)
					}
					createRequest := &cloudservice.CreateNamespaceExportSinkRequest{
						Namespace: ctx.String(NamespaceFlag.Name),
						Spec: &cloudNamespace.ExportSinkSpec{
							Name:    ctx.String(sinkNameFlag.Name),
							Enabled: true,
							Gcs: &cloudSink.GCSSpec{
								GcpProjectId: projectName,
								BucketName:   ctx.String(gcsBucketFlagRequired.Name),
								SaId:         SaId,
							},
						},
					}

					createResp, err := c.cloudAPIClient.CreateNamespaceExportSink(c.ctx, createRequest)
					if err != nil {
						return err
					}

					return PrintProto(createResp.GetAsyncOperation())
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
					saPrincipalFlagOptional,
					gcsBucketFlagOptional,
					ResourceVersionFlag,
				},
				Action: func(ctx *cli.Context) error {
					namespaceName := ctx.String(NamespaceFlag.Name)
					sinkName := ctx.String(sinkNameFlag.Name)
					getExportSinkRes, err := c.cloudAPIClient.GetNamespaceExportSink(c.ctx, &cloudservice.GetNamespaceExportSinkRequest{
						Namespace: namespaceName,
						Name:      sinkName,
					})

					if err != nil {
						return fmt.Errorf("unable to get export sink: %v", err)
					}

					resourceVersion := ctx.String(ResourceVersionFlag.Name)
					if resourceVersion == "" {
						resourceVersion = getExportSinkRes.GetSink().GetResourceVersion()
					}

					spec := getExportSinkRes.GetSink().GetSpec()
					isToggleChanged, err := c.isSinkToggleChange(ctx, getExportSinkRes.GetSink())
					if err != nil {
						return err
					}
					if isToggleChanged {
						spec.Enabled = !spec.Enabled
					}

					if !isToggleChanged && !ctx.IsSet(saPrincipalFlagOptional.Name) && !ctx.IsSet(gcsBucketFlagOptional.Name) {
						fmt.Println("nothing to update")
						return nil
					}

					if ctx.IsSet(saPrincipalFlagOptional.Name) {
						SaId, GcpProjectId, _ := parseSAPrincipal(ctx.String(saPrincipalFlagRequired.Name))
						spec.Gcs.SaId = SaId
						spec.Gcs.GcpProjectId = GcpProjectId
					}

					if ctx.IsSet(gcsBucketFlagOptional.Name) {
						spec.Gcs.BucketName = ctx.String(gcsBucketFlagOptional.Name)
					}

					updateRequest := &cloudservice.UpdateNamespaceExportSinkRequest{
						Namespace:       namespaceName,
						ResourceVersion: resourceVersion,
						Spec:            spec,
					}

					updateResp, err := c.cloudAPIClient.UpdateNamespaceExportSink(c.ctx, updateRequest)
					if err != nil {
						return err
					}
					return PrintProto(updateResp.GetAsyncOperation())
				},
			},
			{
				Name:    "validate",
				Usage:   "Validate export sink",
				Aliases: []string{"v"},
				Flags: []cli.Flag{
					NamespaceFlag,
					sinkNameFlag,
					saPrincipalFlagRequired,
					gcsBucketFlagRequired,
				},
				Action: func(ctx *cli.Context) error {
					namespace := ctx.String(NamespaceFlagName)
					_, err := c.getNamespace(namespace)
					if err != nil {
						return fmt.Errorf("unable to get existing namespace: %v", err)
					}

					SaId, projectName, err := parseSAPrincipal(ctx.String(saPrincipalFlagRequired.Name))
					if err != nil {
						return err
					}

					validateRequest := &cloudservice.ValidateNamespaceExportSinkRequest{
						Namespace: ctx.String(NamespaceFlag.Name),
						Spec: &cloudNamespace.ExportSinkSpec{
							Name: ctx.String(sinkNameFlag.Name),
							Gcs: &cloudSink.GCSSpec{
								GcpProjectId: projectName,
								BucketName:   ctx.String(gcsBucketFlagRequired.Name),
								SaId:         SaId,
							},
						},
					}

					_, err = c.cloudAPIClient.ValidateNamespaceExportSink(c.ctx, validateRequest)
					if err != nil {
						return fmt.Errorf("validation failed with error %v", err)
					}

					fmt.Println("Temporal Cloud was able to write test data to the sink")
					return nil

				},
			},
		},
	}

	exportS3Commands.Subcommands = append(exportS3Commands.Subcommands, exportGeneralCommands...)
	exportCommand.Subcommands = append(exportCommand.Subcommands, exportS3Commands)

	exportGCSCommands.Subcommands = append(exportGCSCommands.Subcommands, exportGeneralCommands...)
	exportCommand.Subcommands = append(exportCommand.Subcommands, exportGCSCommands)

	coonectivityRuleCommand := &cli.Command{
		Name:    "set-connectivity-rules",
		Usage:   "set the connectivity rules for a namespace",
		Aliases: []string{"scrs"},
		Flags: []cli.Flag{
			NamespaceFlag,
			connectivityRuleIdsFlag,
			&cli.BoolFlag{
				Name:  "remove-all",
				Usage: "Acknowledge that all connectivity rules will be removed, enabling connectivity from any source",
			},
		},
		Action: func(ctx *cli.Context) error {
			n, err := c.getNamespace(ctx.String(NamespaceFlagName))
			if err != nil {
				return err
			}
			connectivityRuleIds := ctx.StringSlice(connectivityRuleIdsFlagName)
			if len(connectivityRuleIds) == 0 && !ctx.Bool("remove-all") {
				return fmt.Errorf("connectivity rule ids must be provided or --remove-all must be used")
			}
			if ctx.Bool("remove-all") && len(connectivityRuleIds) > 0 {
				return fmt.Errorf("connectivity rule ids must not be provided when --remove-all is used")
			}
			if reflect.DeepEqual(n.Spec.ConnectivityRuleIds, connectivityRuleIds) {
				return fmt.Errorf("no connectivity rule changes to apply")
			}

			n.Spec.ConnectivityRuleIds = connectivityRuleIds
			return c.updateNamespace(ctx, n)
		},
	}

	subCommands = append(subCommands, exportCommand)

	subCommands = append(subCommands, coonectivityRuleCommand)

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

func disruptiveChange(old namespace.AuthMethod, new namespace.AuthMethod) bool {
	return old != namespace.AUTH_METHOD_RESTRICTED && new != namespace.AUTH_METHOD_API_KEY_OR_MTLS
}

// regionIDFromString parses a region string and returns a RegionID. It must be in the format "<provider>-<region>".
func regionIDFromString(region string) (*common.RegionID, error) {
	switch {
	case strings.HasPrefix(region, CloudProviderAWS+"-"):
		awsRegion := region[len(CloudProviderAWS)+1:]
		return &common.RegionID{
			Provider: common.CLOUD_PROVIDER_AWS,
			Name:     awsRegion,
		}, nil
	case strings.HasPrefix(region, CloudProviderGCP+"-"):
		gcpRegion := region[len(CloudProviderGCP)+1:]
		return &common.RegionID{
			Provider: common.CLOUD_PROVIDER_GCP,
			Name:     gcpRegion,
		}, nil
	default:
		return nil, fmt.Errorf("invalid region: %s", region)
	}
}

func toAuthMethod(m string) (namespace.AuthMethod, error) {
	switch m {
	case AuthMethodRestricted:
		return namespace.AUTH_METHOD_RESTRICTED, nil
	case AuthMethodAPIKey:
		return namespace.AUTH_METHOD_API_KEY, nil
	case AuthMethodMTLS:
		return namespace.AUTH_METHOD_MTLS, nil
	case AuthMethodAPIKeyOrMTLS:
		return namespace.AUTH_METHOD_API_KEY_OR_MTLS, nil
	default:
		return namespace.AUTH_METHOD_UNSPECIFIED, fmt.Errorf("invalid auth method: '%s'", m)
	}
}

func toString(m namespace.AuthMethod) string {
	switch m {
	case namespace.AUTH_METHOD_RESTRICTED:
		return AuthMethodRestricted
	case namespace.AUTH_METHOD_API_KEY:
		return AuthMethodAPIKey
	case namespace.AUTH_METHOD_MTLS:
		return AuthMethodMTLS
	case namespace.AUTH_METHOD_API_KEY_OR_MTLS:
		return AuthMethodAPIKeyOrMTLS
	default:
		return "unspecified"
	}
}
