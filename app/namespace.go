package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/temporalio/tcld/api/temporalcloudapi/namespace/v1"
	ns "github.com/temporalio/tcld/api/temporalcloudapi/namespace/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/namespaceservice/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/request/v1"
	"github.com/urfave/cli/v2"
)

const (
	caCertificateFlagName            = "ca-certificate"
	caCertificateFileFlagName        = "ca-certificate-file"
	caCertificateFingerprintFlagName = "ca-certificate-fingerprint"
)

var (
	caCertificateFlag = &cli.StringFlag{
		Name:    caCertificateFlagName,
		Usage:   "The base64 encoded ca certificate",
		Aliases: []string{"c"},
	}
	caCertificateFileFlag = &cli.PathFlag{
		Name:    caCertificateFileFlagName,
		Usage:   "The path to the ca pem file",
		Aliases: []string{"f"},
	}
	caCertificateFingerprintFlag = &cli.StringFlag{
		Name:    caCertificateFingerprintFlagName,
		Usage:   "The fingerprint of to the ca certificate",
		Aliases: []string{"fp"},
	}
)

type NamespaceClient struct {
	client namespaceservice.NamespaceServiceClient
	ctx    context.Context
}

type GetNamespaceClientFn func(ctx *cli.Context) (*NamespaceClient, error)

func GetNamespaceClient(ctx *cli.Context) (*NamespaceClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &NamespaceClient{
		client: namespaceservice.NewNamespaceServiceClient(conn),
		ctx:    ct,
	}, nil
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

func (c *NamespaceClient) getNamespace(namespace string) (*ns.Namespace, error) {
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

func (c *NamespaceClient) updateNamespace(
	ctx *cli.Context,
	n *ns.Namespace,
) (*request.RequestStatus, error) {
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

func (c *NamespaceClient) renameSearchAttribute(
	ctx *cli.Context,
	n *ns.Namespace,
	existingName string,
	newName string,
) (*request.RequestStatus, error) {
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

func (c *NamespaceClient) parseExistingCerts(ctx *cli.Context) (namespace *ns.Namespace, existing caCerts, err error) {
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

func readAndParseCACerts(ctx *cli.Context) (read caCerts, err error) {
	cert, err := readCACerts(ctx)
	if err != nil {
		return nil, err
	}
	return parseCertificates(cert)
}

func readCACerts(ctx *cli.Context) (string, error) {
	cert := ctx.String(caCertificateFlagName)
	if cert == "" {
		if ctx.Path(caCertificateFileFlagName) != "" {
			data, err := ioutil.ReadFile(ctx.Path(caCertificateFileFlagName))
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

func NewNamespaceCommand(
	getNamespaceClientFn GetNamespaceClientFn,
	getRequestClientFn GetRequestClientFn,
) (CommandOut, error) {

	var c *NamespaceClient
	var r *RequestClient
	return CommandOut{Command: &cli.Command{
		Name:    "namespace",
		Aliases: []string{"n"},
		Usage:   "Namespace operations",
		Before: func(ctx *cli.Context) error {
			var err error
			c, err = getNamespaceClientFn(ctx)
			if err != nil {
				return err
			}
			r, err = getRequestClientFn(ctx)
			return err
		},
		Subcommands: []*cli.Command{{
			Name:    "list",
			Usage:   "List all known namespaces",
			Aliases: []string{"l"},
			Flags:   []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				return c.listNamespaces()
			},
		}, {
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
		}, {
			Name:    "accepted-client-ca",
			Usage:   "Manage client ca certificate used to verify client connections",
			Aliases: []string{"ca"},
			Subcommands: []*cli.Command{{
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
			}, {
				Name:    "add",
				Aliases: []string{"a"},
				Usage:   "Add a new ca accepted client ca certificate",
				Flags: []cli.Flag{
					NamespaceFlag,
					RequestIDFlag,
					ResourceVersionFlag,
					caCertificateFlag,
					caCertificateFileFlag,
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
					status, err := c.updateNamespace(ctx, n)
					if err != nil {
						return err
					}
					return r.HandleRequestStatus(ctx, "add certificate", status)
				},
			}, {
				Name:    "remove",
				Aliases: []string{"r"},
				Usage:   "Remove existing certificates",
				Flags: []cli.Flag{
					NamespaceFlag,
					RequestIDFlag,
					ResourceVersionFlag,
					caCertificateFlag,
					caCertificateFileFlag,
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
					status, err := c.updateNamespace(ctx, n)
					if err != nil {
						return err
					}
					return r.HandleRequestStatus(ctx, "remove certificate", status)
				},
			}, {

				Name:    "set",
				Aliases: []string{"s"},
				Usage:   "Set the accepted client ca certificate",
				Flags: []cli.Flag{
					NamespaceFlag,
					RequestIDFlag,
					ResourceVersionFlag,
					caCertificateFlag,
					caCertificateFileFlag,
				},
				Action: func(ctx *cli.Context) error {
					cert, err := readCACerts(ctx)
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
					status, err := c.updateNamespace(ctx, n)
					if err != nil {
						return err
					}
					return r.HandleRequestStatus(ctx, "set certificates", status)
				},
			}},
		}, {
			Name:    "search-attributes",
			Usage:   "Manage search attributes used by namespace",
			Aliases: []string{"sa"},
			Subcommands: []*cli.Command{{
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
					csa, err := toSearchAttributes(ctx.StringSlice("search-attribute"))
					if err != nil {
						return err
					}
					n, err := c.getNamespace(ctx.String(NamespaceFlagName))
					if err != nil {
						return err
					}
					if n.Spec.SearchAttributes == nil {
						n.Spec.SearchAttributes = make(map[string]namespace.NamespaceSpec_SearchAttributeType)
					}
					for attrName, attrType := range csa {
						if _, ok := n.Spec.SearchAttributes[attrName]; ok {
							return fmt.Errorf("attribute with name '%s' already exists", attrName)
						} else {
							n.Spec.SearchAttributes[attrName] = attrType
						}
					}
					status, err := c.updateNamespace(ctx, n)
					if err != nil {
						return err
					}
					return r.HandleRequestStatus(ctx, "add search attribute", status)
				},
			}, {
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
					status, err := c.renameSearchAttribute(ctx, n, existingName, newName)
					if err != nil {
						return err
					}
					return r.HandleRequestStatus(ctx, "rename search attribute", status)
				},
			}},
		}},
	}}, nil
}

func getSearchAttributeTypes() []string {
	validTypes := []string{}
	for i := 1; i < len(ns.NamespaceSpec_SearchAttributeType_name); i++ {
		validTypes = append(validTypes, ns.NamespaceSpec_SearchAttributeType_name[int32(i)])
	}
	return validTypes
}

func toSearchAttributes(keyValues []string) (map[string]ns.NamespaceSpec_SearchAttributeType, error) {
	res := map[string]ns.NamespaceSpec_SearchAttributeType{}
	for _, kv := range keyValues {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid search attribute \"%s\" must be of format: \"name=type\"", kv)
		}

		val, ok := ns.NamespaceSpec_SearchAttributeType_value[parts[1]]
		if !ok {
			return nil, fmt.Errorf(
				"search attribute type \"%s\" does not exist, acceptable types are: %s",
				parts[1],
				getSearchAttributeTypes(),
			)
		}

		res[parts[0]] = ns.NamespaceSpec_SearchAttributeType(val)
	}
	return res, nil
}
