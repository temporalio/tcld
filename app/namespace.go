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
	"github.com/urfave/cli/v2"
)

const (
	caCertificateFlagName     = "ca-certificate"
	caCertificateFileFlagName = "ca-certificate-file"
)

var (
	caCertificateFlag = &cli.StringFlag{
		Name:    caCertificateFlagName,
		Usage:   "the base64 encoded ca certificate",
		Aliases: []string{"c"},
	}
	caCertificateFileFlag = &cli.PathFlag{
		Name:    caCertificateFileFlagName,
		Usage:   "the path to the ca pem file",
		Aliases: []string{"f"},
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

func (c *NamespaceClient) updateNamespace(ctx *cli.Context, n *ns.Namespace) error {
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

func (c *NamespaceClient) renameSearchAttribute(ctx *cli.Context, n *ns.Namespace, existingName string, newName string) error {
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

func NewNamespaceCommand(getNamespaceClientFn GetNamespaceClientFn) (CommandOut, error) {

	var c *NamespaceClient
	return CommandOut{Command: &cli.Command{
		Name:    "namespace",
		Aliases: []string{"n"},
		Usage:   "namespace operations",
		Before: func(ctx *cli.Context) error {
			var err error
			c, err = getNamespaceClientFn(ctx)
			return err
		},
		Subcommands: []*cli.Command{{
			Name:    "list",
			Usage:   "list all known namespaces",
			Aliases: []string{"l"},
			Flags:   []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				return c.listNamespaces()
			},
		}, {
			Name:    "get",
			Usage:   "get namespace information",
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
			Usage:   "manage client ca certificate used to verify client connections",
			Aliases: []string{"ca"},
			Subcommands: []*cli.Command{{
				Name:  "get",
				Usage: "get the accepted client ca certificates currently configured for the namespace",
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
				Usage:   "add a new ca accepted client ca certificate",
				Aliases: []string{"a"},
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
					newCerts, err := parseCertificates(cert)
					if err != nil {
						return err
					}
					n, err := c.getNamespace(ctx.String(NamespaceFlagName))
					if err != nil {
						return err
					}
					existingCerts, err := parseCertificates(n.Spec.AcceptedClientCa)
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
			}, {
				Name:    "remove",
				Usage:   "remove existing certificates",
				Aliases: []string{"r"},
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
					inCerts, err := parseCertificates(cert)
					if err != nil {
						return err
					}
					n, err := c.getNamespace(ctx.String(NamespaceFlagName))
					if err != nil {
						return err
					}
					existingCerts, err := parseCertificates(n.Spec.AcceptedClientCa)
					if err != nil {
						return err
					}
					certs, err := removeCerts(existingCerts, inCerts)
					if err != nil {
						return err
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
			}, {

				Name:  "set",
				Usage: "set the accepted client ca certificate",
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
					return c.updateNamespace(ctx, n)
				},
			}},
		}, {
			Name:    "search-attributes",
			Usage:   "manage search attributes used by namespace",
			Aliases: []string{"sa"},
			Subcommands: []*cli.Command{{
				Name:    "add",
				Usage:   "add a new namespace custom search attribute",
				Aliases: []string{"a"},
				Flags: []cli.Flag{
					NamespaceFlag,
					RequestIDFlag,
					ResourceVersionFlag,
					&cli.StringSliceFlag{
						Name:     "search-attribute",
						Usage:    fmt.Sprintf("flag can be used multiple times; value must be \"name=type\"; valid types are: %v", getSearchAttributeTypes()),
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
					return c.updateNamespace(ctx, n)
				},
			}, {
				Name:    "rename",
				Usage:   "update the name of an existing custom search attribute",
				Aliases: []string{"rn"},
				Flags: []cli.Flag{
					NamespaceFlag,
					RequestIDFlag,
					ResourceVersionFlag,
					&cli.StringFlag{
						Name:     "existing-name",
						Usage:    "the name of an existing search attribute",
						Aliases:  []string{"en"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "new-name",
						Usage:    "the new name for the search attribute",
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
