package app

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/temporalio/tcld/protogen/api/account/v1"
	"github.com/temporalio/tcld/protogen/api/accountservice/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

type AccountClient struct {
	client accountservice.AccountServiceClient
	ctx    context.Context
}

type regionInfo struct {
	CloudProviderRegion string
	CloudProvider       string
}

func NewAccountClient(ctx context.Context, conn *grpc.ClientConn) *AccountClient {
	return &AccountClient{
		client: accountservice.NewAccountServiceClient(conn),
		ctx:    ctx,
	}
}

type GetAccountClientFn func(ctx *cli.Context) (*AccountClient, error)

func GetAccountClient(ctx *cli.Context) (*AccountClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return NewAccountClient(ct, conn), nil
}

func (c *AccountClient) getAccount() (*account.Account, error) {
	res, err := c.client.GetAccount(c.ctx, &accountservice.GetAccountRequest{})
	if err != nil {
		return nil, err
	}

	if res.Account == nil || res.Account.GetSpec() == nil {
		// this should never happen, the server should return an error when the account is not found
		return nil, fmt.Errorf("invalid account returned by server")
	}

	return res.Account, nil
}

func (c *AccountClient) listRegions() ([]regionInfo, error) {
	resp, err := c.client.GetRegions(c.ctx, &accountservice.GetRegionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("unable to get regions: %w", err)
	}

	var regions []regionInfo
	for _, r := range resp.Regions {
		regions = append(regions, regionInfo{
			CloudProviderRegion: r.GetName(),
			CloudProvider:       r.GetCloudProvider(),
		})
	}

	sort.SliceStable(regions, func(i, j int) bool {
		if regions[i].CloudProvider < regions[j].CloudProvider {
			return true
		}

		return regions[i].CloudProviderRegion < regions[j].CloudProviderRegion
	})

	return regions, nil
}

func (c *AccountClient) updateAccount(ctx *cli.Context, a *account.Account) error {
	resourceVersion := a.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}

	res, err := c.client.UpdateAccount(c.ctx, &accountservice.UpdateAccountRequest{
		RequestId:       ctx.String(RequestIDFlagName),
		ResourceVersion: resourceVersion,
		Spec:            a.Spec,
	})
	if err != nil {
		return err
	}

	return PrintProto(res)
}

func (c *AccountClient) parseExistingMetricsCerts(ctx *cli.Context) (account *account.Account, existing caCerts, err error) {
	a, err := c.getAccount()
	if err != nil {
		return nil, nil, err
	}

	var existingCerts caCerts
	if a.GetSpec().GetMetrics() != nil && a.GetSpec().GetMetrics().GetAcceptedClientCa() != "" {
		existingCerts, err = parseCertificates(a.GetSpec().GetMetrics().GetAcceptedClientCa())
		if err != nil {
			return nil, nil, err
		}
	}

	return a, existingCerts, nil
}

func NewAccountCommand(getAccountClientFn GetAccountClientFn) (CommandOut, error) {
	var c *AccountClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "account",
			Aliases: []string{"a"},
			Usage:   "Account operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getAccountClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "get",
					Usage:   "Get account information",
					Aliases: []string{"g"},
					Action: func(ctx *cli.Context) error {
						n, err := c.getAccount()
						if err != nil {
							return err
						}
						return PrintProto(n)
					},
				},
				{
					Name:    "list-regions",
					Usage:   "Lists all regions where the account can provision namespaces",
					Aliases: []string{"l"},
					Action: func(ctx *cli.Context) error {
						regionInfos, err := c.listRegions()
						if err != nil {
							return err
						}
						return PrintObj(regionInfos)
					},
				},
				{
					Name:    "metrics",
					Usage:   "Configures the metrics endpoint for the Temporal Cloud Account",
					Aliases: []string{"m"},
					Subcommands: []*cli.Command{
						{
							Name:  "enable",
							Usage: "Enables the metrics endpoint. CA Certificates *must* be configured prior to enabling the endpoint",
							Action: func(ctx *cli.Context) error {
								a, err := c.getAccount()
								if err != nil {
									return err
								}

								if a.Spec.Metrics != nil && a.Spec.Metrics.Enabled {
									return errors.New("metrics endpoint is already enabled")
								}

								if a.Spec.Metrics == nil || a.Spec.Metrics.AcceptedClientCa == "" {
									return errors.New("metrics endpoint cannot be enabled until ca certificates have been configured")
								}

								a.Spec.Metrics.Enabled = true
								return c.updateAccount(ctx, a)
							},
						},
						{
							Name:  "disable",
							Usage: "Disables the metrics endpoint",
							Action: func(ctx *cli.Context) error {
								a, err := c.getAccount()
								if err != nil {
									return err
								}

								if a.Spec.Metrics == nil || !a.Spec.Metrics.Enabled {
									return errors.New("metrics endpoint is already disabled")
								}

								a.Spec.Metrics.Enabled = false
								return c.updateAccount(ctx, a)
							},
						},
						{
							Name:    "accepted-client-ca",
							Usage:   "Manages configuration of ca certificates for the external metrics endpoint",
							Aliases: []string{"ca"},
							Subcommands: []*cli.Command{
								{
									Name:    "add",
									Aliases: []string{"a"},
									Usage:   "Add a new ca accepted client ca certificate",
									Flags: []cli.Flag{
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

										a, existingCerts, err := c.parseExistingMetricsCerts(ctx)
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

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == bundle {
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}

										a.Spec.Metrics.AcceptedClientCa = bundle
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "remove",
									Aliases: []string{"r"},
									Usage:   "Remove existing certificates",
									Flags: []cli.Flag{
										RequestIDFlag,
										ResourceVersionFlag,
										CaCertificateFlag,
										CaCertificateFileFlag,
										caCertificateFingerprintFlag,
									},
									Action: func(ctx *cli.Context) error {
										a, existingCerts, err := c.parseExistingMetricsCerts(ctx)
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

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == bundle {
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}

										a.Spec.Metrics.AcceptedClientCa = bundle
										y, err := ConfirmPrompt(ctx, "removing ca certificates can cause connectivity disruption if there are any clients using certificates that cannot be verified. confirm remove?")
										if err != nil || !y {
											return err
										}
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "set",
									Aliases: []string{"s"},
									Usage:   "Set the accepted client ca certificate",
									Flags: []cli.Flag{
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

										a, err := c.getAccount()
										if err != nil {
											return err
										}

										fmt.Println("2: " + a.Spec.Metrics.AcceptedClientCa)

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == cert {
											fmt.Printf("%+v vs %+v\r\n", cert, a.Spec.Metrics.AcceptedClientCa)
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}
										a.Spec.Metrics.AcceptedClientCa = cert
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "list",
									Aliases: []string{"l"},
									Usage:   "List the accepted client ca certificates currently configured for the account metrics endpoint",
									Action: func(ctx *cli.Context) error {
										a, err := c.getAccount()
										if err != nil {
											return err
										}

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa != "" {
											out, err := parseCertificates(a.Spec.Metrics.AcceptedClientCa)
											if err != nil {
												return err
											}
											return PrintObj(out)
										}

										return PrintObj("no client ca certificates configured for metrics endpoint")
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}
