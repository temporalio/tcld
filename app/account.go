package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/temporalio/tcld/protogen/api/account/v1"
	"github.com/temporalio/tcld/protogen/api/accountservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

type AccountClient struct {
	client accountservice.AccountServiceClient
	ctx    context.Context
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

func (c *AccountClient) updateAccount(ctx *cli.Context, a *account.Account) (*request.RequestStatus, error) {
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
		return nil, err
	}
	return res.RequestStatus, nil
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

func NewAccountCommand(getAccountClientFn GetAccountClientFn, getRequestClientFn GetRequestClientFn) (CommandOut, error) {
	var c *AccountClient
	var r *RequestClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "account",
			Aliases: []string{"a"},
			Usage:   "Account operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getAccountClientFn(ctx)
				if err != nil {
					return err
				}
				r, err = getRequestClientFn(ctx)
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
					Name:    "metrics",
					Usage:   "Configures the metrics endpoint for the Temporal Cloud Account",
					Aliases: []string{"m"},
					Subcommands: []*cli.Command{
						{
							Name:  "enable",
							Usage: "Enables the metrics endpoint. CA Certificates *must* be configured prior to enabling the endpoint",
							Flags: []cli.Flag{
								RequestTimeoutFlag,
								WaitForRequestFlag,
							},
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
								status, err := c.updateAccount(ctx, a)
								if err != nil {
									return err
								}
								return r.HandleRequestStatus(ctx, "enable metrics", status)
							},
						},
						{
							Name:  "disable",
							Usage: "Disables the metrics endpoint",
							Flags: []cli.Flag{
								RequestTimeoutFlag,
								WaitForRequestFlag,
							},
							Action: func(ctx *cli.Context) error {
								a, err := c.getAccount()
								if err != nil {
									return err
								}

								if a.Spec.Metrics == nil || !a.Spec.Metrics.Enabled {
									return errors.New("metrics endpoint is already disabled")
								}

								a.Spec.Metrics.Enabled = false
								status, err := c.updateAccount(ctx, a)
								if err != nil {
									return err
								}
								return r.HandleRequestStatus(ctx, "disable metrics", status)

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
										RequestTimeoutFlag,
										WaitForRequestFlag,
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
										status, err := c.updateAccount(ctx, a)
										if err != nil {
											return err
										}
										return r.HandleRequestStatus(ctx, "add metrics ca certificate", status)
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
										RequestTimeoutFlag,
										WaitForRequestFlag,
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
										status, err := c.updateAccount(ctx, a)
										if err != nil {
											return err
										}
										return r.HandleRequestStatus(ctx, "remove metrics ca certificate", status)
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
										RequestTimeoutFlag,
										WaitForRequestFlag,
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
										status, err := c.updateAccount(ctx, a)
										if err != nil {
											return err
										}
										return r.HandleRequestStatus(ctx, "set metrics ca certificates", status)
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
