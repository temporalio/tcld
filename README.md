# tcld (`Beta`)
A cli tool for managing Temporal Cloud namespaces.

> This cli tool is currently in `beta` and access to Temporal Cloud via the cli is restricted. Please reach out to temporal-cloud support for more information.

# Installation
## Install via Homebrew
```
brew install temporalio/brew/tcld
```
## Build from source
1. Verify that you have Go 1.18+ installed. If `go` is not installed, follow instructions on [the Go website](https://golang.org/doc/install).
```
go version
```
2. Clone the `tcld` repository and run `make`.
```
git clone https://github.com/temporalio/tcld.git
cd tcld
make
```
3. Copy the tcld executable to any directory that appears in the PATH environment variable; for example, `/usr/local/bin/`.
```
cp tcld /usr/local/bin/tcld
```
4. Run `tcld version` to check if it worked.
```
tcld version
```

# Authentication and Login
### User login authentication:
In order to use the cli you must first login by running the following command:
```
tcld login
```
You will be sent a link to confirm your device code and login. After logging in, you are now authenticated and can make requests with this cli.

### API Key based authentication:
You can use API keys to authenticate with the cli by passing the `--api-key` flag or setting the `TEMPORAL_CLOUD_API_KEY` environment variable.
```
tcld --api-key <api-key> ...
```

```
export TEMPORAL_CLOUD_API_KEY=<api-key>
tcld ...
```

# API Key Management (Preview)
<em>The API Key feature is currently in "Preview Release". Customers must be invited to use this feature. Please reach out to Temporal Cloud support for more information.</em>

API Keys provide machine based authentication for Temporal Control Plane APIs. These keys are generated for and inherit the roles and permissions of the current user. API Keys are required to have a duration / expiry for preview with a max of 90 days and min of 1 day. We recommend to always set a duration / expiry for your API keys. This will allow you to rotate your API keys frequently and minimize the exposure of a token in case it is compromised.
### Creating an API Key:
<em>Make sure to copy the secret or else you will not be able to retrieve it again.</em>

Create an API key by running the following command:
```
tcld apikey create --name <api-key-name> --description <api-key-description> --duration <api-key-duration>
```
### List API Keys for the current user:
```
tcld apikey list
```
### Delete an API Key:
```
tcld apikey delete --id <api-key-id>
```

### Enable or Disable an API Key:
If you determine there is a need to temporarily disable API Key access but want to enable it in the future, run the following commands:
```
tcld apikey disable --id <api-key-id>
tcld apikey enable --id <api-key-id>
```

### Performing an API Key rotation:
1. Generate the new API key to rotate to.
```
tcld apikey create --name <api-key-name> --description <api-key-description> --duration <api-key-duration>
```
2. Update temporal clients to use the new API key and monitor deployments to make sure all old API key usage is gone.
3. Delete the old API key.
``` 
tcld apikey delete --id <api-key-id>
```

# Namespace Management

### List namespaces user has access to:
```
tcld namespace list
```

### Get namespace information:
```
tcld namespace get -n <namespace>
```

### Update the CA certificate:
```
tcld namespace accepted-client-ca set -n <namespace> --ca-certificate-file <ca-pem-filepath>
```
> :warning: If the update removes a certificate, any clients (tctl/workers) still using the removed certificate will fail to connect to the namespace after the update completes.

#### Performing a certificate rollover:
It is important to do a rollover process when updating your CA certificates. This allows your namespace to serve both CA certificates for a period of time until traffic to your old certificate is gone. To do this follow these steps:

1. Generate the new certificates.
2. Run the `accepted-client-ca add` command with the new CA certificates.
```
tcld namespace accepted-client-ca add -n <namespace> --ca-certificate-file <new-ca-pem-filepath>
```

3. Update temporal clients to use the new certificates and monitor deployments to make sure all old certificate usage is phased out.
4. Run the `accepted-client-ca remove` command to remove the old certificates.
```
tcld namespace accepted-client-ca remove -n <namespace> --ca-certificate-file <old-ca-pem-filepath>
```

Or use the fingerprint of the old ca certificate with the remove command.
```
tcld namespace accepted-client-ca remove -n <namespace> --ca-certificate-fingerprint <old-ca-fingerprint>
```

### Add new search attributes:
```
tcld namespace search-attributes add -n <namespace> --sa "<attribute-name>=<search-attribute-type>" --sa "<attribute-name>=<search-attribute-type>"
```
Supported search attribute types: `Keyword Text Int Double Datetime Bool`

### Rename existing search attribute:
```
tcld namespace search-attributes rename -n <namespace> --existing-name <existing-attribute-name> --new-name <new-attribute-name>
```
> :warning: Any workflows that are using the old search attribute name will fail after the update.

# Asynchronous Operations
Any update operations making changes to the namespaces hosted on Temporal Cloud are asynchronous. Such operations are tracked using a `request-id` that can be passed in when invoking the update operation or will be auto-generated by the server if one is not specified. Once an asynchronous request is initiated, a `request-id` is returned. Use the `request get` command to query the status of an asynchronous request.
```
tcld request get -r <request-id> -n <namespace>
```

# License

MIT License, please see [LICENSE](https://github.com/temporalio/tcld/blob/master/LICENSE) for details.

