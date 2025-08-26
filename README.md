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

# API Key Management

API Keys provide machine based authentication for Temporal Control Plane APIs. These keys are generated for and inherit the roles and permissions of the current user. API Keys are required to have a duration / expiry for preview within 1 to 90 days. We recommend to always set a duration / expiry for your API keys. This will allow you to rotate your API keys frequently and minimize the exposure of a token in case it is compromised.
### Creating an API Key:
*Make sure to copy the secret or else you will not be able to retrieve it again.*

Create an API key by running the following command (duration must be within 1 to 90 days):
```
tcld apikey create --name <api-key-name> --description <api-key-description> --duration <api-key-duration>
```
### List API Keys for the current user:
```
tcld apikey list
```

### List API keys for a specific owner (service account or user):
Note: only Global Admins may list API keys for other users/service accounts.
```
tcld apikey list --owner-id <owner-id>
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

#### Current User Specific Rotation
1. Generate the new API key to rotate to.
```
tcld apikey create --name <api-key-name> --description <api-key-description> --duration <api-key-duration>
```
2. Update temporal clients to use the new API key and monitor deployments to make sure all old API key usage is gone.
3. Delete the old API key.
```
tcld apikey delete --id <api-key-id>
```

#### Service Account Specific Rotation
1. Generate the new API key to rotate to.
```
tcld apikey create --name <api-key-name> --description <api-key-description> --duration <api-key-duration> --service-account-id <service-account-id>
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

# User Management
### List users:
```
tcld user list
```

### Get user information:
```
tcld user get -e <user-email>
```

### Invite users to your account:
To invite users to your account, you must specify the email and account role. Namespace permissions are optional. You can invite multiple emails at once. An invitation email will be sent to the emails specified. Users should accept the invitation from the email to confirm being added to the account.
```
tcld user invite -e <user-email> --ar <account-role> -p <namespace-1=namespace-permission> -p <namespace-2=namespace-permission>
```

### Reinvite users to your account:
If a user has been invited to your account but has not accepted the invite, you can reinvite them using the following command. This command will send a new invite email to the user. The previous email invitation link will become invalid.
```
tcld user resend-invite -e <user-email>
```

### Delete user from your account:
To delete a user from your account, run the following command. The user will be removed from your account and have all permissions revoked.
```
tcld user delete -e <user-email>
```

### Update user permissions:
Run the following command to update a user's account role. A user is only assigned one account role at a time. The admin role gives the user access to all namespaces.
```
tcld user set-account-role -e <user-email> --ar <account-role>
```
Run the following command to update a user's namespace permissions. This is a set operation, which requires assigning the full set of permissions each time. To get the current set of namespace permissions run the `tcld user get` command. Permissions not specified will be effectively removed. Do not run this command if the user is already an account admin, since they already have access to all namespaces.
```
# get list of current namespace permissions
tcld user get -e <user-email> | jq -r '.spec.namespacePermissions'

# set new user namespace permissions, make sure to include any permissions from the previous command
tcld user set-namespace-permissions -e <user-email> -p <namespace-1=namespace-permission> -p <namespace-2=namespace-permission>
```

# User Group Management

### List groups:
```
tcld user-group list
```

### Get group information:
```
tcld user-group get <group-id>
```

### Set group access:
```
tcld user-group set-access -id <group-id> --account-role read --namespace-role <namespace>-read
```

Setting the group access will replace all permissions for the given group. The account role can be one of:

- `owner` - Account owner, full access
- `admin` - Account admin, full access except to financial information
- `developer` - Account developer
- `financeadmin` - Only access to financial information
- `read` - Account read
- `none` - No account level access.

Note that if the account role is `owner` or `admin`, namespace role assignment is not available because the group will already have access to all namespaces.

The `--namespace-role` flag can be repeated for each namespace role the group should be assigned. The format of the role is: `<namespace>-<role>` with the namespace nominally being `<name>.<accountid>`. For example `mynamespace.cwl3n-read` would give read permission to the `mynamespace.cwl3n` namespace. The namespace role can be one of the following:

- `admin` - Full access to the namespace
- `write` - Read and write access to the namespace
- `read` - Read only access

The account and namespace roles replace the definition, so any namespace roles omitted will be removed from the group level access.

To add or remove namespace access without specifying all other roles, the `set-access` command also takes in a `--append`(`-a`), or `--remove`(`-r`) flag which will add the given namespace access or remove them. Appending will not change an existing namespace access(it will reject the update) and the account access cannot be changed when either flag is specified.

# Migration Management (Preview)

*The Migration feature is currently in "Preview Release". Customers must be invited to use this feature. Please reach out to Temporal Cloud support for more information.*

Migrations provide a way to migrate a namespace and its workflow between a self-hosted Temporal server and Temporal Cloud. Migrations rely on active/passive replication built-in to Temporal. Before starting a migration, deploy the [s2s-proxy](https://github.com/temporalio/s2s-proxy/) alongside your self-hosted cluster and obtain a migration endpoint id from Temporal Cloud support. Please reach out to Temporal Cloud support for more information.

### Start a migration

To start a migration, provide the migration endpoint id and the source and target namespace names.
Starting the migration enables active/passive namespace replication.

```
tcld migration start --endpoint-id <endpoint-id> --source-namespace <source-namespace> --target-namespace <target-namespace>
```

### Get a migration

```
tcld migration get --id <migration-id>
```

### Perform handover during a migration

To handover, provide the migration id and the replica id.
Handover changes the active replica to the given replica.
The active replica is the replica currently accepting write operations.

```
tcld migration handover --id <migration-id> --to-replica-id <to-replica-id>
```

### Confirm a migration

Confirming the migration completes the migration and disables replication.

```
tcld migration confirm --id <migration-id>
```

### Abort a migration

Aborting the migration cancels the migration and disables replication.

```
tcld migration abort --id <migration-id>
```

# Asynchronous Operations
Any update operations making changes to the namespaces or user groups hosted on Temporal Cloud are asynchronous. Such operations are tracked using a `request-id` that can be passed in when invoking the update operation or will be auto-generated by the server if one is not specified. Once an asynchronous request is initiated, a `request-id` is returned. Use the `request get` command to query the status of an asynchronous request.
```
tcld request get -r <request-id> -n <namespace>
```

# License

MIT License, please see [LICENSE](https://github.com/temporalio/tcld/blob/master/LICENSE) for details.

