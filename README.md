# To create the build

```
GO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/oci-env-linux-amd64 main.go
```

# To run this script:

```
go run main.go compartmentName=surepay-uat vaultName=surepay-uat-kms-vault-app
```

# Deploy

To deploy the latest binary, push binary to github repo: https://github.com/junaidulqayyumqureshi/oci-env-puller-go-binary/raw/main/dist/ folder and rebuild the docker image

# NOTE

This build will only run and tested on container instance as it is using "ResourcePrincipalConfigurationProvider" in main.go file

If intended to deploy this on other resources, research the OCI SDK documentaions on Principals. For example, to use this on OCI Instance (EC2):

InstancePrincipalConfigurationProvider
