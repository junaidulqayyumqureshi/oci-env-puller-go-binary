# To create the build

```
GO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/oci-env-linux-amd64 main.go
```

# To run this script locally:

```
vaultName=env-webhooks COMPARTMENT_ID=ocid1.compartment.oc1..aaaaaaaazek374nbkphajmosas6cju63yqvurjc34z355ld4j7uuoiita2cq go run main.go
```

Note that you need to pass COMPARTMENT_ID for it to work locally, this COMPARTMENT_ID is of surepay-uat compartment

# Deploy

To deploy the latest binary, push binary to github repo: https://github.com/junaidulqayyumqureshi/oci-env-puller-go-binary/raw/main/dist/ folder and rebuild the docker image
