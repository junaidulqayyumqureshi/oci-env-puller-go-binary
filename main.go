package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/example/helpers"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

func GetVaultByName(configProvider common.ConfigurationProvider, vaultName string, compartmentID string) (*keymanagement.VaultSummary, error) {
	// Create a KMS Vault client
	client, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS Vault client: %v", err)
	}

	// List all vaults in the specified compartment
	req := keymanagement.ListVaultsRequest{
		CompartmentId: common.String(compartmentID),
	}

	resp, err := client.ListVaults(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %v", err)
	}

	// Search for the vault by display name
	for _, vault := range resp.Items {
		if *vault.DisplayName == vaultName {
			return &vault, nil
		}
	}

	return nil, fmt.Errorf("vault with name '%s' not found in compartment '%s'", vaultName, compartmentID)
}

func CompartmentIDByName(configProvider common.ConfigurationProvider, compartmentName string) (string, error) {
	client, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
	if err != nil {
		return "", fmt.Errorf("failed to create Identity client: %v", err)
	}

	// Get the tenancy OCID from the configuration
	tenancyID, err := configProvider.TenancyOCID()
	if err != nil {
		return "", fmt.Errorf("failed to get tenancy OCID: %v", err)
	}

	// List all compartments in the tenancy
	req := identity.ListCompartmentsRequest{
		CompartmentId:          common.String(tenancyID),
		AccessLevel:            identity.ListCompartmentsAccessLevelAccessible,
		CompartmentIdInSubtree: common.Bool(true),
	}

	resp, err := client.ListCompartments(context.Background(), req)
	if err != nil {
		return "", fmt.Errorf("failed to list compartments: %v", err)
	}

	// Search for the compartment by name
	for _, compartment := range resp.Items {
		if *compartment.Name == compartmentName && compartment.LifecycleState == identity.CompartmentLifecycleStateActive {
			return *compartment.Id, nil
		}
	}

	return "", fmt.Errorf("compartment with name '%s' not found", compartmentName)
}

func GetSecretsFromVault(configProvider common.ConfigurationProvider, compartmentId string, vaultId string) error {
	listSecretsRequest := vault.ListSecretsRequest{
		CompartmentId: common.String(compartmentId), // Convert to *string
		VaultId:       common.String(vaultId),
	}

	vaultClient, err := vault.NewVaultsClientWithConfigurationProvider(configProvider)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %v", err)
	}

	secretsClient, err := secrets.NewSecretsClientWithConfigurationProvider(configProvider)
	if err != nil {
		return fmt.Errorf("failed to create Secrets client: %v", err)
	}

	listSecretsResponse, err := vaultClient.ListSecrets(context.Background(), listSecretsRequest)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %v", err)
	}

	// Iterate over each secret and fetch its value
	for _, secret := range listSecretsResponse.Items {
		// Fetch the secret bundle
		getSecretBundleRequest := secrets.GetSecretBundleRequest{
			SecretId: secret.Id,
		}

		getSecretBundleResponse, err := secretsClient.GetSecretBundle(context.Background(), getSecretBundleRequest)
		if err != nil {
			fmt.Printf("Error fetching content for secret %s: %v\n", *secret.SecretName, err)
			continue
		}

		// Decode the secret content
		secretContentBase64 := *getSecretBundleResponse.SecretBundleContent.(secrets.Base64SecretBundleContentDetails).Content
		secretContent, err := base64.StdEncoding.DecodeString(secretContentBase64)
		if err != nil {
			fmt.Printf("Error decoding content for secret %s: %v\n", *secret.SecretName, err)
			continue
		}

		// Sanitize and format the secret name
		sanitizedName := sanitizeSecretName(*secret.SecretName)
		escapedContent := escapeSecretContent(string(secretContent))

		// Print the secret as an exportable environment variable
		fmt.Printf("export %s=$'%s'\n", sanitizedName, escapedContent)
	}

	return nil
}

// sanitizeSecretName replaces invalid characters in a secret name with underscores.
func sanitizeSecretName(secretName string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return re.ReplaceAllString(secretName, "_")
}

// escapeSecretContent escapes newlines and single quotes in the secret content.
func escapeSecretContent(content string) string {
	content = strings.ReplaceAll(content, "\n", "\\n")
	return strings.ReplaceAll(content, "'", "\\'")
}

func main() {
	// Check if a profile argument is passed

	configProvider, err := auth.InstancePrincipalConfigurationProvider()
	helpers.FatalIfError(err)

	tenancyID := helpers.RootCompartmentID()

	fmt.Printf("\n")
	fmt.Printf("Successfully connected to OCI account using profile '%s'. Tenancy OCID: %s\n", tenancyID)
	fmt.Printf("\n")

	var compartmentName string
	for _, arg := range os.Args[1:] { // Start from os.Args[1] to skip the program name
		if strings.HasPrefix(arg, "compartmentName=") {
			compartmentName = strings.TrimPrefix(arg, "compartmentName=")
		}
	}

	compartmentID, err := CompartmentIDByName(configProvider, compartmentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving compartment ID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully retrieved Compartment ID for '%s': %s\n", compartmentName, compartmentID)
	fmt.Printf("\n")

	var vaultName string
	for _, arg := range os.Args[1:] { // Start from os.Args[1] to skip the program name
		if strings.HasPrefix(arg, "vaultName=") {
			vaultName = strings.TrimPrefix(arg, "vaultName=")
		}
	}

	vault, err := GetVaultByName(configProvider, vaultName, compartmentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving vault ID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully retrieved Vault ID for '%s': %s\n", vaultName, vault.Id)
	fmt.Printf("\n")

	err = GetSecretsFromVault(configProvider, compartmentID, *vault.Id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secrets: %v\n", err)
		os.Exit(1)
	}
}