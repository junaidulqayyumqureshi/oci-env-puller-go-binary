package main

import (
    "context"
    "fmt"
    "log"
    "io/ioutil"
	"os"
	"strings"
	"regexp"
	"encoding/base64"
	"encoding/json"

	"github.com/oracle/oci-go-sdk/v65/common"
    "github.com/oracle/oci-go-sdk/v65/common/auth"
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

	var activeSecrets []vault.SecretSummary
	for _, secret := range listSecretsResponse.Items {
		if secret.LifecycleState == vault.SecretSummaryLifecycleStateActive {
			activeSecrets = append(activeSecrets, secret)
		}
	}

	// Iterate over each secret and fetch its value
	for _, secret := range activeSecrets {
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

func getCompartmentID() (string, error) {
    // Retrieve the Resource Principal Session Token (RPST) or its path from the environment variable
    tokenOrPath := os.Getenv("OCI_RESOURCE_PRINCIPAL_RPST")
    if tokenOrPath == "" {
        return "", fmt.Errorf("OCI_RESOURCE_PRINCIPAL_RPST environment variable not set")
    }

    var token string

    // Check if the environment variable contains a path or the token itself
    if _, err := os.Stat(tokenOrPath); err == nil {
        // It's a valid file path; read the token from the file
        tokenBytes, err := ioutil.ReadFile(tokenOrPath)
        if err != nil {
            return "", fmt.Errorf("failed to read token file: %w", err)
        }
        token = string(tokenBytes)
    } else {
        // Assume it's the token itself
        token = tokenOrPath
    }

    // Clean up the token string
    token = strings.TrimSpace(token)

    // *** Print the token ***

    // Split the token into its three parts
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return "", fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
    }

    payloadSegment := parts[1]

    missingPadding := (4 - len(payloadSegment)%4) % 4
    payloadSegment += strings.Repeat("=", missingPadding)

    payloadBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
    if err != nil {
        return "", fmt.Errorf("failed to decode JWT payload: %w", err)
    }

    // Parse the JSON payload into a map
    var claims map[string]interface{}
    if err := json.Unmarshal(payloadBytes, &claims); err != nil {
        return "", fmt.Errorf("failed to unmarshal JWT payload: %w", err)
    }

    compartmentID, ok := claims["res_compartment"].(string)
    if !ok {
        return "", fmt.Errorf("res_compartment not found in token claims")
    }

    return compartmentID, nil
}

func main() {
	var configProvider common.ConfigurationProvider
	var compartmentID string
	var err error
	
    envCompartmentID := os.Getenv("COMPARTMENT_ID")
	if envCompartmentID != "" {
		// Use DefaultProvider if COMPARTMENT_ID is provided
		configProvider = common.DefaultConfigProvider()
		compartmentID = envCompartmentID
		// fmt.Println("Using DefaultConfigProvider and COMPARTMENT_ID from environment")
	} else {
		// Use ResourcePrincipalConfigurationProvider otherwise
		configProvider, err = auth.ResourcePrincipalConfigurationProvider()
		if err != nil {
			log.Fatalf("Error creating Resource Principal configuration: %v", err)
		}
		compartmentID, err = getCompartmentID()
		if err != nil {
			log.Fatalf("Failed to get compartment ID: %v", err)
		}
		// fmt.Println("Using ResourcePrincipalConfigurationProvider")
	}

	vaultName := os.Getenv("vaultName")
	if vaultName == "" {
		fmt.Println("Error: vaultName environment variable not set")
		os.Exit(1)
	}

	vault, err := GetVaultByName(configProvider, vaultName, compartmentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving vault ID: %v\n", err)
		os.Exit(1)
	}

	err = GetSecretsFromVault(configProvider, compartmentID, *vault.Id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secrets: %v\n", err)
		os.Exit(1)
	}
}