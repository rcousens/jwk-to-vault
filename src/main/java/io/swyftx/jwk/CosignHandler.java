package io.swyftx.jwk;

import com.google.common.base.Strings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Handler for Cosign secret type operations
 */
public class CosignHandler {

    /**
     * Handles the Cosign secret type
     *
     * @param options The Cosign options
     */
    public static void handle(Options.CosignOptions options) {
        try {
            System.out.println("Generating cosign key pair...");

            // Set up environment with COSIGN_PASSWORD as empty string
            ProcessBuilder processBuilder = new ProcessBuilder("cosign", "generate-key-pair");
            Map<String, String> env = processBuilder.environment();
            env.put("COSIGN_PASSWORD", "");

            // Execute the cosign command
            Process process = processBuilder.start();
            int exitCode = process.waitFor();

            if (exitCode != 0) {
                throw new RuntimeException("Cosign command failed with exit code: " + exitCode);
            }

            System.out.println("Cosign key pair generated successfully");

            // Read the generated files into memory
            String privateKeyContent = new String(Files.readAllBytes(
                    Paths.get("cosign.key")), java.nio.charset.StandardCharsets.UTF_8);
            String publicKeyContent = new String(Files.readAllBytes(
                    Paths.get("cosign.pub")), java.nio.charset.StandardCharsets.UTF_8);

            // Display the public key to the terminal
            System.out.println("\nCosign Public Key:");
            System.out.println("------------------");
            System.out.println(publicKeyContent);
            System.out.println("------------------\n");

            // Delete the files from the filesystem
            Files.delete(Paths.get("cosign.key"));
            Files.delete(Paths.get("cosign.pub"));

            System.out.println("Cosign key files loaded into memory and removed from filesystem");

            // Store in Vault if path is provided
            if (Strings.isNullOrEmpty(options.secretPath)) {
                System.out.println("Cosign keys discarded as no Vault path was specified");
            } else {
                System.out.println("Attempting to store cosign keys in Vault...");
                VaultClient vaultClient = new VaultClient();
                if (vaultClient.initialize()) {
                    Map<String, Object> secretData = new HashMap<>();
                    secretData.put("privateKey", privateKeyContent);
                    secretData.put("password", "");
                    secretData.put("publicKey", publicKeyContent);
                    boolean success = vaultClient.writeSecret(options.secretPath, secretData);
                    if (success) {
                        System.out.println("Cosign keys successfully stored in Vault at: " + options.secretPath);
                    } else {
                        System.err.println("Failed to store cosign keys in Vault");
                    }
                } else {
                    System.err.println("Failed to initialize Vault client");
                }
            }
        } catch (IOException e) {
            throw Options.printUsageAndExit("Failed to read cosign key files: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw Options.printUsageAndExit("Cosign process was interrupted: " + e.getMessage());
        } catch (Exception e) {
            throw Options.printUsageAndExit("Unexpected error during cosign key generation: " + e.getMessage());
        }
    }
}
