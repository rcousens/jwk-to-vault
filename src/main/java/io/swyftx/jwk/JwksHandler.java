package io.swyftx.jwk;

import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.JWK;

import java.util.HashMap;
import java.util.Map;

/**
 * Handler for JWKS secret type operations
 */
public class JwksHandler {

    /**
     * Handles the JWKS secret type
     *
     * @param options The JWKS options
     */
    public static void handle(Options.JwksOptions options) {
        try {
            System.out.println("Generating key...");
            JWK jwk = KeyGenerator.makeKey(
                options.size,
                options.generator,
                options.keyUse,
                options.keyAlg
            );

            System.out.println("Displaying keys in JWK format...");
            KeyWriter.displayJWK(
                jwk,
                true,
                false,
                true
            );

            System.out.println("Displaying keys in PEM format...");
            KeyWriter.displayPEM(
                jwk,
                false,
                true
            );

            // Initialize Vault client and perform update secret operation for JWKS
            if (Strings.isNullOrEmpty(options.secretPath)) {
                System.out.println("Private key discarded as no Vault path was specified");
            } else {
                System.out.println("Attempting to store private key in Vault...");
                VaultClient vaultClient = new VaultClient();
                if (vaultClient.initialize()) {
                    Map<String, Object> secretData = new HashMap<>();
                    secretData.put("GEN2_BALANCE_SERVICE_PRIVATE_KEY", KeyWriter.privateKeyToString(jwk.toRSAKey().toPrivateKey()));
                    boolean success = vaultClient.writeSecret(options.secretPath, secretData);
                    if (success) {
                        System.out.println("Private key successfully stored in Vault at: " + options.secretPath);
                    } else {
                        System.err.println("Failed to store private key in Vault");
                    }
                } else {
                    System.err.println("Failed to initialize Vault client");
                }
            }
        } catch (NumberFormatException e) {
            throw Options.printUsageAndExit("Invalid key size: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw Options.printUsageAndExit(e.getMessage());
        } catch (Exception e) {
            throw Options.printUsageAndExit("Unexpected error: " + e.getMessage());
        }
    }
}
