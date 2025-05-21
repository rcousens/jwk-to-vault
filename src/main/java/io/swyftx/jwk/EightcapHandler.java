package io.swyftx.jwk;

import com.google.common.base.Strings;

import java.util.HashMap;
import java.util.Map;

/**
 * Handler for Eightcap secret type operations
 */
public class EightcapHandler {

    /**
     * Handles the Eightcap secret type
     *
     * @param options The Eightcap options
     */
    public static void handle(Options.EightcapOptions options) {
        System.out.println("Please enter the Eightcap credentials below. Note, these are masked input fields and entered text will not be visible on the screen.");
        char[] eightcapEntityIdChars = System.console().readPassword("Enter Eightcap Entity ID: ");
        String eightcapEntityId = new String(eightcapEntityIdChars);
        char[] eightcapUsernameChars = System.console().readPassword("Enter Eightcap Username: ");
        String eightcapUsername = new String(eightcapUsernameChars);
        char[] eightcapPasswordChars = System.console().readPassword("Enter Eightcap Password: ");
        String eightcapPassword = new String(eightcapPasswordChars);

        if (Strings.isNullOrEmpty(options.secretPath)) {
            System.out.println("Eightcap credentials discarded as no Vault path was specified");
        } else {
            System.out.println("Attempting to store Eightcap credentials in Vault...");
            VaultClient vaultClient = new VaultClient();
            if (vaultClient.initialize()) {
                Map<String, Object> secretData = new HashMap<>();
                secretData.put("EIGHTCAP_ENTITY_ID", eightcapEntityId);
                secretData.put("EIGHTCAP_USERNAME", eightcapUsername);
                secretData.put("EIGHTCAP_PASSWORD", eightcapPassword);
                boolean success = vaultClient.writeSecret(options.secretPath, secretData);
                if (success) {
                    System.out.println("Eightcap credentials successfully stored in Vault at: " + options.secretPath);
                } else {
                    System.err.println("Failed to store Eightcap credentials in Vault");
                }
            } else {
                System.err.println("Failed to initialize Vault client");
            }
        }
    }
}
