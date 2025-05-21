package io.swyftx.jwk;

// Standard Java IO
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

// Standard Java Security & Crypto
import java.security.Security;

// Standard Java Collections
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Apache Commons CLI
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;

import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

// BouncyCastle
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Google Guava
import com.google.common.collect.ImmutableList;

// Nimbus JOSE+JWT
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;

import com.google.common.base.Strings;

/**
 * Small Helper App to generate Json Web Keys
 */
public class Launcher {

    private static Options options;
    private static final List<String> secretType = ImmutableList.of(
        "eightcap",
        "jwks",
        "cosign"
    );

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        options = new Options();
        configureCommandLineOptions(options);

        CommandLineOptions parsedOptions = null;

        try {
            parsedOptions = parseCommandLineOptions(args);
        } catch (ParseException e) {
            throw printUsageAndExit("Failed to parse arguments: " + e.getMessage());
        } catch (java.text.ParseException e) {
            throw printUsageAndExit("Could not parse existing KeySet: " + e.getMessage());
        }

        if (parsedOptions.secretType.equals("jwks")) {
            try {
                System.out.println("Generating key...");
                JWK jwk = KeyGenerator.makeKey(
                    parsedOptions.size,
                    parsedOptions.generator,
                    parsedOptions.keyUse,
                    parsedOptions.keyAlg
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
                if (Strings.isNullOrEmpty(parsedOptions.secretPath)) {
                    System.out.println("Private key discarded as no Vault path was specified");
                } else {
                    System.out.println("Storing private key in Vault...");
                    VaultClient vaultClient = new VaultClient();
                    if (vaultClient.initialize()) {
                        Map<String, Object> secretData = new HashMap<>();
                        secretData.put("GEN2_BALANCE_SERVICE_PRIVATE_KEY", KeyWriter.privateKeyToString(jwk.toRSAKey().toPrivateKey()));
                        vaultClient.writeSecret(parsedOptions.secretPath, secretData);
                    }
                }


            } catch (NumberFormatException e) {
                throw printUsageAndExit("Invalid key size: " + e.getMessage());
            } catch (IllegalArgumentException e) {
                throw printUsageAndExit(e.getMessage());
            } catch (Exception e) {
                throw printUsageAndExit("Unexpected error: " + e.getMessage());
            }
        }

        if (parsedOptions.secretType.equals("eightcap")) {
            System.out.println("Please enter the Eightcap credentials below. Note, these are masked input fields and entered text will not be visible on the screen.");
            char[] eightcapEntityIdChars = System.console().readPassword("Enter Eightcap Entity ID: ");
            String eightcapEntityId = new String(eightcapEntityIdChars);
            char[] eightcapUsernameChars = System.console().readPassword("Enter Eightcap Username: ");
            String eightcapUsername = new String(eightcapUsernameChars);
            char[] eightcapPasswordChars = System.console().readPassword("Enter Eightcap Password: ");
            String eightcapPassword = new String(eightcapPasswordChars);

            if (Strings.isNullOrEmpty(parsedOptions.secretPath)) {
                System.out.println("Private key discarded as no Vault path was specified");
            } else {
                System.out.println("Storing private key in Vault...");
                VaultClient vaultClient = new VaultClient();
                if (vaultClient.initialize()) {
                    Map<String, Object> secretData = new HashMap<>();
                    secretData.put("EIGHTCAP_ENTITY_ID", eightcapEntityId);
                    secretData.put("EIGHTCAP_USERNAME", eightcapUsername);
                    secretData.put("EIGHTCAP_PASSWORD", eightcapPassword);
                    vaultClient.writeSecret(parsedOptions.secretPath, secretData);
                }
            }
        }

        if (parsedOptions.secretType.equals("cosign")) {
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
                String privateKeyContent = new String(java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get("cosign.key")), java.nio.charset.StandardCharsets.UTF_8);
                String publicKeyContent = new String(java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get("cosign.pub")), java.nio.charset.StandardCharsets.UTF_8);

                // Delete the files from the filesystem
                java.nio.file.Files.delete(java.nio.file.Paths.get("cosign.key"));
                java.nio.file.Files.delete(java.nio.file.Paths.get("cosign.pub"));

                System.out.println("Cosign key files loaded into memory and removed from filesystem");

                // Store in Vault if path is provided
                if (Strings.isNullOrEmpty(parsedOptions.secretPath)) {
                    System.out.println("Cosign keys discarded as no Vault path was specified");
                } else {
                    System.out.println("Storing cosign keys in Vault...");
                    VaultClient vaultClient = new VaultClient();
                    if (vaultClient.initialize()) {
                        Map<String, Object> secretData = new HashMap<>();
                        secretData.put("privateKey", privateKeyContent);
                        secretData.put("password", "");
                        secretData.put("publicKey", publicKeyContent);
                        vaultClient.writeSecret(parsedOptions.secretPath, secretData);
                        System.out.println("Cosign keys successfully stored in Vault at: " + parsedOptions.secretPath);
                    }
                }

            } catch (IOException e) {
                throw printUsageAndExit("Failed to read cosign key files: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw printUsageAndExit("Cosign process was interrupted: " + e.getMessage());
            } catch (Exception e) {
                throw printUsageAndExit("Unexpected error during cosign key generation: " + e.getMessage());
            }
        }
    }

    /**
     * Parse command line arguments
     *
     * @param args Command line arguments
     * @return Parsed command line options
     * @throws ParseException           If parsing fails
     * @throws java.text.ParseException If key usage parsing fails
     */
    private static CommandLineOptions parseCommandLineOptions(String[] args) throws ParseException, java.text.ParseException {
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        CommandLineOptions result = new CommandLineOptions();

        if (cmd.hasOption("h")) {
            throw printUsageAndExit("Vault JWKS Generator\n");
        }

        result.secretType = validateSecretType(cmd.getOptionValue("s"));
        result.size = "2048";
        result.secretPath = cmd.getOptionValue("p");
        result.generator = KeyIdGenerator.get("sha256");
        result.keyType = KeyType.parse("RSA");
        result.keyUse = KeyUse.parse("sig");
        result.keyAlg = JWSAlgorithm.parse("RS256");
        return result;
    }

    private static String validateSecretType(String parsedSecretType) {
        if (!secretType.contains(parsedSecretType)) {
            throw printUsageAndExit("Invalid secret type: " + (parsedSecretType == null ? "none supplied" : parsedSecretType));
        }
        return parsedSecretType;
    }

    /**
     * Class to hold parsed command line options
     */
    private static class CommandLineOptions {
        String size;
        String secretPath;
        String secretType;
        KeyIdGenerator generator;
        KeyType keyType;
        KeyUse keyUse;
        Algorithm keyAlg;
    }

    /**
     * @param options Options to configure
     */
    private static void configureCommandLineOptions(Options options) {
        options.addOption("h", "help", false, "Print this help message");
        options.addOption("p", "path", true, "Vault path to write secret to, if not supplied no vault secret will be written");
        options.addOption("s", "secret", true, "Secret type to update. Can be one of: " + String.join(", ", secretType));
    }

    // print out a usage message and quit
    // return exception so that we can "throw" this for control flow analysis
    private static IllegalArgumentException printUsageAndExit(String message) {
        if (message != null) {
            System.err.println(message);
        }

        List<String> optionOrder = ImmutableList.of("p", "h", "s");

        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(120);
        formatter.setOptionComparator(Comparator.comparingInt(o -> optionOrder.indexOf(o.getOpt())));
        formatter.printHelp("java -jar jwk-to-vault.jar -s [secretType] [options]", options);

        // kill the program
        System.exit(1);
        return new IllegalArgumentException("Program was called with invalid arguments");
    }
}
