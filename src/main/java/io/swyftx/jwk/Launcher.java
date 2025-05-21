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

        try {
            CommandLine cmd = parseCommandLine(args);

            if (cmd.hasOption("h")) {
                throw printUsageAndExit("Vault JWKS Generator\n");
            }

            String secretTypeValue = validateSecretType(cmd.getOptionValue("s"));
            String secretPath = cmd.getOptionValue("p");

            switch (secretTypeValue) {
                case "jwks":
                    handleJwksSecretType(new JwksOptions(secretPath));
                    break;
                case "eightcap":
                    handleEightcapSecretType(new EightcapOptions(secretPath));
                    break;
                case "cosign":
                    handleCosignSecretType(new CosignOptions(secretPath));
                    break;
                default:
                    throw printUsageAndExit("Unsupported secret type: " + secretTypeValue);
            }

        } catch (ParseException e) {
            throw printUsageAndExit("Failed to parse arguments: " + e.getMessage());
        } catch (java.text.ParseException e) {
            throw printUsageAndExit("Could not parse existing KeySet: " + e.getMessage());
        }
    }

    private static CommandLine parseCommandLine(String[] args) throws ParseException {
        CommandLineParser parser = new DefaultParser();
        return parser.parse(options, args);
    }

    private static void handleJwksSecretType(JwksOptions options) {
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
            throw printUsageAndExit("Invalid key size: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw printUsageAndExit(e.getMessage());
        } catch (Exception e) {
            throw printUsageAndExit("Unexpected error: " + e.getMessage());
        }
    }

    private static void handleEightcapSecretType(EightcapOptions options) {
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

    private static void handleCosignSecretType(CosignOptions options) {
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
            throw printUsageAndExit("Failed to read cosign key files: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw printUsageAndExit("Cosign process was interrupted: " + e.getMessage());
        } catch (Exception e) {
            throw printUsageAndExit("Unexpected error during cosign key generation: " + e.getMessage());
        }
    }

    /**
     * Base class for all command line options
     */
    private static abstract class BaseOptions {
        protected final String secretPath;

        public BaseOptions(String secretPath) {
            this.secretPath = secretPath;
        }
    }

    /**
     * Options specific to JWKS secret type
     */
    private static class JwksOptions extends BaseOptions {
        final String size;
        final KeyIdGenerator generator;
        final KeyType keyType;
        final KeyUse keyUse;
        final Algorithm keyAlg;

        public JwksOptions(String secretPath) throws java.text.ParseException {
            super(secretPath);
            this.size = "2048";
            this.generator = KeyIdGenerator.get("sha256");
            this.keyType = KeyType.parse("RSA");
            this.keyUse = KeyUse.parse("sig");
            this.keyAlg = JWSAlgorithm.parse("RS256");
        }
    }

    /**
     * Options specific to Eightcap secret type
     */
    private static class EightcapOptions extends BaseOptions {
        public EightcapOptions(String secretPath) {
            super(secretPath);
        }
    }

    /**
     * Options specific to Cosign secret type
     */
    private static class CosignOptions extends BaseOptions {
        public CosignOptions(String secretPath) {
            super(secretPath);
        }
    }

    private static String validateSecretType(String parsedSecretType) {
        if (!secretType.contains(parsedSecretType)) {
            throw printUsageAndExit("Invalid secret type: " + (parsedSecretType == null ? "none supplied" : parsedSecretType));
        }
        return parsedSecretType;
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
