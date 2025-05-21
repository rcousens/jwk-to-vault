package io.swyftx.jwk;

import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;

import java.util.Comparator;
import java.util.List;

/**
 * Handles command line options for the JWK to Vault application
 */
public class Options {
    private static final org.apache.commons.cli.Options options = new org.apache.commons.cli.Options();
    private static final List<String> SECRET_TYPES = ImmutableList.of(
        "eightcap",
        "jwks",
        "cosign"
    );

    private static final List<String> OPTION_ORDER = ImmutableList.of("p", "h", "s");

    static {
        configureCommandLineOptions();
    }

    /**
     * Configures the command line options
     */
    private static void configureCommandLineOptions() {
        options.addOption("h", "help", false, "Print this help message");
        options.addOption("p", "path", true, "Vault path to write secret to, if not supplied no vault secret will be written");
        options.addOption("s", "secret", true, "Secret type to update. Can be one of: " + String.join(", ", SECRET_TYPES));
    }

    /**
     * Parses the command line arguments
     *
     * @param args Command line arguments
     * @return Parsed command line
     * @throws ParseException If parsing fails
     */
    public static CommandLine parseCommandLine(String[] args) throws ParseException {
        CommandLineParser parser = new DefaultParser();
        return parser.parse(options, args);
    }

    /**
     * Validates the secret type
     *
     * @param parsedSecretType The secret type to validate
     * @return The validated secret type
     * @throws IllegalArgumentException If the secret type is invalid
     */
    public static String validateSecretType(String parsedSecretType) {
        if (!SECRET_TYPES.contains(parsedSecretType)) {
            throw printUsageAndExit("Invalid secret type: " + (parsedSecretType == null ? "none supplied" : parsedSecretType));
        }
        return parsedSecretType;
    }

    /**
     * Prints usage information and exits the program
     *
     * @param message The error message to display
     * @return An exception for control flow
     */
    public static IllegalArgumentException printUsageAndExit(String message) {
        if (message != null) {
            System.err.println(message);
        }

        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(120);
        formatter.setOptionComparator(Comparator.comparingInt(o -> OPTION_ORDER.indexOf(o.getOpt())));
        formatter.printHelp("java -jar jwk-to-vault.jar -s [secretType] [options]", options);

        // kill the program
        System.exit(1);
        return new IllegalArgumentException("Program was called with invalid arguments");
    }

    /**
     * Base class for all command line options
     */
    public static abstract class BaseOptions {
        protected final String secretPath;

        public BaseOptions(String secretPath) {
            this.secretPath = secretPath;
        }
    }

    /**
     * Options specific to JWKS secret type
     */
    public static class JwksOptions extends BaseOptions {
        public final String size;
        public final KeyIdGenerator generator;
        public final KeyType keyType;
        public final KeyUse keyUse;
        public final Algorithm keyAlg;

        public JwksOptions(String secretPath) {
            super(secretPath);
            this.size = "2048";
            this.generator = KeyIdGenerator.get("sha256");

            try {
                this.keyType = KeyType.parse("RSA");
                this.keyUse = KeyUse.parse("sig");
                this.keyAlg = JWSAlgorithm.parse("RS256");
            } catch (java.text.ParseException e) {
                throw printUsageAndExit("Could not parse key parameters: " + e.getMessage());
            }
        }
    }

    /**
     * Options specific to Eightcap secret type
     */
    public static class EightcapOptions extends BaseOptions {
        public EightcapOptions(String secretPath) {
            super(secretPath);
        }
    }

    /**
     * Options specific to Cosign secret type
     */
    public static class CosignOptions extends BaseOptions {
        public CosignOptions(String secretPath) {
            super(secretPath);
        }
    }

    public static BaseOptions createOptions(String secretType, String secretPath) {
        switch (secretType) {
            case "jwks":
                return new JwksOptions(secretPath);
            case "eightcap":
                return new EightcapOptions(secretPath);
            case "cosign":
                return new CosignOptions(secretPath);
            default:
                throw printUsageAndExit("Unsupported secret type: " + secretType);
        }
    }
}
