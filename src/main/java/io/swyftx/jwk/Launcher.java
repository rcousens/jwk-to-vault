package io.swyftx.jwk;

// Standard Java Security & Crypto
import java.security.Security;

// Apache Commons CLI
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

// BouncyCastle
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Small Helper App to generate Json Web Keys
 */
public class Launcher {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            CommandLine cmd = Options.parseCommandLine(args);

            if (cmd.hasOption("h")) {
                throw Options.printUsageAndExit("Vault JWKS Generator\n");
            }

            String secretTypeValue = Options.validateSecretType(cmd.getOptionValue("s"));
            String secretPath = cmd.getOptionValue("p");

            // Use the handler factory to execute the appropriate handler
            HandlerFactory.executeHandler(secretTypeValue, secretPath);

        } catch (ParseException e) {
            throw Options.printUsageAndExit("Failed to parse arguments: " + e.getMessage());
        }
    }
}
