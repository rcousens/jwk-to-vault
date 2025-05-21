package io.swyftx.jwk;

/**
 * Factory for creating and executing the appropriate handler
 */
public class HandlerFactory {

    /**
     * Creates and executes the appropriate handler for the given secret type
     *
     * @param secretType The type of secret
     * @param secretPath The path to store the secret
     */
    public static void executeHandler(String secretType, String secretPath) {
        Options.BaseOptions options = Options.createOptions(secretType, secretPath);

        switch (secretType) {
            case "jwks":
                JwksHandler.handle((Options.JwksOptions) options);
                break;
            case "eightcap":
                EightcapHandler.handle((Options.EightcapOptions) options);
                break;
            case "cosign":
                CosignHandler.handle((Options.CosignOptions) options);
                break;
            default:
                throw Options.printUsageAndExit("Unsupported secret type: " + secretType);
        }
    }
}
