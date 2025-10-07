package de.ebsnet.crmf;

import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Entrypoint. */
@Command(
    name = "EBSnet CSRGenerator",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description = "Create SM PKI Compatible CSRs",
    // TODO: enable subcommands once they work
    subcommands = {
      Initial.class,
      PEM2PKCS12.class,
      Renew.class,
      SendRequest.class,
    })
@SuppressWarnings("PMD.UseUtilityClass")
public final class CSRGenerator {
  private static final AtomicBoolean IS_INIT = new AtomicBoolean(false);

  static {
    init();
  }

  /**
   * Entrypoint
   *
   * @param args
   */
  public static void main(final String[] args) {
    // final var new_args =
    // new String[] {
    // "renew",
    // "--encryption",
    // "/tmp/csr_test/enc.pem",
    // "--signature",
    // "/tmp/csr_test/sig.pem",
    // "--tls",
    // "/tmp/csr_test/tls.pem",
    // "--previous-certificate",
    // "/tmp/csr_test/enc_cert.pem",
    // "--previous-keypair",
    // "/tmp/csr_test/enc_key.pem",
    // "--out",
    // "/tmp/csr_test/out.pem"
    // };
    System.exit(new CommandLine(new CSRGenerator()).execute(args));
    // System.exit(new CommandLine(new CSRGenerator()).execute(new_args));
  }

  /**
   * Initialize JDK settings and security providers to enable Brainpool support, which has been
   * removed from the JDK.
   */
  public static void init() {
    // make sure this is only called once
    if (IS_INIT.compareAndSet(false, true)) {
      System.setProperty(
          "jdk.tls.namedGroups",
          "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, brainpoolP256r1tls13, brainpoolP384r1tls13, brainpoolP512r1tls13");

      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
      Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
      Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
    }
  }
}
