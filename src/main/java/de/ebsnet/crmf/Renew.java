package de.ebsnet.crmf;

import de.ebsnet.crmf.data.CSRMetadata;
import de.ebsnet.crmf.data.Triple;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

// TODO: This does not work, yet

/**
 * This should generate a renewal CSR according to the SM-PKI but our SubCA does not accept those
 * yet.
 *
 * <p>If you have any ideas on how to properly implement this, PRs are very welcome.
 */
@Command(
    name = "renew",
    mixinStandardHelpOptions = true,
    description = "Generate a Request for Renewal")
public final class Renew extends BaseCommand implements Callable<Void> {
  // we initialize here to, in case we are testing from a main method inside this
  // class
  static {
    CSRGenerator.init();
  }

  private static final Logger LOG = Logger.getLogger(Renew.class.getSimpleName());
  private static final int MIN_CHAIN_LENGTH = 2;

  @Option(
      names = {"--previous-keypair"},
      required = true,
      description = "Path to one of the old Key Pairs, used to sign the renewal")
  private Path prevKeyPair;

  @Option(
      names = {"--previous-certificate"},
      required = true,
      description =
          "Path to the old certificate. This is used to sign the renewal and for metadata of the new certificates")
  private Path prevCertificate;

  @Option(
      names = {"--trust-chain"},
      //      required = true,
      description = "Path to the trust chain of the sub CA")
  private Path[] trustChain;

  @SuppressFBWarnings("DMI_HARDCODED_ABSOLUTE_FILENAME")
  public static void main(final String[] args)
      throws CRMFException,
          GeneralSecurityException,
          IOException,
          OperatorCreationException,
          CMSException,
          CMPException {
    final var basePath = Path.of("/home/me/work/tmp/renewal");
    final var renew = new Renew();
    renew.prevCertificate = basePath.resolve("EBSnet.EMT.MAK_Signature_539.pem");
    //        Path.of("/home/me/work/tmp/crmf-csr/keys/old/personalSignatureCertificate.pem");
    renew.trustChain = new Path[] {basePath.resolve("DARZ-Test.CA-SN4-2022.pem")};
    //      Path.of("/home/me/Dokumente/work/keys/old/DARZ-Test.CA-SN4-2022.pem");
    renew.prevKeyPair = basePath.resolve("9984533000003_sig.key");
    //      Path.of("/home/me/work/tmp/crmf-csr/keys/old/sig.key");
    renew.encPath = basePath.resolve("enc.key");
    //      Path.of("/home/me/work/tmp/crmf-csr/keys/new/enc.key");
    renew.sigPath = basePath.resolve("sig.key");
    //      Path.of("/home/me/work/tmp/crmf-csr/keys/new/sig.key");
    renew.tlsPath = basePath.resolve("tls.key");
    //      Path.of("/home/me/work/tmp/crmf-csr/keys/new/tls.key");
    renew.out = basePath.resolve("renew.pem");
    //      Path.of("/home/me/work/tmp/crmf-csr/csr4.pem");
    renew.call();
  }

  private static X509Certificate[] buildTrustChain(final X509Certificate[]... chains) {
    final var insertionOrderSet = new LinkedHashSet<X509Certificate>();
    for (final var chain : chains) {
      insertionOrderSet.addAll(List.of(chain));
    }
    return insertionOrderSet.toArray(new X509Certificate[0]);
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  public static boolean isCompleteTrustChain(final X509Certificate... chain) {
    if (chain.length < MIN_CHAIN_LENGTH) {
      return false;
    }
    for (int i = 0; i < chain.length - 1; i++) {
      if (!chain[i].getIssuerX500Principal().equals(chain[i + 1].getSubjectX500Principal())) {
        final var idx = i;
        LOG.warning(
            () ->
                chain[idx].getSubjectX500Principal()
                    + " is not signed by "
                    + chain[idx + 1].getSubjectX500Principal());
        return false;
      }
    }

    final var root = chain[chain.length - 1];
    final var endsWithRoot = root.getSubjectX500Principal().equals(root.getIssuerX500Principal());
    if (!endsWithRoot) {
      LOG.warning(
          () ->
              "Certificate chain does not end with root certificate. Ends with "
                  + root.getSubjectX500Principal());
      //      return false;
    }
    return true;
  }

  //  @SuppressWarnings("PMD.UseVarargs")
  //  private static <T> T[] concatArrays(final T[] array1, final T[] array2) {
  //    final T[] result = Arrays.copyOf(array1, array1.length + array2.length);
  //    System.arraycopy(array2, 0, result, array1.length, array2.length);
  //    return result;
  //  }

  @Override
  public Void call()
      throws GeneralSecurityException,
          IOException,
          CRMFException,
          OperatorCreationException,
          CMSException {
    final var prevKp = loadKeyPair(this.prevKeyPair);
    final var prevCerts = loadCertificateChain(this.prevCertificate);
    var buildChain = new X509Certificate[0];
    for (final var chain : this.trustChain) {
      buildChain = buildTrustChain(buildChain, loadCertificateChain(chain));
    }
    final var allCerts = buildTrustChain(prevCerts, buildChain);

    if (!isCompleteTrustChain(allCerts)) {
      LOG.warning("incomplete trust chain for signature certificate");
    }

    final var keyPairs =
        new Triple<>(
            loadKeyPair(this.encPath), loadKeyPair(this.sigPath), loadKeyPair(this.tlsPath));
    final var metadata = CSRMetadata.fromCertificate(prevCerts[0]);

    final var innerCSR = Initial.generateCertReqMessages(keyPairs, metadata);
    final var signed = CSRUtil.outerSignature(prevKp, allCerts, innerCSR);

    final var signedASN1 = signed.toASN1Structure();

    final var result = CSRUtil.asPKIMessage(signedASN1.getContent(), true);

    Files.write(this.out, result.getEncoded(), StandardOpenOption.CREATE_NEW);

    return null;
  }
}
