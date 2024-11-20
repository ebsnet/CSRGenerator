package de.ebsnet.crmf;

import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * {@link PKIHeader} for the bsiCertReqMsgs (BSI TR-03109) with OID {@code 0.4.0.127.0.7.4.1.1.1}.
 */
@SuppressWarnings("PMD.TooManyMethods")
final class BSIPKIHeader extends PKIHeader {
  private static final Logger LOG = Logger.getLogger(BSIPKIHeader.class.getName());
  public static final ASN1ObjectIdentifier OID_BSI_CERT_REQ_MSGS =
      new ASN1ObjectIdentifier("0.4.0.127.0.7.4.1.1.1");

  public BSIPKIHeader() {
    // this is more or less a noop
    super(PKIHeader.CMP_2000, PKIHeader.NULL_NAME, PKIHeader.NULL_NAME);
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return OID_BSI_CERT_REQ_MSGS;
  }

  @Override
  public ASN1Integer getPvno() {
    LOG.warning("called function `getPvno` from PKIHeader");
    return super.getPvno();
  }

  @Override
  public GeneralName getSender() {
    LOG.warning("called function `getSender` from PKIHeader");
    return super.getSender();
  }

  @Override
  public GeneralName getRecipient() {
    LOG.warning("called function `getRecipient` from PKIHeader");
    return super.getRecipient();
  }

  @Override
  public ASN1GeneralizedTime getMessageTime() {
    LOG.warning("called function `getMessageTime` from PKIHeader");
    return super.getMessageTime();
  }

  @Override
  public AlgorithmIdentifier getProtectionAlg() {
    LOG.warning("called function `getProtectionAlg` from PKIHeader");
    return super.getProtectionAlg();
  }

  @Override
  public ASN1OctetString getSenderKID() {
    LOG.warning("called function `getSenderKID` from PKIHeader");
    return super.getSenderKID();
  }

  @Override
  public ASN1OctetString getRecipKID() {
    LOG.warning("called function `getRecipKID` from PKIHeader");
    return super.getRecipKID();
  }

  @Override
  public ASN1OctetString getTransactionID() {
    LOG.warning("called function `getTransactionID` from PKIHeader");
    return super.getTransactionID();
  }

  @Override
  public ASN1OctetString getSenderNonce() {
    LOG.warning("called function `getSenderNonce` from PKIHeader");
    return super.getSenderNonce();
  }

  @Override
  public ASN1OctetString getRecipNonce() {
    LOG.warning("called function `getRecipNonce` from PKIHeader");
    return super.getRecipNonce();
  }

  @Override
  public PKIFreeText getFreeText() {
    LOG.warning("called function `getFreeText` from PKIHeader");
    return super.getFreeText();
  }

  @Override
  public InfoTypeAndValue[] getGeneralInfo() {
    LOG.warning("called function `getGeneralInfo` from PKIHeader");
    return super.getGeneralInfo();
  }
}
