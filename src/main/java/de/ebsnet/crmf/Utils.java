package de.ebsnet.crmf;

import java.security.SecureRandom;

public final class Utils {
  private static final char[] ALPHA_NUM_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
  private static final SecureRandom RNG = new SecureRandom();

  private static char[] randomPwd(final char[] alphabet, final int length) {
    final var pwd = new char[length];
    for (int i = 0; i < length; i++) {
      pwd[i] = alphabet[RNG.nextInt(alphabet.length)];
    }
    return pwd;
  }

  public static char[] randomPwd() {
    return randomPwd(ALPHA_NUM_ALPHABET, 32);
  }

  private Utils() {}
}
