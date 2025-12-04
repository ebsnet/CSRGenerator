package de.ebsnet.crmf;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/* default */ final class SendRequestTest {
  private static final SecureRandom PRNG = new SecureRandom();

  private static byte[] randomData(final int size) {
    final var result = new byte[size];
    PRNG.nextBytes(result);
    return result;
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  /* default */ void testWritePem() throws IOException {
    final var testDir = Files.createTempDirectory("write_pem_test");
    try {
      final var data = randomData(4096);
      final var testFile = testDir.resolve("out.pem");
      SendRequest.writePem(testFile, data, "CERTIFICATE");

      final var lines = Files.readAllLines(testFile);
      Assertions.assertEquals(
          "-----BEGIN CERTIFICATE-----", lines.get(0), "starts with PEM prefix");
      Assertions.assertEquals(
          "-----END CERTIFICATE-----", lines.get(lines.size() - 1), "ends with PEM suffix");

      for (int idx = 1; idx < lines.size() - 1; idx++) {
        final var line = lines.get(idx);
        Assertions.assertTrue(line.length() <= 64, "lines are at most 64 chars long");
      }
    } finally {
      deleteDirectory(testDir);
    }
  }

  private static void deleteDirectory(final Path path) throws IOException {
    if (Files.isDirectory(path)) {
      Files.walkFileTree(
          path,
          new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs)
                throws IOException {
              Files.delete(file);
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(final Path dir, final IOException exc)
                throws IOException {
              if (exc == null) {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
              } else {
                throw exc;
              }
            }
          });
    } else {
      Files.deleteIfExists(path);
    }
  }
}
