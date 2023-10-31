package net.pincette.jwt;

import static net.pincette.jwt.BitSize.BIT256;
import static net.pincette.jwt.Util.privateKey;
import static net.pincette.util.Util.must;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

/**
 * Signs JTWs using the Auth0 library. It selects the algorithm based on the given private key.
 *
 * @author Werner Donné
 */
public class Signer {
  private final Algorithm algorithm;

  /**
   * Creates a JWT signer with a private key in PEM format. Only RSA and ECDSA are supported. The
   * bit size is 256.
   *
   * @param privateKey the given private key of type RSA or ECDSA.
   */
  public Signer(final String privateKey) {
    this(privateKey(privateKey));
  }

  /**
   * Creates a JWT signer with a private key. Only RSA and ECDSA are supported. The bit size is 256.
   *
   * @param privateKey the given private key of type RSA or ECDSA.
   */
  public Signer(final PrivateKey privateKey) {
    this(privateKey, BIT256);
  }

  /**
   * Creates a JWT signer with a private key in PEM format. Only RSA and ECDSA are supported.
   *
   * @param privateKey the given private key of type RSA or ECDSA.
   * @param bits the bit size the algorithm should use.
   */
  public Signer(final String privateKey, final BitSize bits) {
    this(privateKey(privateKey), bits);
  }

  /**
   * Creates a JWT signer with a private key. Only RSA and ECDSA are supported.
   *
   * @param privateKey the given private key of type RSA or ECDSA.
   * @param bits the bit size the algorithm should use.
   */
  public Signer(final PrivateKey privateKey, final BitSize bits) {
    algorithm = algorithm(privateKey, bits);
  }

  private static Algorithm algorithm(final PrivateKey key, final BitSize bits) {
    must(key instanceof RSAKey || key instanceof ECKey);

    return key instanceof RSAKey k
        ? bits.rsaAlgorithm.apply(k)
        : bits.ecAlgorithm.apply((ECKey) key);
  }

  public String sign(final JWTCreator.Builder builder) {
    return builder.sign(algorithm);
  }
}
