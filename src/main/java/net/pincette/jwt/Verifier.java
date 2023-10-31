package net.pincette.jwt;

import static com.auth0.jwt.JWT.decode;
import static com.auth0.jwt.JWT.require;
import static com.auth0.jwt.algorithms.Algorithm.ECDSA256;
import static com.auth0.jwt.algorithms.Algorithm.ECDSA384;
import static com.auth0.jwt.algorithms.Algorithm.ECDSA512;
import static com.auth0.jwt.algorithms.Algorithm.RSA256;
import static com.auth0.jwt.algorithms.Algorithm.RSA384;
import static com.auth0.jwt.algorithms.Algorithm.RSA512;
import static net.pincette.jwt.Util.publicKey;
import static net.pincette.util.Util.must;
import static net.pincette.util.Util.tryToGetRethrow;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Optional;
import net.pincette.util.Util.GeneralException;

/**
 * Verifies JTWs using the Auth0 library. It selects the algorithm based on the given public key.
 *
 * @author Werner Donné
 */
public class Verifier {
  final JWTVerifier[] verifiers = new JWTVerifier[3];

  /**
   * Creates a JWT verifier with a public key in PEM format. Only RSA and ECDSA are supported.
   *
   * @param publicKey the given public key of type RSA or ECDSA.
   */
  public Verifier(final String publicKey) {
    this(publicKey(publicKey));
  }

  /**
   * Creates a JWT verifier with a public key. Only RSA and ECDSA are supported.
   *
   * @param publicKey the given public key of type RSA or ECDSA.
   */
  public Verifier(final PublicKey publicKey) {
    must(publicKey instanceof RSAKey || publicKey instanceof ECKey);

    if (publicKey instanceof RSAKey k) {
      verifiers[0] = require(RSA256(k)).build();
      verifiers[1] = require(RSA384(k)).build();
      verifiers[2] = require(RSA512(k)).build();
    } else {
      verifiers[0] = require(ECDSA256((ECKey) publicKey)).build();
      verifiers[1] = require(ECDSA384((ECKey) publicKey)).build();
      verifiers[2] = require(ECDSA512((ECKey) publicKey)).build();
    }
  }

  private static int selectVerifier(final String algorithm) {
    return switch (algorithm) {
      case "ES256", "RS256" -> 0;
      case "ES384", "RS384" -> 1;
      case "ES512", "RS512" -> 2;
      default -> throw new GeneralException("Unknown algorithm " + algorithm);
    };
  }

  /**
   * Verifies the given JWT.
   *
   * @param jwt the given JWT.
   * @return An optional value that will be empty when the JWT can't be verified.
   */
  public Optional<DecodedJWT> verify(final String jwt) {
    return Optional.of(decode(jwt)).flatMap(this::verify);
  }

  /**
   * Verifies the given JWT.
   *
   * @param jwt the given JWT.
   * @return An optional value that will be empty when the JWT can't be verified.
   */
  public Optional<DecodedJWT> verify(final DecodedJWT jwt) {
    return tryToGetRethrow(() -> verifiers[selectVerifier(jwt.getAlgorithm())].verify(jwt));
  }
}
