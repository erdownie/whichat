package whichat_client;
//Private key reader code by user jdhurst and edited by Sarah Whelan on stackoverflow
	//stackoverflow.com/a/19387517
//Takes file path to private key and returns PublicKey object
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

public class PrivateKeyReader {

  public static PrivateKey get(String filename)
  throws Exception {

    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

    PKCS8EncodedKeySpec spec =
      new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }
}
