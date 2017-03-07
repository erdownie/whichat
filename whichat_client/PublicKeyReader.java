package whichat_client;
//Public key reader code by user jdhurst and edited by Sarah Whelan on stackoverflow
	//stackoverflow.com/a/19387517
//Takes file path to public key and returns PublicKey object
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

public class PublicKeyReader {

  public static PublicKey get(String filename)
    throws Exception {

    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

    X509EncodedKeySpec spec =
      new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }
}
