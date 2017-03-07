/*
 * @Author Eric Downie
 * Whichat Decryption Module
 * Accepts a JSON object from encryption module and rsa private key
 * Returns Failure if integrity failed
 * 		otherwise returns decrypted plaintext
 */
package whichat_client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.*; //Imported JSON api to project from external JAR file
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class Decrypter {

	public String decrypt(JsonObject j, String k) throws Exception {
		final String keyPath = k;
		JsonObject jason = j;
		
		//prepare cipher to decrypt rsa
		final PrivateKey rsaKey = PrivateKeyReader.get(keyPath);
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
		cipher.init(Cipher.DECRYPT_MODE, rsaKey);
		
		//get all our strings from json and convert them back to byte arrays
		byte[] rsaCiphertext = jason.getString("RSA").getBytes(StandardCharsets.UTF_8); //keys
		byte[] aesCiphertext = jason.getString("AES").getBytes(StandardCharsets.UTF_8); //message
		byte[] hmacTag = jason.getString("HMAC").getBytes(StandardCharsets.UTF_8); //hmac tag
		
		//decrypt rsa cipher text containing keys
		byte[] concatKeys = cipher.doFinal(rsaCiphertext);
		
		//split the concatenated keys
		byte[] aesKeyBytes = Arrays.copyOfRange(concatKeys, 0, 255);
		byte[] hmacKey = Arrays.copyOfRange(concatKeys, 256, concatKeys.length);
		
		//Recover AES key from its byte array
		SecretKey originalAESKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
		
		//Run HMAC again
		final Mac hmac = Mac.getInstance("HmacSHA256");
		SecretKeySpec ihavenoideawhatimdoinglol = new SecretKeySpec(hmacKey, "HmacSHA256");
		hmac.init(ihavenoideawhatimdoinglol);
		byte[] hmacTagNew = hmac.doFinal(aesCiphertext);//run hmac on the ciphertext
		
		if(!Arrays.equals(hmacTag, hmacTagNew)){
			return "Failure. HmacTag mismatch!";
			//return fail if hmac doesn't match
		}
		
		//prepare cipher to decrypt AES
		cipher = Cipher.getInstance("AES/ECB/OAEPPadding");
		cipher.init(Cipher.DECRYPT_MODE, originalAESKey, new IvParameterSpec(new byte[16]));
		final String decodedText = new String (cipher.doFinal(aesCiphertext), StandardCharsets.UTF_8);
		
		return decodedText;
		
		
	}

}
