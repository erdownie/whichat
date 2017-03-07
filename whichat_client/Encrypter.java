/*
 * @Author Eric Downie
 * Whichat Encryption Module
 * Accepts a plaintext message and rsa public key
 * Returns JSON object containing:
 * 		AES encrypted message
 * 		HMAC tag
 * 		RSA encrypted AES and HMAC keys concatenated
 */
package whichat_client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.*; //Imported JSON api to project from external JAR file
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

//Basis of encryption code by user 'hat' on stackoverflow
	//stackoverflow.com/questions/9658921/encrypting-aes-key-with-rsa-public-key
public class Encrypter {
	public JsonObject encrypt(String[] args) throws Exception{
		final String plaintext = args[1];
		final String keypath = args[2];
		final int keysize = 256;
		byte[] ciphertext = null;
		Cipher cipher = null;
		final PublicKey rsaKey = PublicKeyReader.get(keypath); //translates rsa key into something java understands
		KeyGenerator keyGen = KeyGenerator.getInstance("AWS");
		keyGen.init(keysize); //key size 256 bit
		final SecretKey aesKey = keyGen.generateKey(); //generate a 256-bit aes key
		
		keyGen = KeyGenerator.getInstance("HmacSHA256");
		keyGen.init(keysize); //key size 256 bit
		final SecretKey hmacKey = keyGen.generateKey(); //generate 256-bit hmac key
		
		cipher = Cipher.getInstance("AES/ECB/OAEPPadding"); //set encryption for AES mode
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
										//not sure if this works. Also magic number  ¯\_(ツ)_/¯
		ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)); //encrypts message via AES
										//Specifying UTF8 encoding of string for consistency
		final Mac hmac = Mac.getInstance("HmacSHA256");
		SecretKeySpec ihavenoideawhatimdoinglol = new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256");
		hmac.init(ihavenoideawhatimdoinglol);
		byte[] hmacTag = hmac.doFinal(ciphertext);//run hmac on the ciphertext
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(); //output stream for concatenating keys
		outputStream.write(aesKey.getEncoded()); //add AES to array
		outputStream.write(hmacKey.getEncoded());//add hmac to array
		byte[] concatKeys = outputStream.toByteArray(); //finalize array
		
		cipher = Cipher.getInstance("RSA/ECB/OAEPPadding"); //set encryption for RSA mode
		cipher.init(Cipher.ENCRYPT_MODE,  rsaKey);
		byte[] cipherKeys = cipher.doFinal(concatKeys); //rsa encrypted AES and HMAC keys
		
		//Make strings of everything for JSON object
		String rsaCipherText = new String(cipherKeys, StandardCharsets.UTF_8); //set rsa text to string
		String aesCipherText = new String(ciphertext, StandardCharsets.UTF_8); //encode AES cipher as UTF8 string
		String tag = new String(hmacTag, StandardCharsets.UTF_8);
		
		//Start building the JSON object
		JsonObject jason = Json.createObjectBuilder() //javax.json seems only happy with strings
			     .add("RSA", rsaCipherText)
			     .add("AES", aesCipherText)
			     .add("HMAC", tag)
			     .build(); //complete json object
     
		return jason; //return the new json
	}
}
