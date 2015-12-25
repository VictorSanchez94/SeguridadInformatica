package pr5;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

import javax.crypto.Cipher;


/**
 * 
 * Authors:
 * 	Alberto Sabater Bailon, 546297
 *	Victor Sanchez Ballabriga, 602665
 * 
 */
public class Criptografia {
	
	private static Signature dsa;
	
	
	public static void main (String[] args) {
		KeyPair pair;
		int type = Integer.parseInt(args[0]);
		type = 10;
		switch (type) {
		case 1:			//Prueba de generacion de hash de un texto
			/*
			 * Tiempo: 13 ms
			 * 
			 * Se utiliza el algoritmo SHA-512 para obtener el hash que genera 
			 * una clave de tamaño 512 bits
			 */
			
			byte[] clave = hashClave("Seguridad Informatica 2015-2016");
			System.out.println("HASH:");
			System.out.println(clave);
			break;
		case 2:			//Prueba de generacion de hash doble de un texto
			/*
			 * Tiempo: 13 ms
			 * 
			 * Se utiliza dos veces el algoritmo SHA-512 para cifrar el mensaje
			 * por duplicado
			 */
			
			clave = hashClaveDoble("Seguridad Informatica 2015-2016");
			System.out.println("HASH DOBLE:");
			System.out.println(clave);
			break;
		case 3:			//Prueba de generacion de hash triple de un texto
			/*
			 * Tiempo: 15 ms
			 * 
			 * Se utiliza tres veces el algoritmo SHA-512 para cifrar el mensaje
			 * por triplicado
			 */
			
			clave = hashClaveTriple("Seguridad Informatica 2015-2016");
			System.out.println("HASH TRIPLE:");
			System.out.println(clave);
			break;
		case 4:			//Prueba de generacion pareja de claves publica/privada
			/*
			 * Tiempo: 240 ms
			 * 
			 * Se utiliza le algoritmo RSA para la generación de claves (1024-2048 bites), inicializandolo
			 * con un número pseudoaleatorio generado con el algoritmo SHA1PRNG.
			 */
			
			pair = clavePublicaPrivada(true);
			System.out.println("PUBLIC: " + pair.getPublic());
			System.out.println("PRIVATE: " + pair.getPrivate());
			break;
		case 5:			//Prueba de firma y verificacion de mensajes mediante firma digital
			pair = clavePublicaPrivada(true);
			byte[] b = firmarConClavePrivada("Seguridad Informatica 2015-2016", "DSAwithSHA1", pair.getPrivate());
			System.out.println(b);
			boolean correcto = verificarMsg(new String("Seguridad Informatica 2015-2016").getBytes(), b, pair.getPublic());
			System.out.printf("Â¿Se ha verificado la clave?: %b.\n", correcto);
			break;
		case 6:			// Prueba encriptacion con clave publica y desencriptado con privada
			/*
			 * Tiempo: 5 ms para cifrar y 5 ms descrifrar el texto, + la generacion de las claves
			 * 
			 * Se generan las claves con el algoritmo RSA mencionado anteriormente y se 
			 * cifra un texto con clave publica y se descifra con clave privada
			 */
			
			try {
				pair = clavePublicaPrivada(true);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePublica("Seguridad Informatica 2015-2016", cipher, pair.getPublic(), true);
				System.out.println("ENCRIPTADO:");
				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePrivada(encryptedText, cipher, pair.getPrivate(), true);
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			break;
		case 7:			// Prueba encriptacion con clave privada y desencriptado con publica
			/*
			 * Tiempo: 9 ms para cifrar y 1 ms para descrifrar el texto, + la generacion de las claves
			 * 
			 * Se generan las claves con el algoritmo RSA mencionado anteriormente y se 
			 * cifra un texto con clave privada y se descifra con clave publica
			 */
			
			try {
				pair = clavePublicaPrivada(true);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePrivada("Seguridad Informatica 2015-2016", cipher, pair.getPrivate(), true);
				System.out.println("ENCRIPTADO:");
				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePublica(encryptedText, cipher, pair.getPublic(), true);
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			break;
		case 8:			//Prueba encriptando un texto de 50000 caracteres
			/*
			 * Tiempo: 609 ms para cifrar el texto y 32 ms para descifrarlo
			 * 
			 * Se generan las claves con el algoritmo RSA mencionado anteriormente y se
			 * cifra un texto de 50000 caracteres con clave privada, y se descifra con 
			 * clave publica
			 */
			
			try {
				String st = randomString(50000);
				pair = clavePublicaPrivada(true);
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePrivada(st, cipher, pair.getPrivate(), true);
				System.out.println("ENCRIPTADO");
//				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePublica(encryptedText, cipher, pair.getPublic(), true);
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			break;
		case 9:
			/*
			 * Tiempo: 6331 ms 
			 * 
			 * Se cifran 100 mensajes de 200 caracteres aleatorios con clave publica y se 
			 * descifran con clave privada, con los algoritmos descritos anteriormente
			 */
			
			long t1 = System.currentTimeMillis();
			for (int i=0; i<100; i++) {
				try {
					pair = clavePublicaPrivada(false);
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					byte[][] encryptedText = encriptarConClavePublica(randomString(200), cipher, pair.getPublic(), false);
					desencriptarConClavePrivada(encryptedText, cipher, pair.getPrivate(), false);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			
			System.out.println("Tiempo de cifrado con clave publica y descifrado con clave privada de 100 mensajes aleatorios: " + tFinal);
			break;
		case 10:
			/*
			 * Tiempo: 6269 ms 
			 * 
			 * Se cifran 100 mensajes de 200 caracteres aleatorios con clave privada y se 
			 * descifran con clave publica, con los algoritmos descritos anteriormente
			 */
			
			t1 = System.currentTimeMillis();
			for (int i=0; i<100; i++) {
				try {
					pair = clavePublicaPrivada(false);
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					byte[][] encryptedText = encriptarConClavePrivada(randomString(200), cipher, pair.getPrivate(), false);
					desencriptarConClavePublica(encryptedText, cipher, pair.getPublic(), false);
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			t2 = System.currentTimeMillis();
			tFinal = t2-t1;
			
			System.out.println("Tiempo de cifrado con clave privada y descifrado con clave publica de 100 mensajes aleatorios: " + tFinal);
			break;
		}
		
	}
	
	
	public static byte[] hashClave (String clave) {
		try {
			long t1 = System.currentTimeMillis();
			MessageDigest digestive = MessageDigest.getInstance("SHA-512");
			byte[] hash = digestive.digest(clave.getBytes());
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo de calculo del hash simple: %d ms.\n", t2-t1);
			return hash;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] hashClaveDoble (String clave){
		try {
			long t1 = System.currentTimeMillis();
			MessageDigest digestive = MessageDigest.getInstance("SHA-512");
			byte[] hash = digestive.digest(clave.getBytes());
			hash = digestive.digest(hash);
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo de calculo del hash doble: %d ms.\n", t2-t1);
			return hash;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} 
	}
	public static byte[] hashClaveTriple (String clave){
		try {
			long t1 = System.currentTimeMillis();
			MessageDigest digestiveFontaneda = MessageDigest.getInstance("SHA-512");
			byte[] hash = digestiveFontaneda.digest(clave.getBytes());
			hash = digestiveFontaneda.digest(hash);
			hash = digestiveFontaneda.digest(hash);
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo de calculo del hash triple: %d ms.\n", t2-t1);
			return hash;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	public static KeyPair clavePublicaPrivada(boolean log) {
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom secRdm = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, secRdm);
			KeyPair pair = keyGen.generateKeyPair();
			long t2 = System.currentTimeMillis();
			if (log ) System.out.printf("Tiempo de generacion de las claves: %d ms.\n", t2-t1);
			return pair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] firmarConClavePrivada (String data, String firma, PrivateKey privateKey) {
		try {
			long t1 = System.currentTimeMillis();
			dsa = Signature.getInstance(firma);
			dsa.initSign(privateKey);
			dsa.update(data.getBytes());
			byte[] sig = dsa.sign();
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo para firmar el texto: %d ms.\n", t2-t1);
			return sig;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static boolean verificarMsg (byte[] data, byte[] sig, PublicKey publicKey) {
		try {
			long t1 = System.currentTimeMillis();
			dsa.initVerify(publicKey);
			dsa.update(data);
			boolean correcta = dsa.verify(sig);
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo para verificar la firma digital: %d ms.\n", t2-t1);
			return correcta;
		} catch (InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}

	public static byte[][] encriptarConClavePublica(String text, Cipher cipher, PublicKey publicKey, boolean log) {
		try {
			long t1 = System.currentTimeMillis();
//			byte[] plainText = text.getBytes("UTF8");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			byte[][] cipherText = byteArrayFromString(text);
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
			
//			cipherText = cipher.doFinal(plainText);
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			
			if (log ) System.out.printf("Tiempo para encriptar el texto con clave publica: %d ms.\n", tFinal);

			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String desencriptarConClavePrivada(byte[][] cipherText, Cipher cipher, PrivateKey privateKey, boolean log) {
		try {
			long t1 = System.currentTimeMillis();
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
//			byte[] newPlainText = cipher.doFinal(cipherText);
			
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
			
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			if (log ) System.out.printf("Tiempo para desencriptar el texto con clave privada: %d ms.\n", tFinal);
//			return new String(newPlainText, "UTF8");
			return stringFromByteArrays(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[][] encriptarConClavePrivada(String text, Cipher cipher, PrivateKey privateKey, boolean log) {
		try {
			long t1 = System.currentTimeMillis();
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[][] cipherText = byteArrayFromString(text);
			
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
//			int i = 0;
//			int from = 0;
//			int to = 116;
//			while (to <= text.length()) {
//				cipherText[i] = cipher.doFinal(text.substring(from, to).getBytes());
//				from = to + 1;
//				to += 117;
//				i++;
//			}

			// cipherText = cipher.doFinal(plainText);
			long t2 = System.currentTimeMillis();
			long tFinal = t2 - t1;
			if (log) System.out.printf("Tiempo para encriptar el texto con clave privada: %d ms.\n", tFinal);
			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String desencriptarConClavePublica(byte[][] cipherText, Cipher cipher, PublicKey publicKey, boolean log) {
		try {
			long t1 = System.currentTimeMillis();
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
			
			//byte[] newPlainText = cipher.doFinal(cipherText);
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			if (log) System.out.printf("Tiempo para desencriptar el texto con clave publica: %d ms.\n", tFinal);
//			return new String(newPlainText, "UTF8");
			return stringFromByteArrays(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String randomString (final int length) {
		char[] chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890".toCharArray();
		StringBuilder sb = new StringBuilder();
		Random random = new Random();
		for (int i = 0; i < length; i++) {
		    char c = chars[random.nextInt(chars.length)];
		    sb.append(c);
		}
		String output = sb.toString();
		return output;
	}
	
	private static String stringFromByteArrays (byte[][] bytes) {
		String s = "";
		int i = 0;
		try{
			while(true){
				s = s + new String(bytes[i], "UTF-8");
				i++;
			}
		}catch(Exception e){
			return s;
		}		
	}
	
	private static byte[][] byteArrayFromString (String s) {
		byte[][] b = new byte[(s.length()/116) +1][];
		int index = 0;
		int j = 0;
		for (int i=0; i<s.length(); i+=116) {
			if (i+116 > s.length()) {
				j = s.length();
			}
			else {
				j = i+116;
			}
			b[index] = s.substring(i,j).getBytes();
			index++;
		}
		
		if (b[b.length-1] == null) {
			byte[][] b2 = new byte[b.length-1][];
			for (int i=0; i<b.length-1; i++) {
				b2[i] = b[i];
			}
			return b2;
		} 
		
		return b;
	}
	
}
