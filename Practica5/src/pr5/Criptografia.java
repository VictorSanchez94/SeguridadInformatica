package pr5;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Random;

import javax.crypto.*;

public class Criptografia {
	
	private static Signature dsa;
	
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
	
	public static KeyPair clavePublicaPrivada() {
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom secRdm = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, secRdm);
			KeyPair pair = keyGen.generateKeyPair();
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo de generacion de las claves: %d ms.\n", t2-t1);
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

	public static byte[][] encriptarConClavePublica(String text, Cipher cipher, PublicKey publicKey) {
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
			System.out.printf("Tiempo para encriptar el texto con clave publica: %d ms.\n", tFinal);
			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String desencriptarConClavePrivada(byte[][] cipherText, Cipher cipher, PrivateKey privateKey) {
		try {
			long t1 = System.currentTimeMillis();
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
//			byte[] newPlainText = cipher.doFinal(cipherText);
			
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
			
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			System.out.printf("Tiempo para desencriptar el texto con clave privada: %d ms.\n", tFinal);
//			return new String(newPlainText, "UTF8");
			return stringFromByteArrays(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[][] encriptarConClavePrivada(String text, Cipher cipher, PrivateKey privateKey) {
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
			System.out.printf("Tiempo para encriptar el texto con clave privada: %d ms.\n", tFinal);
			return cipherText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String desencriptarConClavePublica(byte[][] cipherText, Cipher cipher, PublicKey publicKey) {
		try {
			long t1 = System.currentTimeMillis();
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			
			for (int i=0; i<cipherText.length; i++) {
				cipherText[i] = cipher.doFinal(cipherText[i]);
			}
			
			//byte[] newPlainText = cipher.doFinal(cipherText);
			long t2 = System.currentTimeMillis();
			long tFinal = t2-t1;
			System.out.printf("Tiempo para desencriptar el texto con clave publica: %d ms.\n", tFinal);
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
		byte[][] b = new byte[(s.length()/112) +1][];
//		System.out.println("lenght: " + b.length);
		String temp = s;
		int index = 0;
		int j = 0;
		for (int i=0; i<s.length(); i+=112) {
			if (i+112 > s.length()) {
				j = s.length();
			}
			else {
				j = i+112;
			}
//			System.out.println(i + "  " + s.length() + "  " + index + "  " +j + "  " + s.length() + "  " + s.substring(i,j));
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
	
	public static void main (String[] args) {
		KeyPair pair;
		int type = Integer.parseInt(args[0]);
		type = 8;
		switch (type) {
		case 1:			//Prueba de generacion de hash de un texto
			byte[] clave = hashClave("Seguridad Informatica 2015-2016");
			System.out.println("HASH:");
			System.out.println(clave);
			break;
		case 2:			//Prueba de generacion de hash doble de un texto
			clave = hashClaveDoble("Seguridad Informatica 2015-2016");
			System.out.println("HASH DOBLE:");
			System.out.println(clave);
			break;
		case 3:			//Prueba de generacion de hash triple de un texto
			clave = hashClaveTriple("Seguridad Informatica 2015-2016");
			System.out.println("HASH TRIPLE:");
			System.out.println(clave);
			break;
		case 4:			//Prueba de generacion pareja de claves publica/privada
			pair = clavePublicaPrivada();
			System.out.println("PUBLIC: " + pair.getPublic());
			System.out.println("PRIVATE: " + pair.getPrivate());
			break;
		case 5:			//Prueba de firma y verificacion de mensajes mediante firma digital
			pair = clavePublicaPrivada();
			byte[] b = firmarConClavePrivada("Seguridad Informatica 2015-2016", "DSAwithSHA1", pair.getPrivate());
			System.out.println(b);
			boolean correcto = verificarMsg(new String("Seguridad Informatica 2015-2016").getBytes(), b, pair.getPublic());
			System.out.printf("¿Se ha verificado la clave?: %b.\n", correcto);
			break;
		case 6:			// Prueba encriptacion con clave publica y desencriptado con privada
			try {
				pair = clavePublicaPrivada();
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePublica("Seguridad Informatica 2015-2016", cipher, pair.getPublic());
				System.out.println("ENCRIPTADO:");
				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePrivada(encryptedText, cipher, pair.getPrivate());
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			break;
		case 7:			// Prueba encriptacion con clave privada y desencriptado con publica
			try {
				pair = clavePublicaPrivada();
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePrivada("Seguridad Informatica 2015-2016", cipher, pair.getPrivate());
				System.out.println("ENCRIPTADO:");
				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePublica(encryptedText, cipher, pair.getPublic());
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			break;
		case 8:			//Prueba encriptando un texto de 50000 caracteres
			try {
				String st = randomString(50000);
				pair = clavePublicaPrivada();
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				byte[][] encryptedText = encriptarConClavePrivada(st, cipher, pair.getPrivate());
				System.out.println("ENCRIPTADO");
//				System.out.println(stringFromByteArrays(encryptedText));
				System.out.println("\n======================================================================================\n");
				String desencryptedText = desencriptarConClavePublica(encryptedText, cipher, pair.getPublic());
				System.out.println("DESENCRIPTADO:");
				System.out.println(desencryptedText);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			break;
		case 9:			//Prueba generando 100 mensajes de 1000 caracteres para encriptarlos y desencriptarlos midiendo tiempos
			long t1 = System.currentTimeMillis();
			break;
		case 10:			
			String s = randomString(1000);
//			System.out.println("s: " + s.length());
			byteArrayFromString(s);
			break;
		}
		
	}
	
}
