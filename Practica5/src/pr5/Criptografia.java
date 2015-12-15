package pr5;

import java.security.*;

public class Criptografia {
	
//	ArrayList<User> hasTable;
	private static Signature dsa;
	
	public static byte[] hashClave (String clave) {
		try {
			long t1 = System.currentTimeMillis();
			MessageDigest digestiveFontaneda = MessageDigest.getInstance("SHA-512");
			byte[] hash = digestiveFontaneda.digest(clave.getBytes());
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
			MessageDigest digestiveFontaneda = MessageDigest.getInstance("SHA-512");
			byte[] hash = digestiveFontaneda.digest(clave.getBytes());
			hash = digestiveFontaneda.digest(hash);
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
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
			SecureRandom secRdm = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, secRdm);
			KeyPair pair = keyGen.generateKeyPair();
			long t2 = System.currentTimeMillis();
			System.out.printf("Tiempo de generación de las claves: %d ms.\n", t2-t1);
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
	
	public static String descifrarMsg (byte[] sig, PublicKey publicKey) {
		
	}

	
	public static void main (String[] args) {
//		byte[] clave = hashClave("MOSTRO GAY");
//		System.out.println(clave);	
//		clave = hashClaveDoble("MOSTRO GAY");
//		System.out.println(clave);
//		clave = hashClaveTriple("MOSTRO GAY");
//		System.out.println(clave);
		KeyPair pair = clavePublicaPrivada();
//		System.out.println("PUBLIC: " + pair.getPublic());
//		System.out.println("PRIVATE: " + pair.getPrivate());
		byte[] b = firmarConClavePrivada("MOSTRO GAY", "DSAwithSHA1", pair.getPrivate());
		System.out.println(b);
		boolean correcto = verificarMsg(new String("MOSTRO GAY").getBytes(), b, pair.getPublic());
		System.out.printf("Se ha verificado la clave?: %b.\n", correcto);
	}
	
}
