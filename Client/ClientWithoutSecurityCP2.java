package Client;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class ClientWithoutSecurityCP2 {

	public static void main(String[] args) {
		
	    byte[] nonceArray = new byte[20]; 
	    new Random().nextBytes(nonceArray);
	    String nonce = new String(nonceArray, Charset.forName("UTF-8"));
	    
	    String temp1 = "12345";
	    
    	String filename = Paths.get("Client","testing.txt").toAbsolutePath().toString();

//    	String filename = ".\\testing.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) filename = args[1];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			
	
			toServer.writeInt(0); //Set PacketType

			System.out.println("Sending nonce..." + temp1);
//			toServer.writeInt(20);
			toServer.writeInt(temp1.getBytes().length);
			toServer.write(temp1.getBytes());
			
			System.out.println("Getting Encrypted Nonce");
			int encryptedNonceLength = fromServer.readInt();
			byte[] encryptedNonce = new byte[encryptedNonceLength];
			fromServer.readFully(encryptedNonce, 0, encryptedNonceLength);
			
//	        String base64format = DatatypeConverter.printBase64Binary(encryptedNonce);
//	        System.out.println("Cipher Text : "+ base64format);
			
			System.out.println("Request for Server Certificate");
			toServer.writeInt(2); //Set PacketType to sending file

			FileOutputStream fileOutputStream = null;
			BufferedOutputStream bufferedFileOutputStream = null;
		
			System.out.println("Receiving Certificate");
			
			int certBytes = fromServer.readInt();
			byte [] cert = new byte[certBytes];
			// Must use read fully!
			// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
			fromServer.readFully(cert, 0, certBytes);
			String temp = "thisisthecert.org.crt";
//	    	String temp = Paths.get("Client","thisisthecert.org.crt").toAbsolutePath().toString();

			cert = temp.getBytes();
			certBytes = cert.length;
//			System.out.println(returnPath(""));
			fileOutputStream = new FileOutputStream(returnPath(new String(cert, 0, certBytes)));
			bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
		
			
			//Start reading content
			System.out.println("Reading Certificate Content");
			
			int certCBytes = fromServer.readInt();
			//System.out.println(certCBytes);
			byte [] block = new byte[certCBytes];
			fromServer.readFully(block, 0, certCBytes);

			if (certCBytes > 0)
				bufferedFileOutputStream.write(block, 0, certCBytes);

			if (certCBytes <= 2000) {
				System.out.println("Closing file and buffer connection...");

				if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
				if (bufferedFileOutputStream != null) fileOutputStream.close();
			}
			
			//Creating X509Certification Object
//			InputStream fis = new FileInputStream(".\\cacse.crt");
			InputStream fis = new FileInputStream(returnPath("cacse.crt"));

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
			
			InputStream serverCertStream = new FileInputStream(returnPath("thisisthecert.org.crt"));
			CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert =(X509Certificate) cf2.generateCertificate(serverCertStream);

			PublicKey CAKey = CAcert.getPublicKey();
//			PublicKey CAKey = serverCert.getPublicKey();
			try {
				serverCert.checkValidity();   
				serverCert.verify(CAKey);
			} catch(Exception e) {
				System.out.println("Bye! (Close Connection)");
				clientSocket.close();
			}
			
//			System.out.println("printing public key" + serverpublickey);
			
			///DECRYPTING NONCE
			PublicKey serverKey = serverCert.getPublicKey();
			
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher1.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptedNonceBytes = cipher1.doFinal(encryptedNonce);
			String omg = new String(decryptedNonceBytes);
			
			if (!omg.equals(temp1)) {
				System.out.println("Nonce is incorrect. Bye (Close Connection)");
				clientSocket.close();
			}
			System.out.println("Decrypted Nonce is " +  omg);

			//SESSION KEY 
			toServer.writeInt(4);
			System.out.println("Requesting for Session Key");
			int skeylength = fromServer.readInt();
			System.out.println(skeylength);
			
//			toServer.writeInt(4);
//			System.out.println("Requesting for Session Key");
//			int skeylength = fromServer.readInt();
//			while ((skeylength = fromServer.readInt() )== 0) {
//			}
//			byte[] encryptedKey = new byte[skeylength];
//			fromServer.readFully(encryptedKey,0,skeylength);
//			System.out.println("Encrypted Key length");
//			System.out.println(skeylength);
//			Cipher keyCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//			keyCipher.init(Cipher.DECRYPT_MODE, serverKey);
//			byte[] decryptedKey = keyCipher.doFinal(encryptedKey);
//			
//			SecretKey sKey = new SecretKeySpec(decryptedKey,0,decryptedKey.length,"AES");

			
			//Sending file
			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(3);

			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1);
				System.out.println(numBytes);
				
				Cipher ecipher = Cipher.getInstance("AES/ECB/PKCS1Padding");
		        ecipher.init(Cipher.ENCRYPT_MODE, serverKey);
		        byte[] encryptedBytes = ecipher.doFinal(fromFileBuffer);
				
				toServer.writeInt(numBytes);
				toServer.writeInt(encryptedBytes.length);
				toServer.write(encryptedBytes);
//				toServer.writeInt(numBytes);
//				toServer.write(fromFileBuffer);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
	
	public static String returnPath(String path) {
		return Paths.get("Client",path).toAbsolutePath().toString();
	}
}
