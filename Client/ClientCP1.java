package Client;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
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
import javax.xml.bind.DatatypeConverter;

public class ClientCP1 {

	public static void main(String[] args) {
		
	    int temp = new Random().nextInt();
	    
	    String nonce = Integer.toString(temp);
	    
	    String filename_send = "file64KB.txt";
    	String filename = Paths.get("Client",filename_send).toAbsolutePath().toString();

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

			System.out.println("Sending nonce..." + nonce);
//			toServer.writeInt(20);
			toServer.writeInt(nonce.getBytes().length);
			toServer.write(nonce.getBytes());
			
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
			
			int certLength = fromServer.readInt();
			byte [] certBytes = new byte[certLength];
			fromServer.readFully(certBytes, 0, certLength);
//			String temp = "thisisthecert.org.crt";
//	    	String temp = Paths.get("Client","thisisthecert.org.crt").toAbsolutePath().toString();

//			cert = temp.getBytes();
//			certBytes = cert.length;
//			System.out.println(returnPath(""));
//			fileOutputStream = new FileOutputStream(returnPath(new String(cert, 0, certBytes)));
//			bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
//		
			
			//Start reading content
//			System.out.println("Reading Certificate Content");
			
//			int certLength = fromServer.readInt();
//			//System.out.println(certCBytes);
//			byte [] certBytes = new byte[certBytes];
//			fromServer.readFully(certBytes, 0, certBytes);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			
			InputStream serverCertStream = new ByteArrayInputStream(certBytes);

			X509Certificate serverCert =(X509Certificate) cf.generateCertificate(serverCertStream);
			
			//Creating X509Certification Object
			InputStream fis = new FileInputStream(returnPath("cacse.crt"));

			
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
			

//			if (certCBytes > 0)
//				bufferedFileOutputStream.write(block, 0, certCBytes);
//
//			if (certCBytes <= 6000) {
//				System.out.println("Closing file and buffer connection...");
//
//				if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
//				if (bufferedFileOutputStream != null) fileOutputStream.close();
//			}
			
			//Creating X509Certification Object
//			InputStream fis = new FileInputStream(".\\cacse.crt");
//			InputStream fis = new FileInputStream(returnPath("cacse.crt"));
//
//			CertificateFactory cf = CertificateFactory.getInstance("X.509");
//			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
//			
//			InputStream serverCertStream = new FileInputStream(returnPath("thisisthecert.org.crt"));
//			CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
//			X509Certificate serverCert =(X509Certificate) cf2.generateCertificate(serverCertStream);

			PublicKey CAKey = CAcert.getPublicKey();
//			PublicKey CAKey = serverCert.getPublicKey();
			try {
				serverCert.checkValidity();   
				serverCert.verify(CAKey);
			} catch(Exception e) {
				System.out.println("Bye! (Close Connection)");
				clientSocket.close();
			}
			
			
			///DECRYPTING NONCE
			PublicKey serverKey = serverCert.getPublicKey();
			
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher1.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptedNonceBytes = cipher1.doFinal(encryptedNonce);
			String nonceFromServer = new String(decryptedNonceBytes);
			
			if (!nonceFromServer.equals(nonce)) {
				System.out.println("Nonce is incorrect. Bye (Close Connection)");
				clientSocket.close();
			}
			
			System.out.println("Decrypted Nonce is " +  nonceFromServer);
		
			

			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(3);

			toServer.writeInt(filename_send.getBytes().length);
			toServer.write(filename_send.getBytes());
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
				
				Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
			clientSocket.close();
			
		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
	
	public static String returnPath(String path) {
		return Paths.get("Client",path).toAbsolutePath().toString();
	}
}
