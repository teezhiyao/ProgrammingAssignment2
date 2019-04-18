package Server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class ServerWithoutSecurity {

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

				
			FileInputStream certFileInputStream = null;
	        BufferedInputStream certBufferedFileInputStream = null;
	        
			int certNumBytes = 0;

	        
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {
					
					
					int nonceLength = fromClient.readInt();
					byte[] nonceArray = new byte[nonceLength];
					fromClient.readFully(nonceArray, 0, nonceLength);
				    String noncePrint = new String(nonceArray, Charset.forName("UTF-8"));
					System.out.println("Receiving nonce..." + noncePrint);

					System.out.println("Encrypting Nonce and sending back to Client");

			        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
			        byte[] encryptedBytes = cipher.doFinal(nonceArray);
			        
//			        System.out.println(encryptedBytes.length);
//			        String base64format = DatatypeConverter.printBase64Binary(encryptedBytes);
//			        System.out.println("Cipher Text : "+ base64format);
					
			        toClient.writeInt(encryptedBytes.length);
					toClient.write(encryptedBytes);
					
					System.out.println("Sending Certificate to Client");
					
//			    	String certFilename = ".\\sarthakzhiyao.org.crt";
			    	String certFilename = returnPath("sarthakzhiyao.org.crt");

					toClient.writeInt(certFilename.getBytes().length);
					toClient.write(certFilename.getBytes());
					//toServer.flush();

					// Open the file
					certFileInputStream = new FileInputStream(certFilename);
					certBufferedFileInputStream = new BufferedInputStream(certFileInputStream);

			        byte [] fromFileBuffer = new byte[6000];

			        // Send the cert
			        for (boolean fileEnded = false; !fileEnded;) {
			        	certNumBytes = certBufferedFileInputStream.read(fromFileBuffer);
						fileEnded = certNumBytes < 6000;

//						toClient.writeInt(1);
						//System.out.println(certNumBytes);
						toClient.writeInt(certNumBytes);
						toClient.write(fromFileBuffer);
						//toClient.flush();
					}

			        certBufferedFileInputStream.close();
			        certFileInputStream.close();
					
		
					System.out.println("Receiving file...");
			
					
					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);
					String temp = "Justgot.txt";
					filename = temp.getBytes();
					numBytes = filename.length;

					fileOutputStream = new FileOutputStream(returnPath("") +"\\"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					int decryptedByteslength = fromClient.readInt();
					System.out.println(numBytes);
					System.out.println(decryptedByteslength);
					byte [] block = new byte[decryptedByteslength];
					fromClient.readFully(block, 0, decryptedByteslength);
					
					Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					dcipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
					byte[] decryptedBytes = dcipher.doFinal(block);
					

					if (numBytes > 0)
						bufferedFileOutputStream.write(decryptedBytes, 0, numBytes);
		
					if (numBytes < 117  ) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}
	
	public static PrivateKey getPrivateKey()
	  throws Exception {
//		System.out.println(Paths.get("private_key.der").toAbsolutePath().toString());
    	String filename = Paths.get("Server","private_key.der").toAbsolutePath().toString();

//		    	String filename = "\\private_key.der";
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	  }

	public static String returnPath(String path) {
		return Paths.get("Server",path).toAbsolutePath().toString();
	}
}


