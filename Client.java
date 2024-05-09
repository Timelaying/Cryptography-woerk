package assigment;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;
import java.nio.file.*;

public class Client {

	public static void main(String[] args) throws Exception {

		// Connection and File Section of the code
		String host = args[0]; // hostname of server
		int port = Integer.parseInt(args[1]); // port of server
		String userid = args[2]; // userid
		String filename = args[3]; // file

		// fist stage before connection
		FileOutputStream f = new FileOutputStream("somefil");
		try (DataOutputStream out = new DataOutputStream(f)) { // saving userid
			out.writeUTF(userid);
			out.flush();
			out.close();
		}

		// Saving keys
		File folder = new File(".");
		File[] listOfFiles = folder.listFiles();

		File newFolder = new File("clientfiles"); // creating client file folder
		newFolder.mkdir();

		for (File file : listOfFiles) { // check files
			if (file.isFile() && file.getName().equals("server.pub") || file.getName().equals(userid + ".prv")) {
				try { // moving found keys
					Files.move(file.toPath(), new File(newFolder, file.getName()).toPath());
					System.out.println("File " + file.getName() + " moved successfully");

				} catch (IOException e) {
					e.printStackTrace();
				}

			}

		}

		// The key agreement stage

		// Random Byte generation
		byte[] randomBytes = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(randomBytes);
		System.out.println(Arrays.toString(randomBytes)); // to check bytes sents to server

		// Encrypting with RSA/ECB/PKCS1Padding and RSAkey

		// read key
		ObjectInputStream in = new ObjectInputStream(new FileInputStream("./clientfiles/server.pub")); // using
																										// server
																										// key
		PublicKey key = (PublicKey) in.readObject();
		in.close();

		// encrypt
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] raw = cipher.doFinal(randomBytes);

		//get specific user private key
		String fileNa = userid + ".prv";
		String directoryPath = "./clientfiles/";
		String filePa = directoryPath + fileNa;
		
		// read Private key
				ObjectInputStream inc = new ObjectInputStream(new FileInputStream(filePa)); //using client private key																				// key
				PrivateKey keyP = (PrivateKey) inc.readObject();
				inc.close();

		
		 // Sign the encrypted bytes with client's private key
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(keyP);
        signature.update(raw);
        byte[] signatureBytes = signature.sign();
        
        
    	// sending data
		File file = new File("encrypted.msg");
		ObjectOutputStream oout = new ObjectOutputStream(new FileOutputStream(file));
		oout.writeObject(raw);
		oout.close();
		
        //sending signature
        File pile = new File("sigC");
        ObjectOutputStream ooutSC = new ObjectOutputStream(new FileOutputStream(pile));
		ooutSC.writeObject(signatureBytes);
		ooutSC.close();
        		
		//connection starts here to aid synchronization 
		try (Socket s = new Socket(host, port)) {

			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			DataInputStream dis = new DataInputStream(s.getInputStream());
			

			// Decrypting the sent 16bytes from sever
			// Getting the Specific user private key 
			String fileName = userid + ".prv";
			String directoryPath2 = "./clientfiles/";
			String filePath = directoryPath2 + fileName;

			// read user key
			ObjectInputStream in1 = new ObjectInputStream(new FileInputStream(filePath)); // using server private
																							// key
			PrivateKey key1 = (PrivateKey) in1.readObject();
			in1.close();

			Thread.sleep(2000); // to wait for created file encryped2.msg as connection is in sync

				
			// read file
			ObjectInputStream oin = new ObjectInputStream(new FileInputStream("encrypted2.msg"));
			byte[] raw1 = (byte[]) oin.readObject();
			oin.close();
			
			//read signature
			ObjectInputStream oinS = new ObjectInputStream(new FileInputStream("sigS"));
			byte[] rax = (byte[]) oinS.readObject();
			oinS.close();
			
			
			// Verify server's signature	
	        Signature serverSignature = Signature.getInstance("SHA1withRSA");
	        serverSignature.initVerify(key);
	        serverSignature.update(raw1);
	        boolean verified = serverSignature.verify(rax);
	        
	        //logic to verify signature
	        if (!verified) {
	            System.out.println("Server signature is invalid. Aborting.");
	            s.close();
	            return;
	        }

			// decrypt
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher1.init(Cipher.DECRYPT_MODE, key1);
			byte[] stringBytes = cipher1.doFinal(raw1);
			System.out.println(Arrays.toString(stringBytes)); // printing server bytes to check

			
			byte iv[] = randomBytes; // using the first 16 bit sent by client as cbc iv
			
			// Combining the client and server bytes into a single 32-byte key
			byte[] combinedKey = new byte[32];
			System.arraycopy(randomBytes, 0, combinedKey, 0, 16);
			System.arraycopy(stringBytes, 0, combinedKey, 16, 16);

			System.out.println(Arrays.toString(combinedKey)); // just to check printed keys

			// AES SECTION
			// Use the combined key to generate a 256-bit AES key
			SecretKeySpec aesKey = new SecretKeySpec(combinedKey, "AES");

			// to Replace this with the actual filename
			File filetbe = new File(filename);
			byte[] fileBytes = Files.readAllBytes(filetbe.toPath());

			// Re-encrypt of file
			Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher2.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
			byte[] raw2 = cipher.doFinal(fileBytes);

			// Preparing to Prepend the original filename with the client's userid and the
			// special string, and compute the MD5 hash
			String originalFilename = filetbe.getName();
			String newFilename = userid + ":gfhk7346:" + originalFilename;
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hashBytes = md.digest(newFilename.getBytes());

			// Converting to hexadecimal
			StringBuilder sb = new StringBuilder();
			for (byte b : hashBytes)
				sb.append(String.format("%02X", b));
			String HexHash = sb.toString();
			System.out.println(HexHash); // a print out test

			
			String TestFilename = HexHash; // logic to save and name file with HashHex
			File fileTBS = new File(TestFilename);
			FileOutputStream fl = new FileOutputStream(fileTBS);
			try (DataOutputStream outl = new DataOutputStream(fl)) { // saving fileTBS
				outl.write(raw2); // writting the encryted data to the file
				outl.flush();
				outl.close();
			}

			// to send Hashed Name to make naming convention easy for server
			File Hexname = new File("hexname");
			FileOutputStream fop = new FileOutputStream(Hexname);
			try (DataOutputStream out4 = new DataOutputStream(fop)) {
				out4.writeUTF(TestFilename);
				out4.flush();
				out4.close();

			}
		}
	}
}
