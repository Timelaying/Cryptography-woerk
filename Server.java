package assigment;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;

import java.nio.file.*;

public class Server {

	public static void main(String[] args) throws Exception {

		// Connection and File Section of the code
		int port = Integer.parseInt(args[0]);

		try (ServerSocket ss = new ServerSocket(port)) {
			System.out.println("Waiting incoming connection...");

			while (true) {
				Socket s = ss.accept();
				DataInputStream dis = new DataInputStream(s.getInputStream());
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());

				try (DataInputStream in = new DataInputStream(new FileInputStream("somefil"))) { // to get userid
					String userid = in.readUTF();
					System.out.println("Received userid: " + userid);
					

					// Saving RSAKeygen, assuming it was compiled before the client and server program
					File folder = new File(".");
					File[] listOfFiles = folder.listFiles();

					File newFolder = new File("serverfiles"); // creating server file folder
					newFolder.mkdir();
					// logic to search and save file
					for (File file : listOfFiles) {
						if (file.isFile() && file.getName().equals("server.prv")
								|| file.getName().equals(userid + ".pub")) {
							try { // moving found keys
								Files.move(file.toPath(), new File(newFolder, file.getName()).toPath());
								System.out.println("File " + file.getName() + " moved successfully");
							} catch (IOException e) {
								e.printStackTrace();
							}

						}

					}

					//Key agreement stage
					// Decrypting the sent 16bytes from client
					
					// read key to decrypt byte
					ObjectInputStream in1 = new ObjectInputStream(new FileInputStream("./serverfiles/server.prv")); // using
																													// server
																													// private																										// key
					PrivateKey key = (PrivateKey) in1.readObject();
					in1.close();
					//
					
					
					
					// read file
					ObjectInputStream oin = new ObjectInputStream(new FileInputStream("encrypted.msg"));
					byte[] raw = (byte[]) oin.readObject();
					oin.close();
					
					//read signature
					ObjectInputStream oinL = new ObjectInputStream(new FileInputStream("sigC"));
					byte[] rawx = (byte[]) oinL.readObject();
					oinL.close();
					
					//get Client public key
					String fileNa = userid + ".pub";
					String directoryPa = "./serverfiles/";
					String filePa = directoryPa + fileNa;

					// read key
					ObjectInputStream in21 = new ObjectInputStream(new FileInputStream(filePa)); // using client public
																									// key
					PublicKey key12 = (PublicKey) in21.readObject();
					in21.close();
					
					
					// Verify clients's signature
			        Signature serverSignature = Signature.getInstance("SHA1withRSA");
			        serverSignature.initVerify(key12);
			        serverSignature.update(raw);
			        boolean verified = serverSignature.verify(rawx);
			        
			        //logic to abort if signature fails
			        if (!verified) {
			            System.out.println("Server signature is invalid. Aborting.");
			            s.close();
			            return;
			        }
					
					
					// decrypt
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.DECRYPT_MODE, key);
					byte[] stringBytes = cipher.doFinal(raw);
					System.out.println(Arrays.toString(stringBytes)); // printing client bytes to check

					// server sending it own random 16bytes
					// Random Byte generation
					byte[] randomBytes = new byte[16];
					SecureRandom random = new SecureRandom();
					random.nextBytes(randomBytes);
					System.out.println(Arrays.toString(randomBytes)); // to check bytes sent to client

					// Encrypting with RSA/ECB/PKCS1Padding and RSAkey

					// Getting the Specific user public key
					String fileName = userid + ".pub";
					String directoryPath = "./serverfiles/";
					String filePath = directoryPath + fileName;

					// read key
					ObjectInputStream in2 = new ObjectInputStream(new FileInputStream(filePath)); // using clients public
																									// key
					PublicKey key1 = (PublicKey) in2.readObject();
					in2.close();

					// encrypt
					Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher1.init(Cipher.ENCRYPT_MODE, key1);
					byte[] raw1 = cipher1.doFinal(randomBytes);

					
					// Sign the encrypted byte with server's private key
			        Signature signature = Signature.getInstance("SHA1withRSA");
			        signature.initSign(key);
			        signature.update(raw1);
			        byte[] signatureBytes = signature.sign();

					// sending data
					File file = new File("encrypted2.msg");
					ObjectOutputStream oout = new ObjectOutputStream(new FileOutputStream(file));
					oout.writeObject(raw1);
					oout.close();
					
					//sending signature
			        File pile = new File("sigS");
			        ObjectOutputStream ooutSC = new ObjectOutputStream(new FileOutputStream(pile));
					ooutSC.writeObject(signatureBytes);
					ooutSC.close();
					
					

					// The CBC mode needs a 16-byte initialisation vector (IV);
					// aeskey generation
					byte iv[] = stringBytes; // using the first 16 bit sent by client as cbc iv

					byte[] combinedKey = new byte[32];
					System.arraycopy(stringBytes, 0, combinedKey, 0, 16);
					System.arraycopy(randomBytes, 0, combinedKey, 16, 16);
					SecretKeySpec aesKey = new SecretKeySpec(combinedKey, "AES");
					System.out.println(Arrays.toString(combinedKey)); // just to check printed keys

					Thread.sleep(2000); // to wait for hexname to aid synchronization

					// getting the hexname
					DataInputStream dex = new DataInputStream(new FileInputStream("hexname"));
					byte[] fileBytes = dex.readAllBytes();// to read file sent by client
					// test content of file if was wrong/ bad
					String sp = new String(fileBytes, "UTF8"); // not s = b.toString()
					System.out.println(sp);

					// the way the file is save, we need to remove first empty spaces
					// character
					String getRealHex = sp.substring(2, sp.length());
					System.out.println(getRealHex);

					// to read /hexnamed in digest
					DataInputStream pex = new DataInputStream(new FileInputStream(getRealHex));
					byte[] fileBytesInHex = pex.readAllBytes();

					// decrypting
					Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
					cipher2.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
					byte[] decryptedBytes = cipher.doFinal(fileBytesInHex);

					// to check what wad dcrpyted
					String check = new String(decryptedBytes, "UTF8"); // not s = b.toString()
					System.out.println(check);

					// Save the decrypted content locally
					// reading the sent naming convention from client

					File fileTBS = new File(getRealHex);
					FileOutputStream fl = new FileOutputStream(fileTBS);
					try (DataOutputStream outl = new DataOutputStream(fl)) { // saving with file with hashed name
						outl.writeUTF(check); // writting the decryted data to the file
						outl.flush();
						outl.close();
					}

					try {
						Files.copy(fileTBS.toPath(), new File(newFolder, fileTBS.getName()).toPath());
						// the file was created and move to server directory
					} catch (IOException e) {
						e.printStackTrace();
					}

				}

			}
		}
	}
}
