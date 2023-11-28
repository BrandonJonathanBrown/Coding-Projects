import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class Client {
    private static SecretKey secretKey;

    public static void main(String[] args) {
        try {
            // Generate a secret key
            secretKey = generateSecretKey();

            // Create a socket to connect to the server
            Socket socket = new Socket("localhost", 100);

            // Initialize cipher instances
            Cipher encryptCipher = Cipher.getInstance("AES");
            Cipher decryptCipher = Cipher.getInstance("AES");

            // Initialize the ciphers with the secret key
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Create input and output streams for communication
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Start a separate thread to handle incoming messages
            Thread incomingThread = new Thread(() -> {
                try {
                    while (true) {
                        String encryptedMessage = in.readUTF();
                        String decryptedMessage = decrypt(decryptCipher, Base64.getDecoder().decode(encryptedMessage));
                        System.out.println("Server: " + decryptedMessage);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            incomingThread.start();

            // Read messages from the console and send to the server
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            while (true) {
                System.out.print("You: ");
                String message = consoleReader.readLine();
                String encryptedMessage = Base64.getEncoder().encodeToString(encrypt(encryptCipher, message));
                out.writeUTF(encryptedMessage);
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES key size
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(Cipher cipher, String plaintext) {
        try {
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decrypt(Cipher cipher, byte[] ciphertext) {
        try {
            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
