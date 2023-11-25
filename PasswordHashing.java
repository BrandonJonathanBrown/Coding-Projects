import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.lang.Runnable;

public class PasswordHashing implements Runnable {

    public static void main(String[] args) {
        Thread thread = new Thread(new PasswordHashing());
        thread.start();
    }

    private static String generateHash(String password, String salt) {
        String generatedHash = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes());
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            generatedHash = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating hash: " + e.getMessage());
        }
        return generatedHash;
    }

    private static String getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    @Override
    public void run() {
        Scanner input = new Scanner(System.in);
        System.out.print("Enter a password: ");
        String password = input.nextLine();

        if (password.length() < 8) {
            System.out.println("Password must be at least 8 characters long.");
            return;
        }

        String salt = getSalt();
        String hashedPassword = generateHash(password, salt);

        password = null;

        System.out.println("Original Password: " + password);
        System.out.println("Salt: " + salt);
        System.out.println("Hashed Password: " + hashedPassword);
    }
}
