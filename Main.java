import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner jaga = new Scanner(System.in);
        try {
            System.out.println("Enter a password for encryption/decryption:");
            String password = jaga.nextLine();
            EncryptionDecryption ed = new EncryptionDecryption(password);

            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("Choose an option (1 or 2):");
            int choice = jaga.nextInt();
            jaga.nextLine(); 

            switch (choice) {
                case 1:
                    System.out.println("Enter text to encrypt:");
                    String plainText = jaga.nextLine();
                    String encryptedText = ed.encrypt(plainText);
                    System.out.println("Encrypted text: " + encryptedText);
                    break;
                case 2:
                    System.out.println("Enter text to decrypt:");
                    String encryptedInput = jaga.nextLine(); 
                    String decryptedText = ed.decrypt(encryptedInput);
                    System.out.println("Decrypted text: " + decryptedText);
                    break;
                default:
                    System.out.println("Invalid option. Please choose 1 or 2.");
                    break;
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
        } finally {
            jaga.close();
        }
    }
}
