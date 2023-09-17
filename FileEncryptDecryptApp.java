import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

public class FileEncryptDecryptApp extends JFrame {
    private JButton encryptButton;
    private JButton decryptButton;
    private JTextArea logTextArea;

    private File selectedFile;
    private JFileChooser fileChooser;

    public FileEncryptDecryptApp() {
        // Initialize UI components and layout
        this.setTitle("File Encryption/Decryption App");
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setSize(600, 400);

        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        fileChooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
        fileChooser.setFileFilter(filter);

        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logTextArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile();
                if (selectedFile != null) {
                    try {
                        String inputFilePath = selectedFile.getAbsolutePath();
                        byte[] fileData = Files.readAllBytes(Paths.get(inputFilePath));

                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(256);
                        SecretKey aesKey = keyGen.generateKey();

                        byte[] encryptedData = encryptAES(fileData, aesKey);

                        String outputFilePath = inputFilePath + ".enc";
                        Files.write(Paths.get(outputFilePath), encryptedData);

                        // Encrypt AES key using RSA public key
                        PublicKey rsaPublicKey = loadRSAPublicKey("publickey.pem"); // Replace with your key file
                        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), rsaPublicKey);

                        saveKeyToFile("cipherkey.json", encryptedAESKey);

                        logTextArea.append("Encryption complete. Encrypted file saved as: " + outputFilePath + "\n");
                    } catch (Exception ex) {
                        logTextArea.append("Encryption failed. " + ex.getMessage() + "\n");
                    }
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile();
                if (selectedFile != null) {
                    try {
                        String inputFilePath = selectedFile.getAbsolutePath();
                        byte[] encryptedData = Files.readAllBytes(Paths.get(inputFilePath));

                        // Decrypt AES key using RSA private key
                        PrivateKey rsaPrivateKey = loadRSAPrivateKey("privatekey.pem"); // Replace with your key file
                        byte[] aesKeyBytes = decryptRSA(loadKeyFromFile("cipherkey.json"), rsaPrivateKey);

                        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");

                        byte[] decryptedData = decryptAES(encryptedData, aesKey);

                        String outputFilePath = inputFilePath.replace(".enc", "_dec.txt");
                        Files.write(Paths.get(outputFilePath), decryptedData);

                        logTextArea.append("Decryption complete. Decrypted file saved as: " + outputFilePath + "\n");
                    } catch (Exception ex) {
                        logTextArea.append("Decryption failed. " + ex.getMessage() + "\n");
                    }
                }
            }
        });

        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        this.add(panel);
    }

    private void selectFile() {
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
        }
    }

    private byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] decryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }



    private byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private PublicKey loadRSAPublicKey(String publicKeyFilePath) throws Exception {
        byte[] publicKeyBytes = loadKeyFromFile(publicKeyFilePath);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey loadRSAPrivateKey(String privateKeyFilePath) throws Exception {
        byte[] privateKeyBytes = loadKeyFromFile(privateKeyFilePath);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private byte[] loadKeyFromFile(String keyFilePath) throws IOException {
        Path path = Paths.get(keyFilePath);
        return Files.readAllBytes(path);
    }

    private void saveKeyToFile(String keyFilePath, byte[] keyData) throws IOException {
        Path path = Paths.get(keyFilePath);
        Files.write(path, keyData);
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        SwingUtilities.invokeLater(() -> {
            FileEncryptDecryptApp app = new FileEncryptDecryptApp();
            app.setVisible(true);
        });
    }
}

