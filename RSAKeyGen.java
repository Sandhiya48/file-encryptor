import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyGen {
    public static void main(String[] args) {
        try {
            // Generate a key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // You can adjust the key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Save the public key to publickey.pem
            PublicKey publicKey = keyPair.getPublic();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            try (FileOutputStream fos = new FileOutputStream("publickey.pem")) {
                fos.write(x509EncodedKeySpec.getEncoded());
            }

            // Save the private key to privatekey.pem
            PrivateKey privateKey = keyPair.getPrivate();
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            try (FileOutputStream fos = new FileOutputStream("privatekey.pem")) {
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }

            System.out.println("Public and private keys have been generated and saved.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
