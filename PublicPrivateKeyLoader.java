import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicPrivateKeyLoader {
    public static void main(String[] args) {
        // Đường dẫn tới tệp chứa khóa công khai
        String publicKeyPath = "Pub1.pem";
        // Đường dẫn tới tệp chứa khóa bí mật
        String privateKeyPath = "Priv1.pem";

        PublicPrivateKeyLoader loaderPub = new PublicPrivateKeyLoader();
        PublicPrivateKeyLoader loaderPriv = new PublicPrivateKeyLoader();
        try {
            PublicKey keyPub = loaderPub.loadPublicKey(publicKeyPath);
            System.out.println(keyPub.toString());
            System.out.println("=======================================");
            PrivateKey keyPriv = loaderPriv.loadPrivateKey(privateKeyPath);
            System.out.println(keyPriv.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //hello is just an update
    /**
     * This method loads a file from the classpath and returns it as a String.
     * 
     * @param fileName
     * @return
     * @throws IOException
     */

     private static String readFile(final String fileName) throws IOException {
        ClassLoader classLoader = PublicPrivateKeyLoader.class.getClassLoader();
        URL resource = classLoader.getResource(fileName);

        if (resource == null) {
            throw new FileNotFoundException("File not found: " + fileName);
        }

        File file = new File(resource.getFile());
        
        if (!file.exists()) {
            throw new FileNotFoundException("File not found: " + fileName);
        }

        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * This methos load the RSA private key from a PKCS#8 PEM file.
     * 
     * @param pemFilename
     * @return
     * @throws Exception
     */

     private static PublicKey loadPemRsaPublicKey(String pemFilename) throws Exception {
        String pemString = readFile(pemFilename);

        String publicKeyPEM = pemString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                // .replace("\\s", "")
                // .replaceAll(System.lineSeparator(), "")
                .replace("\n", "")
                .replace("\r", "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return rsaKeyFactory.generatePublic(keySpec);
     }

     private static PrivateKey loadPemRsaPrivateKey(String pemFilename) throws Exception {
        String pemString = readFile(pemFilename);

        String privateKeyPEM = pemString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                // .replaceAll("\\s", "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
     }

     //================================================================
     public PublicKey loadPublicKey(String file) throws Exception {
        return loadPemRsaPublicKey(file);
     }

     public PrivateKey loadPrivateKey(String file) throws Exception {
        return loadPemRsaPrivateKey(file);
     }
}