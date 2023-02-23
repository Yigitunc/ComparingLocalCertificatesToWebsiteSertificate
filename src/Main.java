import javax.net.ssl.HttpsURLConnection;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;

public class Main {
    public static void main(String[] args) throws Exception {

        String path = "C:\\your\\path\\to\\keystore,keystores";
        URL url = new URL("https://help.sap.com/docs/");
        boolean Result = compareCertificates(path,url);
        if (Result == true)
            System.out.println("You have the sertificate");
        else
            System.out.println("You dont have sertificate");

    }

    public static String getFingerprint(byte[] data) throws Exception {
        // SHA-1 FINGERPRINT, IF YOU WANT YOU CAN GET OTHER FINGERPRINTS LIKE MD5 OR SHA-224...
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(data);
        byte[] digest = messageDigest.digest();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            stringBuilder.append(String.format("%02x", digest[i]));
            if (i < digest.length - 1)
                stringBuilder.append(":");
        }
        return stringBuilder.toString();
    }

    public static String[] getLocalKeystores(String path){

        File directoryPath = new File(path);
        String contents[] = directoryPath.list();
        String[] keystoreFiles = new String[contents.length];

        // Put these sertificates and their paths in one String Array
        for (int i = 0; i < contents.length; i++)
            keystoreFiles[i] = path + "\\" + contents[i];
        return keystoreFiles;
    }

    public static boolean compareCertificates(String path, URL url) throws Exception {

        String[] keystoreFiles = getLocalKeystores(path);
        String keystorePassword = "your keystore password";
        KeyStore keystore = KeyStore.getInstance("JKS"); // Keystore type

        int count = 0;

        // Website you want to go
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();

        for (String keystoreFile : keystoreFiles) {

            FileInputStream in = new FileInputStream(keystoreFile);
            keystore.load(in, keystorePassword.toCharArray());
            in.close();
            Enumeration<String> aliases = keystore.aliases();

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();
                Certificate yourCert = keystore.getCertificate(alias);
                byte[] yourFingerPrints = yourCert.getEncoded();
                String yourFingerPrint = getFingerprint(yourFingerPrints);

                for (Certificate siteCertf : certs) {
                    System.out.println("---------- BETWEEN CERTIFICATES ---------");
                    byte[] siteFingerPrints = siteCertf.getEncoded();
                    String siteFingerPrint = getFingerprint(siteFingerPrints);
                    System.out.println("YOUR FINGERPRINT = " + yourFingerPrint);
                    System.out.println("WEB  FINGERPRINT = " + siteFingerPrint);
                    if (yourFingerPrint.equals(siteFingerPrint))
                        count++;
                }
            }
        }
        conn.disconnect();
        if (count > 0)
            return true;
        else
           return false;
    }
}