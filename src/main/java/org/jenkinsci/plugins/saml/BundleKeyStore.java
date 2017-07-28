package org.jenkinsci.plugins.saml;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.logging.Logger;

/**
 * Pac4j requires to set a keystore for encryption operations,
 * the plugin generate an automatic keystore or it it is not possible uses a keystore bundle on the plugin.
 * The generated key is valid for a day, when expires it is generated a new one on the same keystore.
 * A new key store is created when you restart Jenkins or if is not possible to access to the created.
 * http://www.pac4j.org/1.9.x/docs/clients/saml.html
 */
public class BundleKeyStore {
    public static final String PAC4J_DEMO_PASSWD = "pac4j-demo-passwd";
    public static final String PAC4J_DEMO_KEYSTORE = "resource:samlKeystore.jks";
    public static final String SIG_ALG = "SHA1WithRSA";
    public static final String KEY_ALG = "RSA";
    public static final Long KEY_VALIDITY = 1 * 24L * 60L * 60L;

    private static final Logger LOG = Logger.getLogger(BundleKeyStore.class.getName());

    private String keystorePath = PAC4J_DEMO_KEYSTORE;
    private String ksPassword = PAC4J_DEMO_PASSWD;
    private String ksPkPassword = PAC4J_DEMO_PASSWD;
    private Date dateValidity;
    private File keystore;

    public BundleKeyStore() {
    }

    /**
     * initialized the keystore, it tries to create a keystore in a file,
     * if it fails load the settings of the demo keystore.
     */
    public synchronized void init() {
        try {

            if(keystore == null){
                keystore = File.createTempFile("saml-jenkins-keystore-", ".jks");
                keystorePath = "file:" + keystore.getPath();
            }

            if(PAC4J_DEMO_KEYSTORE.equals(ksPassword)) {
                ksPassword = generatePassword();
                ksPkPassword = generatePassword();
            }

            KeyStore ks = loadKeyStore(keystore, ksPassword);
            KeyPair keypair = generate(2048);
            X509Certificate[] chain = createCertificateChain(keypair);
            ks.setKeyEntry("SAML-generated-keyPair", keypair.getPrivate(), ksPkPassword.toCharArray(), chain);
            saveKeyStore(keystore, ks, ksPassword);
            LOG.warning("Using automatic generated keystore : " + keystorePath);
        } catch (Exception e) {
            LOG.warning("Using bundled keystore : " + e.getMessage());
            ksPassword = PAC4J_DEMO_PASSWD;
            ksPkPassword = PAC4J_DEMO_PASSWD;
            keystorePath = PAC4J_DEMO_KEYSTORE;
        }
    }

    /**
     * create an array with the certificate created from the key pair.
     *
     * @param keypair key pair origin.
     * @return an array of x509 certificates.
     * @throws IOException              @IOException
     * @throws CertificateException     @CertificateException
     * @throws InvalidKeyException      @InvalidKeyException
     * @throws SignatureException       @SignatureException
     * @throws NoSuchAlgorithmException @NoSuchAlgorithmException
     * @throws NoSuchProviderException  @NoSuchProviderException
     */
    private X509Certificate[] createCertificateChain(KeyPair keypair)
            throws IOException, CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException {
        X500Name x500Name = new X500Name("cn=SAML-jenkins");
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = getSelfCertificate(x500Name, new java.util.Date(), KEY_VALIDITY, keypair);
        return chain;
    }

    /**
     * Create a new keystore.
     *
     * @param keystore the keystore object.
     * @param password the password to set to the keystore.
     * @return the new keystore.
     * @throws KeyStoreException        @see KeyStoreException
     * @throws IOException              @see IOException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     * @throws CertificateException     @see CertificateException
     */
    private KeyStore initKeyStore(File keystore, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password.toCharArray());
        saveKeyStore(keystore, ks, password);
        return ks;
    }

    /**
     * save the keystore to disk.
     *
     * @param keystore file to save the keystore.
     * @param ks       the keystore object.
     * @param password the password to set to the keystore.
     * @throws KeyStoreException        @see KeyStoreException
     * @throws IOException              @see IOException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     * @throws CertificateException     @see CertificateException
     */
    private void saveKeyStore(File keystore, KeyStore ks, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        FileOutputStream fos;
        fos = new FileOutputStream(keystore);
        try {
            ks.store(fos, password.toCharArray());
        } finally {
            fos.close();
        }
    }

    /**
     * load a keystore from a file. if it fails create a new keystore.
     *
     * @param keystore path to the keystore.
     * @param password password of the keystore.
     * @return the keystore loaded.
     * @throws KeyStoreException        @see KeyStoreException
     * @throws IOException              @see IOException
     * @throws CertificateException     @see CertificateException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     */
    private KeyStore loadKeyStore(File keystore, String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try{
            InputStream in = new FileInputStream(keystore);
            try {
                ks.load(in, password.toCharArray());
            } finally {
                in.close();
            }
        } catch (Exception e) {
            ks = initKeyStore(keystore, password);
        }
        return ks;
    }

    /**
     * @return a random password.
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     */
    private String generatePassword() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte bytes[] = new byte[256];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * generate an RSA key pair.
     *
     * @param keySize size in bits of the key.
     * @return an RSA key pair.
     * @throws InvalidKeyException      @see InvalidKeyException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     */
    private KeyPair generate(int keySize) throws InvalidKeyException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALG);
        SecureRandom prng = new SecureRandom();
        keyGen.initialize(keySize, prng);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    /**
     * geerate a x509 certificate from a key pair.
     *
     * @param x500Name  general name to the certificate subject and issuer.
     * @param validFrom date when the validity begins.
     * @param validity  number of days that it is valid.
     * @param keyPair   key pair to generate the certificate.
     * @return a certificate x509.
     * @throws CertificateException     @see CertificateException
     * @throws InvalidKeyException      @see InvalidKeyException
     * @throws SignatureException       @see SignatureException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     * @throws NoSuchProviderException  @see NoSuchProviderException
     */
    private X509Certificate getSelfCertificate(X500Name x500Name, Date validFrom, long validity, KeyPair keyPair)
            throws CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            dateValidity = new Date();
            dateValidity.setTime(validFrom.getTime() + validity * 1000L);
            CertificateValidity certValidity = new CertificateValidity(validFrom, dateValidity);
            X509CertInfo certInfo = new X509CertInfo();
            certInfo.set("version", new CertificateVersion(2));
            certInfo.set("serialNumber", new CertificateSerialNumber((new Random()).nextInt() & 2147483647));
            AlgorithmId algo = AlgorithmId.get(SIG_ALG);
            certInfo.set("algorithmID", new CertificateAlgorithmId(algo));
            certInfo.set("subject", x500Name);
            certInfo.set("key", new CertificateX509Key(keyPair.getPublic()));
            certInfo.set("validity", certValidity);
            certInfo.set("issuer", x500Name);

            X509CertImpl certImpl = new X509CertImpl(certInfo);
            certImpl.sign(keyPair.getPrivate(), SIG_ALG);
            return certImpl;
        } catch (IOException e) {
            throw new CertificateEncodingException("getSelfCert: " + e.getMessage());
        }
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKsPassword() {
        return ksPassword;
    }

    public String getKsPkPassword() {
        return ksPkPassword;
    }

    /**
     * @return true if the demo keystore is used.
     */
    public boolean isUsingDemoKeyStore() {
        return PAC4J_DEMO_KEYSTORE.equals(keystorePath);
    }

    /**
     * @return true is the key store is still valid.
     */
    public synchronized boolean isValid() {
        boolean ret = false;
        if (dateValidity != null) {
            Calendar validity = Calendar.getInstance();
            validity.setTime(dateValidity);
            ret = Calendar.getInstance().compareTo(validity) <= 0;
        }
        return ret;
    }
}
