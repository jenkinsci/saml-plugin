package org.jenkinsci.plugins.saml;

import org.apache.commons.lang.math.NumberUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Pac4j requires to set a keystore for encryption operations,
 * the plugin generate an automatic keystore or it it is not possible uses a keystore bundle on the plugin.
 * The generated key is valid for a day, when expires it is generated a new one on the same keystore.
 * A new key store is created when you restart Jenkins or if is not possible to access to the created.
 *
 * @see <a href="http://www.pac4j.org/1.9.x/docs/clients/saml.html">pac4j - Authentication mechanisms: SAML</a>
 */
public class BundleKeyStore {
    public static final String PAC4J_DEMO_PASSWD = "pac4j-demo-passwd";
    public static final String PAC4J_DEMO_KEYSTORE = "resource:samlKeystore.jks";
    public static final String PAC4J_DEMO_ALIAS = "pac4j-demo";
    public static final String DEFAULT_KEY_ALIAS = "SAML-generated-keyPair";
    public static final String KEY_ALG = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String PROVIDER = "BC";
    public static final String KEY_VALIDITY_PROPERTY = BundleKeyStore.class.getName() + ".validity";
    public static final Long KEY_VALIDITY = 365L;

    private static final Logger LOG = Logger.getLogger(BundleKeyStore.class.getName());

    private String keystorePath = PAC4J_DEMO_KEYSTORE;
    private String ksPassword = PAC4J_DEMO_PASSWD;
    private String ksPkPassword = PAC4J_DEMO_PASSWD;
    private String ksPkAlias = PAC4J_DEMO_ALIAS;
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

            if (keystore == null) {
                keystore = File.createTempFile("saml-jenkins-keystore-", ".jks");
                keystorePath = "file:" + keystore.getPath();
            }

            if (PAC4J_DEMO_KEYSTORE.equals(ksPassword)) {
                ksPassword = generatePassword();
                ksPkPassword = generatePassword();
            }
            ksPkAlias = DEFAULT_KEY_ALIAS;
            KeyStore ks = loadKeyStore(keystore, ksPassword);
            KeyPair keypair = generate(2048);
            X509Certificate[] chain = createCertificateChain(keypair);
            ks.setKeyEntry(ksPkAlias, keypair.getPrivate(), ksPkPassword.toCharArray(), chain);
            saveKeyStore(keystore, ks, ksPassword);
            LOG.warning("Using automatic generated keystore : " + keystorePath);
        } catch (Exception e) {
            LOG.warning("Using bundled keystore : " + e.getMessage());
            ksPassword = PAC4J_DEMO_PASSWD;
            ksPkPassword = PAC4J_DEMO_PASSWD;
            keystorePath = PAC4J_DEMO_KEYSTORE;
            ksPkAlias = PAC4J_DEMO_ALIAS;
        }
    }

    /**
     * create an array with the certificate created from the key pair.
     *
     * @param keypair key pair origin.
     * @return an array of x509 certificates.
     * @throws IOException              @see IOException
     * @throws CertificateException     @see CertificateException
     * @throws InvalidKeyException      @see InvalidKeyException
     * @throws SignatureException       @see SignatureException
     * @throws NoSuchAlgorithmException @see NoSuchAlgorithmException
     * @throws NoSuchProviderException  @see NoSuchProviderException
     */
    private X509Certificate[] createCertificateChain(KeyPair keypair)
            throws IOException, CertificateException, InvalidKeyException, SignatureException,
            NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        X509Certificate[] chain = new X509Certificate[1];
        Long validity = NumberUtils.toLong(System.getProperty(KEY_VALIDITY_PROPERTY), KEY_VALIDITY);
        chain[0] = generateCertificate("cn=SAML-jenkins", new Date(),  TimeUnit.DAYS.toSeconds(validity), keypair);
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
        try (InputStream in = new FileInputStream(keystore)) {
            ks.load(in, password.toCharArray());
        } catch (IOException e) {
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
    private KeyPair generate(int keySize) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALG, PROVIDER);
        SecureRandom prng = new SecureRandom();
        keyGen.initialize(keySize, prng);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    /**
     * generate a x509 certificate from a key pair.
     *
     * @param dnName    domain name to the certificate subject and issuer.
     * @param notBefore date when the validity begins.
     * @param validity  number of days that it is valid.
     * @param keyPair   key pair to generate the certificate.
     * @return a certificate x509.
     * @throws CertIOException           @see CertIOException
     * @throws OperatorCreationException @see OperatorCreationException
     * @throws CertificateException      @see CertificateException
     * @throws NoSuchAlgorithmException  @see NoSuchAlgorithmException
     */
    private X509Certificate generateCertificate(String dnName, Date notBefore, long validity, KeyPair keyPair)
            throws CertIOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException {

        X500Name dn = new X500Name(dnName);
        Date notAfter = new Date(notBefore.getTime() + validity * 1000L);
        dateValidity = notAfter;
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                new BigInteger(160, new SecureRandom()),
                notBefore,
                notAfter,
                dn,
                keyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        ASN1Encodable[] subjectAltNAmes = {new GeneralName(GeneralName.dNSName, dnName)};
        builder.addExtension(Extension.subjectAlternativeName, false,
                GeneralNames.getInstance(new DERSequence(subjectAltNAmes)));

        X509CertificateHolder certHldr = builder.build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate()));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHldr);

        return cert;
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

    public String getKsPkAlias() {
        return ksPkAlias;
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
