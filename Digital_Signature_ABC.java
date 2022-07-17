import javax.security.KeyPair;
import javax.security.KeyPairGenerator;
import javax.security.PrivateKey;
import javax.security.PublicKey;
import javax.security.SecureRandom;
import javax.security.Signature;
import javax.util.Scanner;

import javax.xml.bind.DatatypeConverter;

public class ABC_Keypair_and_Digital_Signature {

    // Signing Algorithm
    private static final String
            SIGNING_ALGORITHM
            = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static Scanner sc;

    // Function to implement Digital signature
    // by passing private key.
    public static byte[] Create_Digital_Signature(
            byte[] input,
            PrivateKey Key)
            throws Exception
    {
        Signature signature
                = Signature.getInstance(
                SIGNING_ALGORITHM);
        signature.initSign(Key);
        signature.update(input);
        return signature.sign();
    }
    // Generating the asymmetric key pair
    public static KeyPair Generate_RSA_KeyPair()
            throws Exception
    {
        SecureRandom secureRandom
                = new SecureRandom();
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator
                .getInstance(RSA);
        keyPairGenerator
                .initialize(
                        2048, secureRandom);
        return keyPairGenerator
                .generateKeyPair();
    }
    // verify digital signature using public key
    public static boolean
    Verify_Digital_Signature(
            byte[] input,
            byte[] signatureToVerify,
            PublicKey key)
            throws Exception
    {
        Signature signature
                = Signature.getInstance(
                SIGNING_ALGORITHM);
        signature.initVerify(key);
        signature.update(input);
        return signature
                .verify(signatureToVerify);
    }

    public static void main(String args[])
            throws Exception
    {

        String input
                = "ABC"
                + " Blockchain Auction";
        KeyPair keyPair
                = Generate_RSA_KeyPair();

        byte[] signature
                = Create_Digital_Signature(
                input.getBytes(),
                keyPair.getPrivate());

        System.out.println(
                "Signature Value:\n "
                        + DatatypeConverter
                        .printHexBinary(signature));

        System.out.println(
                "Verification: "
                        + Verify_Digital_Signature(
                        input.getBytes(),
                        signature, keyPair.getPublic()));
    }
}

