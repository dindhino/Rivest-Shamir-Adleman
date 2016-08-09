
import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Dhino
 */
public interface RSA extends Serializable {

    /**
     * Encrypts a message through enc = Math.pow(message,e) mod n
     * where:
     * enc = encrypted message
     * message = message to be encrypted
     * e = relative prime to phi
     * n = modulo obtained from p*q
     *
     * @param bigInteger
     * @return encrypted message represented by a Java BigInteger
     */
    BigInteger encrypt(BigInteger bigInteger);

    /**
     * Encrypts a message using the encrypt method checking if message blocks
     * are valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#encrypt(java.math.BigInteger)
     * @param message string
     * @return a list of encrypted message blocks where each encrypted block is
     * represented by a Java BigInteger
     */
    List<BigInteger> encryptMessage(final String message);

    /**
     * Encrypts a message through enc = Math.pow(message,e) mod n
     * where:
     * enc = encrypted message
     * message = message to be encrypted
     * e = relative prime to phi
     * n = modulo obtained from p*q
     *
     * @param filePath path to a file containing the message to be encripted
     * @return a BigInteger representing each encrypted file line
     */
    List<BigInteger> encryptFile(String filePath);

    /**
     * Decrypt an encrypted message through message = Math.pow(enc, d) mod n
     * where:
     * message = decrypted message
     * enc = encrypted message
     * d = private key obtained from multiplicative inverse of 'e' mod 'phi'
     * n = modulo obtained from p*q
     *
     * @param encrypted encrypted message
     * @return decrypted message represented by a Java BigInteger type
     */
    BigInteger decrypt(BigInteger encrypted);

    /**
     * Decrypt a list of encrypted messages through message = Math.pow(enc, d) mod n
     * where:
     * message = decrypted message
     * enc = encrypted message
     * d = private key obtained from multiplicative inverse of 'e' mod 'phi'
     * n = modulo obtained from p*q
     *
     * @param encryption encrypted messages represented by a list of Java
     * BigInteger
     * @return list of decrypted message
     */
    List<BigInteger> decrypt(List<BigInteger> encryption);

    /**
     * Digitally signs a message through A = Math.pow(message, d) mod n
     * where:
     * A = signed message
     * message = message to be digitally signed
     * d = private key obtained from multiplicative inverse of 'e' mod 'phi'
     * n = modulo obtained from p*q
     *
     * @param bigInteger
     * @return signed message represented by a Java BigInteger
     */
    BigInteger sign(BigInteger bigInteger);

    /**
     * Signs a message using the sign method checking if message blocks are
     * valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#sign(java.math.BigInteger)
     * @param message string
     * @return a list of signed message blocks where each signed block is
     * represented by a Java BigInteger
     */
    List<BigInteger> signMessage(final String message);

    /**
     * Signs each line of a file using the sign method
     *
     * @see RSA#signMessage(java.lang.String)
     * @param filePath
     * @return a BigInteger representing each signed lines
     */
    List<BigInteger> signFile(String filePath);

    /**
     * verifies a signed message through Math.pow(A, e) mod n = message
     * where:
     * A = signed message
     * e = relative prime to phi
     * n = modulo obtained from p*q
     * message = original message
     *
     * @param signedMessage
     * @return decimal number result from verification , if its equal to the
     * decimal representation of the original message then its successfully
     * verified
     * @see RSA#isVerified(java.math.BigInteger, java.math.BigInteger)
     *
     */
    BigInteger Verify(BigInteger signedMessage);

    /**
     * verifies a list of signed messages through verify method
     *
     * @param signedMessages
     * @return list of verified messages
     * @see RSA#Verify(java.math.BigInteger)
     */
    List<BigInteger> verify(List<BigInteger> signedMessages);

    /**
     * @param signedMessage
     * @param message
     * @return true if decimal representation of the original message matched the decimal representation of the signed message
     * false otherwise
     *
     * @see RSA#Verify(java.math.BigInteger)
     */
    boolean isVerified(BigInteger signedMessage, BigInteger message);

    /**
     * @param message
     * @return decimal representation of the message
     */
    List<BigInteger> messageToDecimal(final String message);

    /**
     * @param filePath
     * @return decimal representation of a file
     */
    List<BigInteger> fileToDecimal(final String filePath);
}
