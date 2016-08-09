
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
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        BigInteger p;
        BigInteger q;
        BigInteger e;
        final String message;
        boolean isFile = false;
        if (args.length != 4) {//at leat four parametter should be given
            p = new BigInteger("5700734181645378434561188374130529072194886062117");
            q = new BigInteger("35894562752016259689151502540913447503526083241413");
            e = new BigInteger("33445843524692047286771520482406772494816708076993");
            message = "RSA is the algorithm used by modern computers to encrypt and decrypt messages.\n"
                    + "It is an asymmetric cryptographic algorithm.\n"
                    + "Asymmetric means that there are two different keys.\n"
                    + "This is also called public key cryptography, because one of them can be given to everyone.\n"
                    + "The other key must be kept private.\n"
                    + "It is based on the fact that finding the factors of an integer is hard (the factoring problem).\n"
                    + "RSA stands for Ron Rivest, Adi Shamir and Leonard Adleman, who first publicly described it in 1978.\n"
                    + "A user of RSA creates and then publishes the product of two large prime numbers, along with an auxiliary value, as their public key.\n"
                    + "The prime factors must be kept secret.\n"
                    + "Anyone can use the public key to encrypt a message, but with currently published methods,\n"
                    + "if the public key is large enough, only someone with knowledge of the prime factors can feasibly decode the message.";

//            below are also valid primes
//            p = new BigInteger("61"); 
//            q = new BigInteger("53");
//            e = new BigInteger("17");
        } else {
            p = new BigInteger(args[0]);
            q = new BigInteger(args[1]);
            e = new BigInteger(args[2]);
            if (args[3].contains("file:")) {
                isFile = true;
                message = args[3].substring(5);
            } else {
                message = args[3];
            }
        }

        RSA RSA = new RSAImpl(p, q, e);
        System.out.println(RSA);

        List<BigInteger> encryption;
        List<BigInteger> signed;
        List<BigInteger> decimalMessage;
        if (isFile) {
            encryption = RSA.encryptFile(message);
            signed = RSA.signFile(message);
            decimalMessage = RSA.fileToDecimal(message);
        } else {
            encryption = RSA.encryptMessage(message);
            signed = RSA.signMessage(message);
            decimalMessage = RSA.messageToDecimal(message);
        }

        List<BigInteger> decrypt = RSA.decrypt(encryption);
        List<BigInteger> verify = RSA.verify(signed);
        System.out.println("");
        System.out.println("");
        System.out.println("======================== Message (plain text) ========================\n" + Utils.bigIntegerToString(decimalMessage));
        System.out.println("");
        System.out.println("======================== Message (decimal) ========================\n" + Utils.bigIntegerSum(decimalMessage));
        System.out.println("");
        System.out.println("======================== Encripted (decimal) ========================\n" + Utils.bigIntegerSum(encryption));
        System.out.println("");
        System.out.println("======================== Decrypted (decimal) ========================\n" + Utils.bigIntegerSum(decrypt));
        System.out.println("");
        System.out.println("======================== Decrypted (plain text) ========================\n" + Utils.bigIntegerToString(decrypt));
        System.out.println("");
        System.out.println("======================== Signed (decimal) ========================\n" + Utils.bigIntegerSum(signed));
        System.out.println("");
        System.out.println("======================== Verified (decimal) ========================\n" + Utils.bigIntegerSum(verify));
        System.out.println("");
        System.out.println("======================== Verified (plain text) ========================\n" + Utils.bigIntegerToString(verify));
    }
}
