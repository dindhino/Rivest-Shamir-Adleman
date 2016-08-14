
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 * Implementation of Rivest-Shamir-Adleman (RSA) algorithm
 * http://en.wikipedia.org/wiki/RSA_(cryptosystem)
 *
 * @author Dhino
 */
public class RSAImpl implements RSA {

    private final static BigInteger ONE = new BigInteger("1");
    private final BigInteger privateKey;
    private final BigInteger e; //part of public key - relative prime of phi 
    private final BigInteger modulus; //part of public key obtained with n = p*q
    private final BigInteger p; //prime
    private final BigInteger q; //prime
    private final BigInteger phi;// obtained with phi = (p-1)*(q-1)

    RSAImpl(BigInteger p, BigInteger q, BigInteger e) {

        phi = (p.subtract(ONE)).multiply(q.subtract(ONE)); //phi = (p-1)*(q-1) 
        this.e = e;
        this.p = p;
        this.q = q;
        modulus = p.multiply(q);
        privateKey = e.modInverse(phi);//d = Math.pow(e,-1) mod phi, private key is obtained with the multiplative inverse of 'e' mod 'phi'
    }

    @Override
    public BigInteger encrypt(BigInteger bigInteger) {
        if (isModulusSmallerThanMessage(bigInteger)) {
            throw new IllegalArgumentException("Could not encrypt - message bytes are greater than modulus");
        }
        return bigInteger.modPow(e, modulus);
    }

    @Override
    public List<BigInteger> encryptMessage(final String message) {
        List<BigInteger> toEncrypt = new ArrayList<>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toEncrypt = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toEncrypt.add((messageBytes));
        }
        List<BigInteger> encrypted = new ArrayList<>();
        for (BigInteger bigInteger : toEncrypt) {
            encrypted.add(this.encrypt(bigInteger));
        }
        return encrypted;
    }

    @Override
    public List<BigInteger> encryptFile(String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line;
        List<BigInteger> encription = new ArrayList<>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));

            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
                encription.addAll(this.encryptMessage(line));
            }

        } catch (IOException ex) {
            Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return encription;

    }

    @Override
    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(privateKey, modulus);
    }

    @Override
    public List<BigInteger> decrypt(List<BigInteger> encryption) {
        List<BigInteger> decryption = new ArrayList<>();
        encryption.stream().forEach((bigInteger) -> {
            decryption.add(this.decrypt(bigInteger));
        });
        return decryption;
    }

    @Override
    public BigInteger sign(BigInteger bigInteger) {
        return bigInteger.modPow(privateKey, modulus);
    }

    @Override
    public List<BigInteger> signMessage(final String message) {
        List<BigInteger> toSign = new ArrayList<>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toSign = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toSign.add((messageBytes));
        }
        List<BigInteger> signed = new ArrayList<>();
        for (BigInteger bigInteger : toSign) {
            signed.add(this.sign(bigInteger));
        }
        return signed;
    }

    @Override
    public List<BigInteger> signFile(String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line;
        List<BigInteger> signedLines = new ArrayList<>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));

            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
                signedLines.addAll(this.signMessage(line));
            }

        } catch (IOException ex) {
            Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return signedLines;
    }

    @Override
    public BigInteger Verify(BigInteger signedMessage) {
        return signedMessage.modPow(e, modulus);
    }

    @Override
    public List<BigInteger> verify(List<BigInteger> signedMessages) {
        List<BigInteger> verification = new ArrayList<>();
        signedMessages.stream().forEach((bigInteger) -> {
            verification.add(this.Verify(bigInteger));
        });
        return verification;
    }

    @Override
    public boolean isVerified(BigInteger signedMessage, BigInteger message) {
        return this.Verify(signedMessage).equals(message);
    }

    /**
     * ensures that blocks to encrypt are smaller than modulus
     *
     * @param messages list of blocks to be splited at half recursively
     * @return list of valid blocks
     *
     */
    private List<BigInteger> getValidEncryptionBlocks(List<String> messages) {
        List<BigInteger> validBlocks = new ArrayList<>();
        BigInteger messageBytes = new BigInteger(messages.get(0).getBytes());
        if (!isModulusSmallerThanMessage(messageBytes)) {
            messages.stream().forEach((msg) -> {
                validBlocks.add(new BigInteger(msg.getBytes()));
            });
            return validBlocks;
        } else {//message is bigger than modulus so we have to split it
            return getValidEncryptionBlocks(Utils.splitMessages(messages));
        }

    }

    @Override
    public List<BigInteger> messageToDecimal(final String message) {
        List<BigInteger> toDecimal = new ArrayList<>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toDecimal = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toDecimal.add((messageBytes));
        }
        List<BigInteger> decimal = new ArrayList<>();
        for (BigInteger bigInteger : toDecimal) {
            decimal.add(bigInteger);
        }
        return decimal;
    }

    @Override
    public List<BigInteger> fileToDecimal(final String filePath) {
        BufferedReader br = null;
        FileInputStream fis = null;
        String line;
        List<BigInteger> decimalLines = new ArrayList<>();
        try {
            fis = new FileInputStream(new File(filePath));
            br = new BufferedReader(new InputStreamReader(fis, Charset.forName("UTF-8")));

            while ((line = br.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
                decimalLines.addAll(this.messageToDecimal(line));
            }

        } catch (IOException ex) {
            Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (br != null) {
                    br.close();
                }

            } catch (IOException ex) {
                Logger.getLogger(RSAImpl.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return decimalLines;
    }

    private boolean isModulusSmallerThanMessage(BigInteger messageBytes) {
        return modulus.compareTo(messageBytes) == -1;
    }

    @Override
    public String toString() {
        String s = "";
        s += "(*) user inputs" + "\n";
        s += "p                                  = " + p + " (*)\n";
        s += "q                                  = " + q + " (*)\n";
        s += "modulus (n = p*q)                  = " + modulus + "\n";
        s += "totient phi(n) = ((p-1)*(q-1))     = " + phi + "\n";
        s += "e (choose e > 1 coprime to phi(n)) = " + e + " (*)\n";
        s += "private (d, d*e = 1 (mod phi(n)))  = " + privateKey + "\n\n";

        s += "public key is :\n";
        s += "n = " + modulus + "\n";
        s += "e = " + e + " \n";
        s += "  -> enc = Math.pow(message,e) mod n" + "\n\n";

        s += "private key is :\n";
        s += "n = " + modulus + "\n";
        s += "d = " + privateKey + " \n";
        s += "  -> message = Math.pow(enc,d) mod n" + "\n";
        return s;
    }

}
