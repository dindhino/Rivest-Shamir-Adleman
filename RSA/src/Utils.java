
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Dhino
 *
 * non encryption related methods
 *
 */
public class Utils {

    /**
     * given a list of Strings split each of them in the middle
     *
     * @param messages
     * @return the list of splited strings
     */
    public static List<String> splitMessages(List<String> messages) {
        List<String> splitedMessages = new ArrayList<>(messages.size() * 2);
        messages.stream().forEach((message) -> {
            int half = (int) Math.ceil(((double) message.length()) / ((double) 2));
            splitedMessages.add(message.substring(0, half));
            if (half < message.length()) {
                splitedMessages.add(message.substring(half, message.length()));
            }
        });

        return splitedMessages;

    }

    public static String bigIntegerToString(List<BigInteger> list) {
        StringBuilder plainText = new StringBuilder();
        list.stream().forEach((bigInteger) -> {
            plainText.append(new String(bigInteger.toByteArray()));
        });
        return plainText.toString();
    }

    /**
     *
     * @param list
     * @return decimal representation of encrypted/decrypted the message bytes
     */
    public static String bigIntegerSum(List<BigInteger> list) {
        BigInteger result = new BigInteger("0");
        for (BigInteger bigInteger : list) {
            result = result.add(bigInteger);
        }
        return result.toString();
    }

}
