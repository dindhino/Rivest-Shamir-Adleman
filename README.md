# Rivest-Shamir-Adleman
Implementation of Rivest-Shamir-Adleman (RSA) algorithm -> http://en.wikipedia.org/wiki/RSA_(cryptosystem)

<br/>
To run this program you will need to provide four arguments: p, q, e and message where: <br/>
<ul>
<li> p: a prime </li>
<li> q: another prime </li>
<li> e: choose e > 1 coprime to phi(n), phi(n) = (p-1)*(q-1) </li>
<li> message: a String message to be encrypted, decrypted, signed and verified through a digital signed certificate </li>
</ul>

If none of the inputs are provided the following values will be used as default:
<ul>
<li> p: 5700734181645378434561188374130529072194886062117 </li>
<li> q: 35894562752016259689151502540913447503526083241413 </li>
<li> e: 33445843524692047286771520482406772494816708076993 </li>
<li> message: RSA is the algorithm used by modern computers to encrypt and decrypt messages. It is an asymmetric cryptographic algorithm. Asymmetric means that there are two different keys. This is also called public key cryptography, because one of them can be given to everyone. The other key must be kept private. It is based on the fact that finding the factors of an integer is hard (the factoring problem). RSA stands for Ron Rivest, Adi Shamir and Leonard Adleman, who first publicly described it in 1978. A user of RSA creates and then publishes the product of two large prime numbers, along with an auxiliary value, as their public key. The prime factors must be kept secret. Anyone can use the public key to encrypt a message, but with currently published methods, if the public key is large enough, only someone with knowledge of the prime factors can feasibly decode the message. </li>
</ul>

<br/><br/>
Command to run: java -jar RSA.jar "61" "53" "17" "Message to be encrypted, decrypted, signed, and verified"

<br/>
To read from a file, the last argument must be prefixed by a 'file:' plus the path to the file containing the message to be encrypted, decrypted, signed and verified.

Here's an example: java -jar RSA.jar "61" "53" "17" "file:\home\dhino\message.txt"
