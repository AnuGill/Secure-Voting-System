package secureVoting;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CTF {
	
	static BigInteger[] publicKeyVoter = {new BigInteger("5"), new BigInteger("8877419335933411")}; //5, 8877419335933411
	static BigInteger[] publicKeyCLA = {new BigInteger("3"), new BigInteger("28651327031137471")}; //3, 28651327031137471
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];
	static Map<String, Integer> tally = new HashMap<>();
	static Set<Integer> validationNums = new HashSet<>();

	public static void main(String[] args) {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("49979687"), new BigInteger("15485867"));
		myPublicKey[0] = keys[0]; //e
		myPrivateKey[0] = keys[1]; //d
		myPublicKey[1] = myPrivateKey[1]= keys[2]; //n
		
	}
	
	public void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("49979687"), new BigInteger("15485867"));
		myPublicKey[0] = keys[0]; //e
		myPrivateKey[0] = keys[1]; //d
		myPublicKey[1] = myPrivateKey[1]= keys[2]; //n
	}
	
	public void vote(BigInteger validationNum, BigInteger[] vote){
		BigInteger decryptedValidNum = (validationNum).modPow(myPrivateKey[0], myPrivateKey[1]);
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < vote.length; i++) {
			BigInteger t = new BigInteger(vote[i]+"");
			BigInteger decrypted = (t).modPow(myPrivateKey[0], myPrivateKey[1]);
			sb.append((char) (decrypted.intValue()));
		}
		String decryptedVote = sb.toString();
		if(validationNums.contains(decryptedValidNum.intValue())) {
			tally.put(decryptedVote, tally.getOrDefault(decryptedVote, 0) + 1);
		}
	}
	
	public void updateValidationNums(BigInteger validationNum) {
		generateMyKeys();
		BigInteger decrypted = (validationNum).modPow(myPrivateKey[0], myPrivateKey[1]);
		validationNums.add(decrypted.intValue());
	}
	
	public static void printResult() {
		if(tally.isEmpty()) System.out.println("No votes have been registered yet!");
		for (Map.Entry<String,Integer> entry : tally.entrySet())  
            System.out.println("Candidate = " + entry.getKey() + 
                             ", Vote Count = " + entry.getValue()); 
	}

}
