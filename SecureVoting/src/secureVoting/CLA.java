package secureVoting;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CLA {
	
	static BigInteger[] publicKeyVoter = {new BigInteger("5"), new BigInteger("8877419335933411")}; //5, 8877419335933411
	static BigInteger[] publicKeyCTF = {new BigInteger("3"), new BigInteger("773978785583629")}; //3, 773978785583629
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];
	static Map<Integer, Integer> voterList = new HashMap<>();
	static Set<Integer> generatedRandomNums = new HashSet<>();

	public static void main(String[] args) {
		
		BigInteger[] keys = RSA.generateKeys(new BigInteger("573259433"), new BigInteger("49979687"));
		myPublicKey[0] = keys[0]; //e
		myPrivateKey[0] = keys[1]; //d
		myPublicKey[1] = myPrivateKey[1]= keys[2]; //n
	}
	
	public void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("573259433"), new BigInteger("49979687"));
		myPublicKey[0] = keys[0]; //e
		myPrivateKey[0] = keys[1]; //d
		myPublicKey[1] = myPrivateKey[1]= keys[2]; //n
	}
	
	public BigInteger getValidationNum(BigInteger voterId) {
		generateMyKeys();
		int validationNum = 0;
		do {
			validationNum = (int) (Math.random() * 10000); 
		}while(!generatedRandomNums.add(validationNum));
		BigInteger decrypted = (voterId).modPow(myPrivateKey[0], myPrivateKey[1]);
		voterList.put(decrypted.intValue(), validationNum);
		CTF ctf = new CTF();
		BigInteger validNum = new BigInteger(validationNum+"");
		BigInteger encryptedValidNum = (validNum).modPow(publicKeyCTF[0], publicKeyCTF[1]);
		
		BigInteger encryptedValidNumForVoter = (validNum).modPow(publicKeyVoter[0], publicKeyVoter[1]);
		ctf.updateValidationNums(encryptedValidNum);
		return encryptedValidNumForVoter;
	}
		

}
