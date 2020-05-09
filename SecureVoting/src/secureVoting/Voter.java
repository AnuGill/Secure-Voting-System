package secureVoting;

import java.math.BigInteger;

public class Voter {
	static BigInteger[] publicKeyCLA = {new BigInteger("3"), new BigInteger("28651327031137471")}; // 3, 28651327031137471
	static BigInteger[] publicKeyCTF = {new BigInteger("3"), new BigInteger("773978785583629")};; //3, 773978785583629
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];
	
	private int voterId;

	public int getVoterId() {
		return voterId;
	}

	public void setVoterId(int voterId) {
		this.voterId = voterId;
	}

	
	public Voter(int id) {
		setVoterId(id);
	}
	
	public static void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("573259433"), new BigInteger("15485867"));
		myPublicKey[0] = keys[0]; //e
		myPrivateKey[0] = keys[1]; //d
		myPublicKey[1] = myPrivateKey[1]= keys[2]; //n
	}
	
	public void castVote(String vote) {
		CLA cla = new CLA();
		BigInteger t = new BigInteger(getVoterId()+"");
		
		BigInteger encrypted = (t).modPow(publicKeyCLA[0], publicKeyCLA[1]);
		
		BigInteger myValidationNum = cla.getValidationNum(encrypted);
		BigInteger decryptedValidNum = (myValidationNum).modPow(myPrivateKey[0], myPrivateKey[1]);
		
		
		CTF ctf = new CTF();
		BigInteger encryptedValidNum = (decryptedValidNum).modPow(publicKeyCTF[0], publicKeyCTF[1]);
		byte[] m = vote.getBytes();
		BigInteger encryptedVote;
		BigInteger[] arr = new BigInteger[m.length];
		for(int i = 0; i < m.length; i++) {
			t = new BigInteger(m[i]+"");
			encryptedVote = (t).modPow(publicKeyCTF[0], publicKeyCTF[1]);
			arr[i] = encryptedVote;
		}
		ctf.vote(encryptedValidNum, arr);
	}
	
	public static void main(String[] args) {
		generateMyKeys();
		if(args[0].equals("over")) {
			CTF.printResult();
			return;
		}
		Voter voter = new Voter(Integer.parseInt(args[0]));
		voter.castVote(args[1]);
	}

}
