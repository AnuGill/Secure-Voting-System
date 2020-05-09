package clientServer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CLA implements Runnable {

	static BigInteger[] publicKeyVoter = { new BigInteger("5"), new BigInteger("8877419335933411") }; // 5,
	static BigInteger[] publicKeyCTF = { new BigInteger("3"), new BigInteger("773978785583629") }; // 3, 773978785583629
	static BigInteger[] myPublicKey = new BigInteger[2];
	static BigInteger[] myPrivateKey = new BigInteger[2];
	static Map<Integer, Integer> voterList = new HashMap<>();
	static Set<Integer> generatedRandomNums = new HashSet<>();

	private ServerSocket s;

	public CLA(int p) throws Exception {
		// open server socket and start listening
		s = new ServerSocket(p);
		generateMyKeys();
	}

	public void generateMyKeys() {
		BigInteger[] keys = RSA.generateKeys(new BigInteger("573259433"), new BigInteger("49979687"));
		myPublicKey[0] = keys[0]; // e
		myPrivateKey[0] = keys[1]; // d
		myPublicKey[1] = myPrivateKey[1] = keys[2]; // n
	}

	public class RequestHandler implements Runnable {
		private Socket sock;

		private RequestHandler(java.net.Socket x) {
			sock = x;
		}

		public void run() {
			try {
				System.out.println("connect...");
				int c;
				StringBuilder sb = new StringBuilder();

				while ((c = sock.getInputStream().read()) != -1) {
					sb.append(c - '0');
					if (sock.getInputStream().available() == 0) {
						break;
					}
				}
				BigInteger voterId = new BigInteger(sb.toString());

				int validationNum = 0;
				do {
					validationNum = (int) (Math.random() * 1000);
				} while (!generatedRandomNums.add(validationNum)); //checks whether this validation number has already been generated

				BigInteger decrypted = (voterId).modPow(myPrivateKey[0], myPrivateKey[1]);
				voterList.put(decrypted.intValue(), validationNum);

				BigInteger validNum = new BigInteger(validationNum + "");
				BigInteger encryptedValidNumForCTF = (validNum).modPow(publicKeyCTF[0], publicKeyCTF[1]);

				BigInteger encryptedValidNumForVoter = (validNum).modPow(publicKeyVoter[0], publicKeyVoter[1]);

				String vN = encryptedValidNumForVoter.toString();
				for (int l = 0; l < vN.length(); l++) {
					sock.getOutputStream().write(vN.charAt(l)); //sends encrypted validation number to voter 
				}

				Socket ctf = new Socket("127.0.0.1", 6000);

				String encryptedIdToSend = encryptedValidNumForCTF.toString();
				for (int l = 0; l < encryptedIdToSend.length(); l++) {
					ctf.getOutputStream().write(encryptedIdToSend.charAt(l)); //sends encrypted validation number to CTF
				}

				ctf.getOutputStream().flush();
				ctf.close();

				sock.getOutputStream().flush();
				sock.close();
				System.out.println("disconnect...");
			} catch (Exception e) {
				System.out.println("HANDLER: " + e);
			}
		}
	}

	public void run() {
		while (true) {
			try {
				// accept a connection and run handler in a new thread
				new Thread(new RequestHandler(s.accept())).run();
			} catch (Exception e) {
				System.out.println("SERVER: " + e);
			}
		}
	}

	public static void main(String[] argv) throws Exception {
		if (argv.length != 1) {
			System.out.println("java SimpleServer <port>");
			System.exit(1);
		}
		new CLA(Integer.parseInt(argv[0])).run();
	}

}
