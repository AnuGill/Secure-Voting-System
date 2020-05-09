# Secure-Voting-System

# Instructions

Development Environment – Eclipse, Command Prompt (Test environment)

0)	Compile CLA, CTF, RSA and Voter classes. Start CLA.java and CTF.java
Java CLA 5000
Java CTF 6000

1)	Voter will first connect to CLA to obtain a unique validation number.
    Java Voter 127.0.0.1 5000 10 “”
	  Arguments- host (IP address of CLA)
		          Port (Port on which CLA is running)
		          User Id of the voter
		          Empty string (Voter sends empty vote to CLA (ignored by CLA))
2)	Voter and CTF both get the generated validation number by CLA.

3)	Voter will now connect to CTF.
    Java Voter 127.0.0.1 6000 584 “Republican”
	  Arguments- Host (IP address of CTF)
		          Port (Port number on which CTF is running)
		          Validation Number (obtained from CLA)
 		          Vote (Name of the candidate)

4)	CTF will check the validation number. Following three cases are tested:
  a)	If validation number is valid, CTF will print the tally and sends the success message to the Voter.
  b)	If the user has already voted previously then CTF does not allow to vote again and sends the message to the Voter.
  c)	If the validation number is not valid (i.e CLA has not sent this validation number to CTF for any user), then CTF does         not allow to vote and send the message to the Voter.
  
5)	Similarly, other voters will obtain validation numbers from CLA and cast their vote to the CTF.

Note: The samples are taken by running Voter, CTF and CLA on same machine. But they are intended to run on 3 different machines. In order to do that, please change the IP address and port number of CTF in CLA.java on line# 72 where CLA makes connection to CTF.
    Socket ctf = new Socket("127.0.0.1", 6000);
