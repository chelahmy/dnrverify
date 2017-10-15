// main.cpp
// Denarius Signed Message Verification
// By Abdullah Daud, chelahmy@gmail.com
// 15 October 2017

#include <iostream>
#include <string>
#include "dnrverify.h"

using namespace std;

int main(int argc, char *argv[])
{
	string addr, sig, msg, str;
	int i, msgnol;
	
	cout << "Verify Denarius Signed Message" << endl;

	if (!VerifyMessage("D6EB81Yqu5AGZtggcHjgHsEDujhinUGU3C", 
				"II2jAYE/dz94gHOZt7iVmIU7RLnnXspjjLcdgg3cqnUW7fbUa/sNti8TvZasTlJ0WT401R4oUte9OFfZbftq0oQ=", 
				"Hello world!"))
	{
		cout << "Verification test failed" << endl;
		return 0;
	}
	
	cout << "Denarius Address: ";	
	cin >> addr;
	cout << "Signature: ";
	cin >> sig;
	
	cout << "Number of lines in the message: ";
	cin >> msgnol;
	
	if (msgnol <= 1)
	{
		cout << "Message: ";
		getline(cin >> ws, msg);
	}
	else
	{	
		for (i = 1; i <= msgnol; i++)
		{
			if (i > 1)
				msg.append("\n");
				
			cout << "Message line #" << i << " ";
			getline(cin >> ws, str);
			msg.append(str);
		}
	}
	
	if (VerifyMessage(addr, sig, msg))
		cout << "Valid";
	else
		cout << "Invalid";	

	cout << endl;
	
	return 1;
}

