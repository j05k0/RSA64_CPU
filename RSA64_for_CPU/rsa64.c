#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

struct public_key {
	unsigned long long n;
	unsigned long long e;
};

struct private_key {
	unsigned long long p;
	unsigned long long q;
	unsigned long long n;
	unsigned long long d;
};

void print_hex(char* arr, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02x", (unsigned char)arr[i]);
	printf("\n");
}

char *strToInt(int bufSize, unsigned long long decrypted) {
	int i;
	char *decMsg;
	decMsg = malloc((bufSize + 1) * sizeof(char));
	unsigned long long int temp;
	for (i = 3; i >= 0; i--) {
		temp = decrypted >> 8;
		temp = temp << 8;
		decMsg[i] = decrypted - temp;
		decrypted = decrypted >> 8;
	}
	decMsg[bufSize] = '\0';
	return decMsg;
}

int checkPrime(unsigned long long n) {
	int i;
	if (n % 2 == 0)
		return 1;
	for (i = 3; i <= sqrt(n); i+=2)
	{
		// podmienka pre neprvocislo
		if (n % i == 0)
			return 1;
	}
	return 0;
}

unsigned long long int nextPrime(unsigned long long n) {
	while (checkPrime(n) != 0) {
		if(n % 2 == 0)
			n++;
		n += 2;
	}
	return n;
}

unsigned long long gcd(unsigned long long a, unsigned long long b)
{
	unsigned long long temp;
	while (1)
	{
		temp = a % b;
		if (temp == 0)
			return b;
		a = b;
		b = temp;
	}
}

unsigned long long EEA(unsigned long long a, unsigned long long b) {
	unsigned long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
	while (a != 0) {
		q = gcd / a;
		r = gcd % a;
		m = x - u*q;
		n = y - v*q;
		gcd = a;
		a = r;
		x = u;
		y = v;
		u = m;
		v = n;
	}
	return y;
}

unsigned long long rsa_modExp(unsigned long long b, unsigned long long e, unsigned long long m)
{
	if (b < 0 || e < 0 || m <= 0) {
		printf("Error of arguments!\n");
		exit(1);
	}
	b = b % m;
	if (e == 0)
		return 1;
	if (e == 1)
		return b;
	if (e % 2 == 0) {
		return (rsa_modExp(b * b % m, e / 2, m) % m);
	}
	if (e % 2 == 1) {
		return (b * rsa_modExp(b, (e - 1), m) % m);
	}

}

void rsa_gen_keys(struct public_key *pub, struct private_key *priv, int modSize)
{
	int i;
	int bufSize = modSize / 16;
	unsigned char *buf;
	unsigned long long int phi;
	buf = (unsigned char*)malloc(bufSize * sizeof(unsigned char) + 1);

	pub->e = 65537;
	srand(time(NULL));
	
	do {
		for (i = 0; i < bufSize; i++) {
			buf[i] = rand() % 0xFF;
		}
		buf[0] |= 0xC0;
		buf[bufSize - 1] |= 0x01;
		priv->p = buf[0];
		for (i = 1; i < bufSize; i++) {
			priv->p = priv->p << 8;
			priv->p += buf[i];
		}
		priv->p = nextPrime(priv->p);
		while (priv->p % pub->e == 1) {
			priv->p = nextPrime(priv->p);
		}

		do {
			for (i = 0; i < bufSize; i++) {
				buf[i] = rand() % 0xFF;
			}
			buf[0] |= 0xC0;
			buf[bufSize - 1] |= 0x01;
			priv->q = buf[0];
			for (i = 1; i < bufSize; i++) {
				priv->q = priv->q << 8;
				priv->q += buf[i];
			}
			priv->q = nextPrime(priv->q);
			while (priv->q % pub->e == 1) {
				priv->q = nextPrime(priv->q);
			}
		} while (priv->p == priv->q);
		priv->n = priv->p * priv->q;
		pub->n = priv->n;
		phi = (priv->p - 1) * (priv->q - 1);
		priv->d = EEA(phi, pub->e);
		while (priv->d < 0) {
			priv->d = priv->d + phi;
		}
	} while (priv->d >= priv->n);

	printf("---------------Public Key-----------------\n");
	printf("n is [%llu]\n", pub->n);
	printf("e is [%llu]\n", pub->e);
	printf("---------------Private Key------------------\n");
	printf("n is [%llu]\n", priv->n);
	printf("d is [%llu]\n", priv->d);
	printf("p is [%llu]\n", priv->p);
	printf("q is [%llu]\n", priv->q);
}

long long *rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key *pub)
{
	long long *encrypted = malloc(sizeof(long long)*message_size);
	if (encrypted == NULL) {
		printf("Error: Heap allocation failed.\n");
		return NULL;
	}
	long long i = 0;
	for (i = 0; i < message_size; i++) {
		encrypted[i] = rsa_modExp(message[i], pub->e, pub->n);
	}
	return encrypted;
}

char *rsa_decrypt(const long long *message, const unsigned long message_size, const struct private_key *priv)
{
	if (message_size % sizeof(long long) != 0) {
		printf("Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(long long));
		return NULL;
	}
	// We allocate space to do the decryption (temp) and space for the output as a char array
	// (decrypted)
	char *decrypted = malloc(message_size / sizeof(long long));
	char *temp = malloc(message_size);
	if ((decrypted == NULL) || (temp == NULL)) {
		printf("Error: Heap allocation failed.\n");
		return NULL;
	}
	// Now we go through each 8-byte chunk and decrypt it.
	long long i = 0;
	for (i = 0; i < message_size / 8; i++) {
		temp[i] = rsa_modExp(message[i], priv->d, priv->n);
	}
	// The result should be a number in the char range, which gives back the original byte.
	// We put that into decrypted, then return.
	for (i = 0; i < message_size / 8; i++) {
		decrypted[i] = temp[i];
	}
	free(temp);
	return decrypted;
}

char *inputString(long long bufSize, long long *numBlocks) {
	FILE *input;
	char c, *temp, *message;
	input = fopen("input.txt", "r");
	message = malloc(sizeof(char)* bufSize);
	if (!message) {
		printf("Error: Heap allocation failed.\n");
		return NULL;
	}
	int len = 0, blockidx = 0;
	while (fscanf(input, "%c", &c) != EOF) {
		*(message + blockidx * bufSize + len++) = c;
		if (len == bufSize) {
			temp = realloc(message, sizeof(char) * bufSize * (++blockidx + 1));
			if (temp) {
				message = temp;
				len = 0;
			}
			else {
				printf("Message reallocation failed!\n");
				return NULL;
			}
		}
	}
	fclose(input);
	*(message + blockidx * bufSize + len++) = '\0';
	temp = realloc(message, sizeof(char) * (bufSize * (blockidx + 1) + len));
	if (temp) {
		message = temp;
	}
	else {
		printf("Message reallocation failed!\n");
		return NULL;
	}
	*numBlocks = blockidx + 1;
	return message;
}

void help(char *argv) {
	FILE *help;
	char input;
	help = fopen("help.txt", "r");
	while (fscanf(help, "%c", &input) != EOF) {
		printf("%c", input);
		/*if (!strcmp(input, "Pouzitie:")) {
			printf("%s ", argv);
		}*/
	}
	fclose(help);
}

int main(int argc, char **argv) {
	struct public_key pub[1];
	struct private_key priv[1];
	int modSize = 32, bufSize = modSize / 8;
	int i, j;
	long long numBlocks = 0;

	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++) {
			if (!strcmp(argv[i], "-h")) {
				help(argv[0]);
			}
			else if (!strcmp(argv[i], "-g")) {
				rsa_gen_keys(pub, priv, modSize);
				i++;
				char *filename1, *filename2;
				if (i < argc) {
					filename1 = (char*)malloc((strlen(argv[i]) + 1) * sizeof(char));
					filename2 = (char*)malloc((strlen(argv[i]) + 5) * sizeof(char));
					filename1[0] = '\0';
					filename2[0] = '\0';
					strcat(filename1, argv[i]);
					strcat(filename2, filename1);
					strcat(filename2, ".pub");
				}
				else {
					filename1 = (char*)malloc(7 * sizeof(char));
					filename2 = (char*)malloc(11 * sizeof(char));
					filename1[0] = '\0';
					filename2[0] = '\0';
					strcat(filename1, "rsakey");
					strcat(filename2, filename1);
					strcat(filename2, ".pub");
				}
				printf("Ukladam kluce do suborov %s and %s...\n", filename1, filename2);
				FILE *keyFile;
				keyFile = fopen(filename1, "w");
				fprintf(keyFile, "%llu %llu %llu %llu", priv->n, priv->d, priv->p, priv->q);
				fclose(keyFile);
				keyFile = fopen(filename2, "w");
				fprintf(keyFile, "%llu %llu", pub->n, pub->e);
				fclose(keyFile);
			}
			else {
				printf("%s is a wrong argument, try again, or use -h for help.\n", argv[i]);
				return 0;
			}
		}
		return 0;
	}
	else {
		printf("Too few arguments, try again, or use -h for help.\n");
		return 0;
	}

	char *message;
	message = inputString(bufSize, &numBlocks);
	if (message == NULL) {
		printf("Message read failed!\n");
		exit(1);
	}

	char *buf;
	unsigned long long encrypted, tempNumber;
	int flag = 0;
	FILE *cipher;
	cipher = fopen("cipher.txt", "w");
	for (i = 0; i < numBlocks; i++) {
		buf = (char*)malloc((i + 1) * bufSize * sizeof(char));
		for (j = 0; j < bufSize; j++) {
			if (!flag)
				buf[j] = *(message + i * bufSize + j);
			else
				buf[j] = '\0';
			if (buf[j] == '\0')
				flag = 1;
		}
		//print_hex(buf, bufSize);
		tempNumber = buf[0];
		for (j = 1; j < bufSize; j++) {
			tempNumber = tempNumber << 8;
			tempNumber += buf[j];
		}
		//printf("%d. Message is %llu\n", i+1, tempNumber);
		encrypted = rsa_modExp(tempNumber, pub->e, pub->n);
		//printf("Encrypted: %llu\n", encrypted);
		fprintf(cipher, "%llu ", encrypted);
		free(buf);
	}
	fclose(cipher);
	//printf("\n");
	printf("Encryption done\n");

	FILE *output;
	output = fopen("output.txt", "w");
	cipher = fopen("cipher.txt", "r");
	char *result, *msg;
	unsigned long long int cipherMsg, decrypted;
	result = malloc(sizeof(char) * bufSize);
	msg = malloc(sizeof(char) * bufSize);
	result[0] = '\0';
	for(i = 0; i < numBlocks; i++){
		fscanf(cipher, "%llu", &cipherMsg);
		decrypted = rsa_modExp(cipherMsg, priv->d, priv->n);
		//printf("Decrypted: %llu\n", decrypted);
		msg = strToInt(bufSize, decrypted);
		//strcat(result, msg);
		fprintf(output, "%s", msg);
	}
	fclose(cipher);
	fclose(output);

	printf("Decryption done\n");
	getch();
	return 0;
}


