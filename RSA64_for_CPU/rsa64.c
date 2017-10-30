#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

//#define MAX_DIGITS 50

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
}


int checkPrime(unsigned long long n) {
	if (n % 2 == 0)
		return 1;
	for (int i = 3; i <= sqrt(n); i+=2)
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
	//pub->e = 17;
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

char *inputString(long long *size) {
	FILE *input;
	char c, *temp, *message;
	input = fopen("input.txt", "r");
	message = malloc(sizeof(char)* (*size));
	if (!message) {
		printf("Error: Heap allocation failed.\n");
		return NULL;
	}
	int len = 0;
	while (fscanf(input, "%c", &c) != EOF) {
		message[len++] = c;
		if (len == *size) {
			temp = realloc(message, sizeof(char)*(*size * 2));
			if (temp) {
				message = temp;
				(*size) *= 2;
			}
			else {
				printf("Message reallocation failed!\n");
				return NULL;
			}
		}
	}
	fclose(input);
	message[len++] = '\0';
	temp = realloc(message, sizeof(char) * len);
	if (temp) {
		message = temp;
		*size = len;
	}
	else {
		printf("Message reallocation failed!\n");
		return NULL;
	}
	return message;
}

int main() {
	struct public_key pub[1];
	struct private_key priv[1];
	int modSize = 32, bufSize = modSize/8;
	int i;
	long long *size;
	size = malloc(sizeof(long long));

	rsa_gen_keys(pub, priv, modSize);

	char message[] = "Hello world!\nHow are you today, mate?";
	*size = strlen(message);

	char *buf;
	buf = (char*)malloc(bufSize * sizeof(char));
	for (i = 0; i < bufSize; i++) {
		buf[i] = message[i];
	}
	print_hex(buf, bufSize);
	unsigned long long temp = buf[0];
	for (i = 1; i < bufSize; i++) {
		temp = temp << 8;
		temp += buf[i];
	}
	printf("\nMessage is %llu\n", temp);
	unsigned long long encrypted = rsa_modExp(temp, pub->e, pub->n);
	printf("Encrypted: %llu\n", encrypted);
	unsigned long long decrypted = rsa_modExp(encrypted, priv->d, priv->n);
	printf("Decrypted: %llu\n", decrypted);

	/*char *message;
	*size = 100;
	message = inputString(size);
	if (message == NULL) {
		printf("Message read failed!\n");
		exit(1);
	}
	printf("size is: %d\n", *size);*/

	/*printf("Original:\n");
	for (i = 0; i < strlen(message); i++) {
	printf("%lld ", (long long)message[i]);
	}
	printf("\n");*/

	/*clock_t begin = clock();
	long long *encrypted = rsa_encrypt(message, *size, pub);
	if (!encrypted) {
		printf("Error in encryption!\n");
		return 1;
	}
	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("\nEncryption took %lf seconds.\n", time_spent);
	printf("Encrypted:\n");
	for (i = 0; i < strlen(message); i++) {
	printf("%lld ", (long long)encrypted[i]);
	}
	printf("\n");

	begin = clock();
	char *decrypted = rsa_decrypt(encrypted, 8 * *size, priv);
	if (!decrypted) {
		printf("Error in decryption!\n");
		return 1;
	}
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Decryption took %lf seconds.\n", time_spent);
	printf("Decrypted:\n");
	for (i = 0; i < strlen(message); i++) {
	printf("%lld ", (long long)decrypted[i]);
	}
	printf("\n");

	free(encrypted);
	free(decrypted);*/

	getch();
	return 0;
}


