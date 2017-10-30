#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

//#define MAX_DIGITS 50

struct public_key {
	long long n;
	long long e;
};

struct private_key {
	long long n;
	long long d;
};

int checkPrime(long long n) {
	for (int i = 2; i <= n / 2; i++)
	{
		// podmienka pre neprvocislo
		if (n % i == 0)
		{
			return 1;
			break;
		}
	}
	return 0;
}

long long gcd(long long a, long long b)
{
	long long temp;
	while (1)
	{
		temp = a % b;
		if (temp == 0)
			return b;
		a = b;
		b = temp;
	}
}

long long EEA(long long a, long long b) {
	long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
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

long long rsa_modExp(long long b, long long e, long long m)
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
	char *buf;
	buf = (char*)malloc(bufSize * sizeof(char));

	pub->e = 65537;
	srand(time(NULL));
	
	for (i = 0; i < bufSize; i++) {
		buf[i] = rand() % 0xFF;
	}
	buf[0] |= 0xC0;
	buf[bufSize - 1] |= 0x01;

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

	rsa_gen_keys(pub, priv);
	//printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->n, (long long)priv->d);
	//printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->n, (long long)pub->e);

	////char message[] = "Hello world!\nHow are you today, mate?";
	//char *message;
	//long long *size;
	//size = malloc(sizeof(long long));
	//*size = 100;
	//message = inputString(size);
	//if (message == NULL) {
	//	printf("Message read failed!\n");
	//	exit(1);
	//}
	//printf("size is: %d\n", *size);
	//int i;

	///*printf("Original:\n");
	//for (i = 0; i < strlen(message); i++) {
	//printf("%lld ", (long long)message[i]);
	//}
	//printf("\n");*/

	//clock_t begin = clock();
	//long long *encrypted = rsa_encrypt(message, *size, pub);
	//if (!encrypted) {
	//	printf("Error in encryption!\n");
	//	return 1;
	//}
	//clock_t end = clock();
	//double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	//printf("\nEncryption took %lf seconds.\n", time_spent);
	///*printf("Encrypted:\n");
	//for (i = 0; i < strlen(message); i++) {
	//printf("%lld ", (long long)encrypted[i]);
	//}
	//printf("\n");*/

	//begin = clock();
	//char *decrypted = rsa_decrypt(encrypted, 8 * *size, priv);
	//if (!decrypted) {
	//	printf("Error in decryption!\n");
	//	return 1;
	//}
	//end = clock();
	//time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	//printf("Decryption took %lf seconds.\n", time_spent);
	///*printf("Decrypted:\n");
	//for (i = 0; i < strlen(message); i++) {
	//printf("%lld ", (long long)decrypted[i]);
	//}
	//printf("\n");*/

	//free(encrypted);
	//free(decrypted);

	getch();
	return 0;
}


