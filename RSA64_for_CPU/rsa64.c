#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

int debug = 0;

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

unsigned long long round_closest(unsigned long long dividend, unsigned long long divisor)
{
	return (dividend + (divisor / 2)) / divisor;
}

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

	if (debug) {
		printf("---------------Public Key-----------------\n");
		printf("n is [%llu]\n", pub->n);
		printf("e is [%llu]\n", pub->e);
		printf("---------------Private Key------------------\n");
		printf("n is [%llu]\n", priv->n);
		printf("d is [%llu]\n", priv->d);
		printf("p is [%llu]\n", priv->p);
		printf("q is [%llu]\n", priv->q);
	}
}

void rsa_encrypt(unsigned long long e, unsigned long long n, long long numBlocks, int bufSize, unsigned char *message, unsigned char *cipher)
{
	int i, j;
	unsigned char *buf;
	unsigned long long encrypted, tempNumber;
	int flag = 0;
	if (cipher == NULL) {
		cipher = "cipher.txt";
	}
	FILE *cipher_file;
	cipher_file = fopen(cipher, "w");
	for (i = 0; i < numBlocks; i++) {
		buf = (unsigned char*)malloc((i + 1) * bufSize * sizeof(unsigned char));
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
		encrypted = rsa_modExp(tempNumber, e, n);
		//printf("Encrypted: %llu\n", encrypted);
		fprintf(cipher_file, "%llu ", encrypted);
		free(buf);
	}
	fclose(cipher_file);
	//printf("\n");
	if (debug) {
		printf("Sifrovanie dokoncene. Sifra je ulozena v subore %s.\n", cipher);
	}
}

void rsa_decrypt(unsigned long long d, unsigned long long n, int bufSize, char *cipher, char *output)
{
	if (output == NULL) {
		output = "output.txt";
	}
	int i;
	FILE *output_file, *cipher_file;
	output_file = fopen(output, "wb");
	cipher_file = fopen(cipher, "r");
	unsigned char *msg;
	unsigned long long int cipherMsg, decrypted;
	msg = (unsigned char *)malloc(sizeof(unsigned char) * bufSize);
	while(fscanf(cipher_file, "%llu", &cipherMsg) != EOF)  {
		decrypted = rsa_modExp(cipherMsg, d, n);
		//printf("Decrypted: %llu\n", decrypted);
		msg = strToInt(bufSize, decrypted);
		fwrite(msg, sizeof(unsigned char), strlen(msg), output_file);
	}
	fclose(cipher_file);
	fclose(output_file);
	if (debug) {
		printf("Desifrovanie dokoncene. Vystup je ulozeny v subore %s.\n", output);
	}
}

char *inputString(char *input, long long bufSize, long long *numBlocks) {
	FILE *input_file;
	int i = 0;
	unsigned char c, *temp, *message;
	long sizeOfFile = 0;
	//nacitanie suboru do buffra
	if (input != NULL) {
		input_file = fopen(input, "rb");
		fseek(input_file, 0, SEEK_END);
		sizeOfFile = ftell(input_file);
		fseek(input_file, 0, SEEK_SET);
		if (debug) {
			printf("Velkost suboru je:\t\t%ld\n", sizeOfFile);
		}
		message = (unsigned char *)malloc(sizeof(unsigned char)* sizeOfFile);
		fread(message, sizeof(unsigned char), sizeOfFile, input_file);
		message[sizeOfFile] = '\0';
		*numBlocks = round_closest(sizeOfFile, bufSize);
		return message;
	}
	//nacitanie znakov zo standardneho vstupu
	else {
		input_file = stdin;
		message = (unsigned char *)malloc(sizeof(unsigned char) * bufSize);
		if (!message) {
			if (debug) {
				printf("Chyba: Alokacia pamate zlyhala.\n");
			}
			return NULL;
		}
		int len = 0;
		while (fscanf(input_file, "%c", &c) != EOF) {
			message[len++] = c;
			if (len == bufSize) {
				temp = realloc(message, sizeof(unsigned char) * len * 2);
				if (temp) {
					message = temp;
				}
				else {
					if (debug) {
						printf("Realokovanie buffra so vstupom zlyhalo!\n");
					}
					return NULL;
				}
			}
		}
		message[len++] = '\0';
		len = strlen(message);
		temp = realloc(message, sizeof(unsigned char) * len);
		if (temp) {
			message = temp;
		}
		else {
			printf("Message reallocation failed!\n");
			return NULL;
		}
		*numBlocks = round_closest(len, bufSize);
		return message;
	}
}

void help(char *argv) {
	FILE *help;
	char input;
	help = fopen("help.txt", "r");
	while (fscanf(help, "%c", &input) != EOF) {
		printf("%c", input);
	}
	fclose(help);
}

int main(int argc, char **argv) {
	struct public_key pub[1];
	struct private_key priv[1];
	int modSize = 32, bufSize = modSize / 8;
	int i, j;
	long long numBlocks = 0;
	clock_t begin, end;
	double time_spent;
	char *output, *input;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (!strcmp(argv[i], "-b")) {
				debug = 1;
				break;
			}
		}
		for (i = 1; i < argc; i++) {
			if (!strcmp(argv[i], "-h")) {
				help(argv[0]);
			}
			else if (!strcmp(argv[i], "-g")) {
				rsa_gen_keys(pub, priv, modSize);
				i++;
				char *filename1, *filename2;
				if (i < argc && (strcmp(argv[i], "-e") != 0 && strcmp(argv[i], "-d") != 0 && strcmp(argv[i], "-h") != 0) && strcmp(argv[i], "-b") != 0) {
					filename1 = (char*)malloc((strlen(argv[i]) + 1) * sizeof(char));
					filename2 = (char*)malloc((strlen(argv[i]) + 5) * sizeof(char));
					filename1[0] = '\0';
					filename2[0] = '\0';
					strcat(filename1, argv[i]);
					strcat(filename2, filename1);
					strcat(filename2, ".pub");
				}
				else {
					i--;
					filename1 = (char*)malloc(7 * sizeof(char));
					filename2 = (char*)malloc(11 * sizeof(char));
					filename1[0] = '\0';
					filename2[0] = '\0';
					strcat(filename1, "rsakey");
					strcat(filename2, filename1);
					strcat(filename2, ".pub");
				}
				FILE *keyFile;
				keyFile = fopen(filename1, "w");
				fprintf(keyFile, "%llu %llu %llu %llu", priv->n, priv->d, priv->p, priv->q);
				fclose(keyFile);
				keyFile = fopen(filename2, "w");
				fprintf(keyFile, "%llu %llu", pub->n, pub->e);
				fclose(keyFile);
				if (debug) {
					printf("Kluce boli ulozene do suborov %s and %s...\n", filename1, filename2);
				}
			}
			else if (!strcmp(argv[i], "-e") || !strcmp(argv[i], "-d")) {
				i++;
				if (i < argc) {
					FILE *key;
					key = fopen(argv[i], "r");
					int flag = 0;
					//testujem ci je to subor s verejnym klucom, ak ano tak ho citam
					if (strstr(argv[i], ".pub") != NULL) {
						if (fscanf(key, "%llu", &pub->n) != EOF) {
							if (fscanf(key, "%llu", &pub->e) != EOF) {
								if (debug) {
									printf("Nacitane kluce:\nn: %llu\ne: %llu\n", pub->n, pub->e);
								}
							}
							else {
								if (debug) {
									fprintf(stderr, "Zly vstupny subor s klucom!\n");
								}
								return 0;
							}
						}
						else {
							if (debug) {
								fprintf(stderr, "Zly vstupny subor s klucom!\n");
							}
							return 0;
						}
					}
					//citam subor so sukromnym klucom
					else {
						flag = 1;
						if (fscanf(key, "%llu", &priv->n) != EOF) {
							if (fscanf(key, "%llu", &priv->d) != EOF) {
								if (debug) {
									printf("Nacitane kluce:\nn: %llu\nd: %llu\n", priv->n, priv->d);
								}
							}
						}
					}
					fclose(key);
					i++;
					if (argv[i] == NULL) {
						if (debug) {
							printf("Nebol zadany vstupny subor, citam stdin.\n");
						}
						input = NULL;
						output = NULL;
					}
					else {
						if (argv[i + 1] != NULL) {
							output = (char*)malloc(strlen(argv[i + 1]) * sizeof(char));
							strcpy(output, argv[i + 1]);
						}
						else {
							output = NULL;
						}
					}
					
					if (!strcmp(argv[i - 2], "-e")) {
						char *message;
						begin = clock();
						message = inputString(argv[i], bufSize, &numBlocks);
						if (message == NULL) {
							if (debug) {
								printf("Chyba pri citani zo vstupu!\n");
							}
							exit(1);
						}
						end = clock();
						time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
						if (debug) {
							printf("Nacitanie spravy zabralo %lf sekund.\n", time_spent);
							printf("Pocet blokov: %llu\n", numBlocks);
						}

						begin = clock();
						if (flag) {
							rsa_encrypt(priv->d, priv->n, numBlocks, bufSize, message, output);
						}
						else {
							rsa_encrypt(pub->e, pub->n, numBlocks, bufSize, message, output);
						}
						end = clock();
						time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
						if (debug) {
							printf("Sifrovanie zabralo %lf sekund.\n", time_spent);
						}
						return 0;
					}
					else {
						if (argv[i] != NULL) {
							char *cipher;
							cipher = (char*)malloc(strlen(argv[i]) * sizeof(char));
							strcpy(cipher, argv[i]);
							begin = clock();
							if (flag) {
								rsa_decrypt(priv->d, priv->n, bufSize, cipher, output);
							}
							else {
								rsa_decrypt(pub->e, pub->n, bufSize, cipher, output);
							}
							end = clock();
							time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
							if (debug) {
								printf("Desifrovanie zabralo %lf sekund.\n", time_spent);
							}
						}
						else if (debug) {
							printf("Nebol zadany vstupny subor na desifrovanie.\n");
						}
						return 0;
					}
				}
				else {
					if (debug) {
						printf("Chyba subor s klucom!\n");
					}
				}
			}
			else if (!strcmp(argv[i], "-t")) {
				FILE *test, *test_out;
				test = fopen(argv[++i], "rb");
				fseek(test, 0, SEEK_END);
				long sizeOfFile = ftell(test);
				fseek(test, 0, SEEK_SET);
				printf("Velkost suboru je:\t\t%ld\n", sizeOfFile);
				unsigned char *buff2;
				unsigned char c;
				long idx = 0;
				buff2 = (unsigned char*)malloc(sizeOfFile * sizeof(unsigned char));
				begin = clock();
				/*while (fscanf(test, "%c", &c) != EOF) {
					buff2[idx++] = c;
				}*/
				fread(buff2, sizeOfFile, sizeof(unsigned char), test);
				end = clock();
				time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
				printf("Pocet nacitanych znakov:\t%ld\n", strlen(buff2));
				printf("Nacitanie zabralo %lf sekund.\n", time_spent);
				fclose(test);

				char *dest_filename;
				dest_filename = (char*)malloc((strlen(argv[i]) + 1) * sizeof(char));
				dest_filename[0] = '1';
				dest_filename[1] = '\0';
				strcat(dest_filename, argv[i]);
				test_out = fopen("out", "wb");
				fwrite(buff2, sizeof(unsigned char), sizeOfFile, test_out);
				fclose(test_out);
				printf("Ulozenie dokoncene.\n");
				free(buff2);
				return 0;
			}
			else if (!strcmp(argv[i], "-b")) {
				if (!debug) {
					debug = 1;
				}
			}
			else {
				printf("%s je zly argument, skus znova alebo pouzi -h pre pomoc.\n", argv[i]);
				return 0;
			}
		}
		return 0;
	}
	else {
		if (debug) {
			printf("Malo argumentov, skus znova alebo pouzi -h pre pomoc.\n");
		}
		return 0;
	}
}


