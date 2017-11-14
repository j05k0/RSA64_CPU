#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

#define MAX_KEYBOARD_INPUT 1023

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

struct message {
	unsigned char *msg;
	unsigned long long size;
	unsigned long long numBlocks;
};

void print_hex(char* arr, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02x", (unsigned char)arr[i]);
	printf("\n");
}

struct message intToStr(int bufSize, unsigned long long decrypted, int flag) {
	struct message decMsg;
	int i;
	unsigned long long int temp;
	decMsg.msg = (unsigned char *)malloc(bufSize * sizeof(unsigned char));
	decMsg.size = 0;
	for (i = bufSize - 1; i >= 0; i--) {
		temp = decrypted >> 8;
		temp = temp << 8;
		decMsg.msg[i] = decrypted - temp;
		if (flag && decMsg.msg[i] == 255) {
			decMsg.size = i;
		}
		decrypted = decrypted >> 8;
	}
	if (decMsg.size == 0) {
		decMsg.size = bufSize;
	}
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
	if (m == 1) {
		return 0;
	}
	unsigned long long result = 1;
	b = b % m;
	while (e > 0) {
		if (e % 2 == 1) {
			result = (result * b) % m;
		}
		e = e >> 1;
		b = (b * b) % m;
	}
	return result;
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

void rsa_encrypt(unsigned long long e, unsigned long long n, int bufSize, struct message message, unsigned char *cipher)
{
	int i, j, flag = 0;
	unsigned char *buf;
	unsigned long long *encrypted;
	clock_t begin, end;
	double time_spent;
	
	encrypted = (unsigned long long *)malloc(message.numBlocks * sizeof(unsigned long long));
	buf = (unsigned char*)malloc(bufSize * sizeof(unsigned char));
	begin = clock();
	for (i = 0; i < message.numBlocks; i++) {
		for (j = 0; j < bufSize; j++) {
			if (!flag) {
				buf[j] = *(message.msg + i * bufSize + j);
				if ((i == message.numBlocks - 1) && buf[j] == 255) {
					flag = 1;
				}
			}
			else {
				buf[j] = 0;
			}
		}
		//print_hex(buf, bufSize);
		encrypted[i] = buf[0];
		for (j = 1; j < bufSize; j++) {
			encrypted[i] = encrypted[i] << 8;
			encrypted[i] += buf[j];
		}
		//printf("%d. Message is %llu\n", i + 1, tempNumber);
		encrypted[i] = rsa_modExp(encrypted[i], e, n);
		//printf("Encrypted: %llu\n", encrypted);
		
	}
	free(buf);
	end = clock();
	time_spent = ((double)(end - begin) / CLOCKS_PER_SEC) * 1000;
	if (debug) {
		printf("Sifrovanie zabralo %lf ms\n", time_spent);
	}

	FILE *cipher_file;
	if (cipher != NULL) {
		cipher_file = fopen(cipher, "wb");
	}
	else {
		cipher_file = stdout;
		if (debug) {
			printf("Zasifrovany text:\n");
		}
	}
	
	begin = clock();
	unsigned long long sizeWritten = fwrite(encrypted, sizeof(unsigned long long), message.numBlocks, cipher_file);
	if (cipher != NULL) {
		fclose(cipher_file);
	}
	
	if (sizeWritten != message.numBlocks) {
		fprintf(stderr, "[rsa_encrypt]: Nepodarilo sa ulozit sifru do suboru\n");
		free(encrypted);
		exit(1);
	}
	end = clock();
	time_spent = ((double)(end - begin) / CLOCKS_PER_SEC) * 1000;
	if (debug && cipher != NULL) {
		printf("Zapis sifry na vystup trval %lf ms\n", time_spent);
		printf("Sifrovanie dokoncene. Sifra je ulozena v subore %s\n", cipher);
	}
	else if(debug) {
		printf("\nZapis sifry na vystup trval %lf ms\n", time_spent);
		printf("Sifrovanie dokoncene. Sifra je na stdout\n");
	}
	free(encrypted);
}

void rsa_decrypt(unsigned long long d, unsigned long long n, int bufSize, char *input, char *output)
{
	unsigned long long *decrypted;
	unsigned long long numBlocks;
	unsigned long long sizeOfFile;
	int i;
	clock_t begin, end;
	double time_spent;
	FILE *output_file, *cipher_file;
	
	begin = clock();
	if (input != NULL) {
		cipher_file = fopen(input, "rb");
		fseek(cipher_file, 0, SEEK_END);
		sizeOfFile = ftell(cipher_file);
		rewind(cipher_file);
		sizeOfFile /= 8;
		decrypted = (unsigned long long *)malloc(sizeof(unsigned long long) * sizeOfFile);
		if (!decrypted) {
			fprintf(stderr, "[rsa_decrypt]Alokacia pamate pre decrypted zlyhala\n");
			exit(1);
		}
		numBlocks = fread(decrypted, sizeof(unsigned long long), sizeOfFile, cipher_file);
		fclose(cipher_file);
	}
	else {
		freopen(NULL, "rb", stdin);
		cipher_file = stdin;
		fseek(cipher_file, 0, SEEK_END);
		sizeOfFile = ftell(cipher_file);
		rewind(cipher_file);
		if (sizeOfFile > 0) {
			decrypted = (unsigned long long *)malloc(sizeof(unsigned long long) * sizeOfFile);
			numBlocks = fread(decrypted, sizeof(unsigned long long), sizeOfFile, cipher_file);
		}
		else {
			fprintf(stderr, "Pokus o zadanie sifry manualne z klavesnice\n");
			exit(1);
		}
	}
	end = clock();
	time_spent = ((double)(end - begin) / CLOCKS_PER_SEC) * 1000;
	if (debug) {
		printf("Nacitanie sifry zabralo %lf ms.\n", time_spent);
		printf("Pocet blokov: %llu\n", numBlocks);
	}
	realloc(decrypted, numBlocks * sizeof(unsigned long long));

	if (output != NULL) {
		output_file = fopen(output, "wb");
	}
	else {
		output_file = stdout;
		if (debug) {
			printf("Desifrovany text:\n");
		}
	}

	begin = clock();
	struct message decMsg;
	for (i = 0; i < numBlocks - 1; i++) {
		decrypted[i] = rsa_modExp(decrypted[i], d, n);
		//printf("Decrypted: %llu\n", decrypted);
		decMsg = intToStr(bufSize, decrypted[i], 0);
		fwrite(decMsg.msg, 1, decMsg.size, output_file);
		free(decMsg.msg);
	}
	decrypted[i] = rsa_modExp(decrypted[i], d, n);
	decMsg = intToStr(bufSize, decrypted[i], 1);
	fwrite(decMsg.msg, 1, decMsg.size, output_file);
	end = clock();
	time_spent = ((double)(end - begin) / CLOCKS_PER_SEC) * 1000;

	if (output != NULL) {
		fclose(output_file);
	}
	if (debug && output != NULL) {
		printf("Desifrovanie trvalo %lf ms\n", time_spent);
		printf("Desifrovanie dokoncene. Vystup je ulozeny v subore %s\n", output);
	}
	else if (debug) {
		printf("\nDesifrovanie trvalo %lf ms\n", time_spent);
		printf("Desifrovanie dokoncene. Vystup je na stdout\n");
	}
}

struct message inputString(char *input, long long bufSize) {
	FILE *input_file;
	struct message message;
	int i = 0;
	unsigned long long sizeOfFile;
	//nacitanie suboru do buffra
	if (input != NULL) {
		input_file = fopen(input, "rb");
		fseek(input_file, 0, SEEK_END);
		sizeOfFile = ftell(input_file);
		//fseek(input_file, 0, SEEK_SET);
		rewind(input_file);
		if (debug) {
			printf("Velkost suboru je:\t\t%llu\n", sizeOfFile);
		}
		message.msg = (unsigned char *)malloc(sizeof(unsigned char) * (sizeOfFile + 1));
		message.size = fread(message.msg, 1, sizeOfFile, input_file);
		if (debug) {
			printf("Nacitana velkost suboru je:\t%llu\n", message.size);
		}
		message.msg[sizeOfFile] = 255;
		message.size++;
		fclose(input_file);
	}
	//nacitanie suboru zo standardneho vstupu
	else {
		freopen(NULL, "rb", stdin);
		input_file = stdin;
		fseek(input_file, 0, SEEK_END);
		sizeOfFile = ftell(input_file);
		rewind(input_file);
		if (sizeOfFile > 0) {
			//citanie suboru zo stdin
			if (debug) {
				printf("Velkost suboru je:\t\t%llu\n", sizeOfFile);
			}
			message.msg = (unsigned char *)malloc(sizeof(unsigned char) * sizeOfFile);
			message.size = fread(message.msg, 1, sizeOfFile, input_file);
			if (debug) {
				printf("Nacitana velkost suboru je:\t%llu\n", message.size);
			}
			message.msg[message.size++] = 255;
		}
		else {
			//nacitanie znakov zo stdin
			message.msg = (unsigned char *)malloc(sizeof(unsigned char) * (MAX_KEYBOARD_INPUT + 1));
			fgets(message.msg, MAX_KEYBOARD_INPUT, input_file);
			message.size = strlen(message.msg);
			//message.msg[message.size - 1] = '\0';
			message.msg[message.size++] = 255;
			sizeOfFile = message.size;
		}
	}
	if (sizeOfFile % bufSize != 0) {
		message.numBlocks = sizeOfFile / bufSize + 1;
	}
	else {
		message.numBlocks = sizeOfFile / bufSize;
	}
	return message;
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
	int i, flag = 0;
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
					if (key != NULL)
					{
						//testujem ci je to subor s verejnym klucom, ak ano tak ho citam
						if (strstr(argv[i], ".pub") != NULL) {
							if (fscanf(key, "%llu", &pub->n) != EOF) {
								if (fscanf(key, "%llu", &pub->e) != EOF) {
									if (debug) {
										printf("Nacitane kluce:\nn: %llu\ne: %llu\n", pub->n, pub->e);
									}
								}
								else {
									fprintf(stderr, "Zly vstupny subor s klucom!\n");
									return 0;
								}
							}
							else {
								fprintf(stderr, "Zly vstupny subor s klucom!\n");
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
					}
					else {
						fprintf(stderr, "Nepodarilo sa otvorit subor s klucom!\n");
						return 0;
					}
					i++;
					if (argv[i] == NULL) {
						if (debug) {
							printf("Nebol zadany vstupny subor, citam stdin.\n");
						}
						input = NULL;
						output = NULL;
					}
					else {
						input = (char*)malloc(strlen(argv[i]) * sizeof(char));
						strcpy(input, argv[i]);
						if (argv[i + 1] != NULL) {
							output = (char*)malloc(strlen(argv[i + 1]) * sizeof(char));
							strcpy(output, argv[i + 1]);
						}
						else {
							output = NULL;
						}
					}
					
					if (!strcmp(argv[i - 2], "-e")) {
						struct message message;
						begin = clock();
						//nacitanie vstupu do buffra
						message = inputString(input, bufSize);
						if (message.msg == NULL) {
							fprintf(stderr, "Chyba pri citani zo vstupu!\n");
							exit(1);
						}
						end = clock();
						time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000;
						if (debug) {
							printf("Nacitanie spravy zabralo %lf ms.\n", time_spent);
							printf("Pocet blokov: %llu\n", message.numBlocks);
						}
						if (flag) {
							rsa_encrypt(priv->d, priv->n, bufSize, message, output);
						}
						else {
							rsa_encrypt(pub->e, pub->n, bufSize, message, output);
						}
						return 0;
					}
					else {
						if (flag) {
							rsa_decrypt(priv->d, priv->n, bufSize, input, output);
						}
						else {
							rsa_decrypt(pub->e, pub->n, bufSize, input, output);
						}
						return 0;
					}
				}
				else {
					fprintf(stderr, "Chyba subor s klucom!\n");
					exit(1);
				}
			}
			else if (!strcmp(argv[i], "-b")) {
				if (!debug) {
					debug = 1;
				}
			}
			else {
				fprintf(stderr, "%s je zly argument, skus znova alebo pouzi -h pre pomoc.\n", argv[i]);
				return 0;
			}
		}
		return 0;
	}
	else {
		fprintf(stderr, "Malo argumentov, skus znova alebo pouzi -h pre pomoc.\n");
		return 0;
	}
}


