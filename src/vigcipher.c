/**
 * @file    vigcipher.c
 * @author  RedRoosterKey
 * @version see version.h
 *
 * @section LICENSE
 *
 *                    GNU GENERAL PUBLIC LICENSE
 *                     Version 3, 29 June 2007
 *
 *    vigcipher is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    vigcipher is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @section DESCRIPTION
 *
 * Runs a basic substitution cipher on STDOUT and outputs "encrypted" text to
 * STDOUT.  Please note that this mode of encryption has been proven to be
 * completely insecure and should only be used for entertainment or educational
 * purposes.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "version.h"

#define MAX_ALPHABET_SIZE 256

const char * HELP =
		"Usage: vigcipher [OPTION]... \n\
Applies an insecure Vigenere cipher on STDIN \n\
  and outputs \"encrypted\" text on STDOUT\n\
\n\
  -a, --alphabet=<alphabet> specifies the unique ordered set of characters \n\
                             which can be encrypted when input\n\
  -e, --encrypt             increment characters according to the key\n\
  -d, --decrypt             decrement characters according to the key\n\
  -h, --help                display this help message and exit\n\
  -k, --key=<key>           specifies the non-unique ordered set of characters\n\
                             that describes the substitution indices\n\
  -l. --lower               convert everything to lower case if possible\n\
                             (may produce an error if this creates duplicate\n\
                             characters in the alphabet)\n\
  -p, --passthru            characters not in the alphabet will simply be\n\
                             output unencrypted\n\
                             (default behavior is to produce an error)\n\
  -q, --predefined-alpha    (UC|LC|AC|PRINT)\n\
                             UC = [A-Z]\n\
                             LC = [a-z]\n\
                             AC = [A-Za-z]\n\
                             PRINT = all printable characters\n\
  -u, --upper\n\
  -v, --version             output version information and exit\n";

void stoupper(char * string) {
	for (short index = 0; string[index] != '\0'; index++) {
		string[index] = toupper(string[index]);
	}
}

void stolower(char * string) {
	for (short index = 0; string[index] != '\0'; index++) {
		string[index] = tolower(string[index]);
	}
}

// Predefined alphabets
const char * UC_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char * LC_ALPHA = "abcdefghijklmnopqrstuvwxyz";
const char * AC_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const char * PRINTABLE =
		" !\"#$%&'()*+,-./0123456789:;<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

bool doesAlphabetHaveDuplicates(char * alphabet) {
	if (NULL == alphabet) {
		return (false);
	}
	unsigned short count[256];
	for (int i = 0; i < 256; i++) {
		count[i] = 0;
	}

	for (int i = 0; 0 != alphabet[i]; i++) {
		if (0 < count[(short) alphabet[i]]) {
			return (true);
		}
		count[(short) alphabet[i]] = 1;
	}
	return (false);
}

int findChar(char * alphabet, char ch) {
	for (int i = 0; 0 != alphabet[i]; i++) {
		if (alphabet[i] == ch) {
			return (i);
		}
	}
	return (-1);
}

bool applyCipher(char * alphabet, char * key, bool trueToEncrypt,
bool passThroughInvalidInput, bool toUpper, bool toLower) {
	if (true == toUpper && true == toLower) {
		fputs("You cannot convert output to both upper case and lower case.\n",
		stderr);
		return (true);
	}

	if(NULL == alphabet || NULL == key) {
		return (true);
	}

	short alphabetSize = strlen(alphabet);
	short keySize = strlen(key);

	short indexKey[keySize];
	if (0 < alphabetSize && 0 < keySize) {
		bool missingChars = false;
		for (int i = 0; 0 != key[i]; i++) {
			int index = findChar(alphabet, key[i]);
			if (0 > index) {
				fprintf(stderr,
						"Key has character '%c' that is not in the alphabet.\n",
						key[i]);
				missingChars = true;
			}
			indexKey[i] = index;
		}
		if (true == missingChars) {
			return (true);
		}
	} else {
		return (true);
	}

	int keyIndex = 0;
	int input;
	while (EOF != (input = getchar())) {
		if (toUpper)
			input = toupper(input);
		if (toLower)
			input = tolower(input);
		int inputIndex = findChar(alphabet, input);
		if (0 > inputIndex) {
			if (passThroughInvalidInput) {
				putchar(input);
				continue;
			} else {
				fprintf(stderr,
						"Input has character '%c' that is not in the alphabet.\n",
						input);
				exit(EXIT_FAILURE);
			}
		}
		int outputIndex = inputIndex;
		if (trueToEncrypt) {
			outputIndex += (indexKey[keyIndex] + 1);
		} else {
			outputIndex -= (indexKey[keyIndex] + 1);
		}
		outputIndex = (outputIndex + alphabetSize) % alphabetSize;
		keyIndex = (keyIndex + 1) % keySize;
		putchar(alphabet[outputIndex]);
	}
	return (false);
}

int main(int argc, char **argv) {
	bool errors = false;

	bool encrypt = false;
	bool decrypt = false;
	bool passThroughInvalidInput = false;
	bool toUpper = false;
	bool toLower = false;
	char alphabet[MAX_ALPHABET_SIZE + 1] = "";
	char key[MAX_ALPHABET_SIZE] = "";
	static struct option long_options[] = { { "alphabet", required_argument, 0,
			'a' }, { "encrypt", no_argument, 0, 'e' }, { "decrypt", no_argument,
			0, 'd' }, { "help", no_argument, 0, 'h' }, { "key",
	required_argument, 0, 'k' }, { "lower", no_argument, 0, 'l' }, { "passthru",
	no_argument, 0, 'p' }, { "predefined-alpha", required_argument, 0, 'q' }, {
			"upper", no_argument, 0, 'u' }, { "version", no_argument, 0, 'v' },
			{ 0, 0, 0, 0 } };
	// Handle command line options
	while (true) {
		int option_index = 0;

		int option = getopt_long(argc, argv, "a:edhk:lpq:uv", long_options,
				&option_index);
		if (option == -1)
			break;
		switch (option) {
		case 'a':
			if (strlen(optarg) > MAX_ALPHABET_SIZE) {
				fprintf(stderr,
						"Alphabet is %d long and max supported size is %d.\n",
						(int) strlen(optarg), MAX_ALPHABET_SIZE);
				errors = true;
			}
			strncpy(alphabet, optarg, MAX_ALPHABET_SIZE);
			break;
		case 'e':
			encrypt = true;
			break;
		case 'd':
			decrypt = true;
			break;
		case 'h':
			// Print help
			puts(HELP);
			return (EXIT_SUCCESS);
			break;
		case 'k':
			strncpy(key, optarg, MAX_ALPHABET_SIZE);
			break;
		case 'l':
			toLower = true;
			break;
		case 'p':
			passThroughInvalidInput = true;
			break;
		case 'q':
			if (0 == strcmp("UC", optarg)) {
				strncpy(alphabet, UC_ALPHA, MAX_ALPHABET_SIZE);
			} else if (0 == strcmp("LC", optarg)) {
				strncpy(alphabet, LC_ALPHA, MAX_ALPHABET_SIZE);
			} else if (0 == strcmp("AC", optarg)) {
				strncpy(alphabet, AC_ALPHA, MAX_ALPHABET_SIZE);
			} else if (0 == strcmp("PRINT", optarg)) {
				strncpy(alphabet, PRINTABLE, MAX_ALPHABET_SIZE);
			} else {
				fprintf(stderr, "There is no predefined alphabet \"%s\"\n",
						optarg);
				fputs("Please run with --help for usage options.\n", stderr);
				errors = true;
			}
			break;
		case 'u':
			toUpper = true;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return (EXIT_SUCCESS);
		case '?':
			fputs("Please run with --help for usage options.\n", stderr);
			errors = true;
			break;
		default:
			abort();
			break;
		}
	}

	if (optind < argc) {
		fputs("Non-option arguments are not supported.\n", stderr);
		fputs("Please run with --help for usage options.\n", stderr);
		errors = true;
	}

	// Check the required options are provided
	// These options are fatal.  We cannot call applyCipher without
	// encrypt/decrypt being properly set
	if (false == encrypt && false == decrypt) {
		fputs("Specify if you would like to encrypt or decrypt.\n", stderr);
		return (EXIT_FAILURE);
	} else if (true == encrypt && true == decrypt) {
		fputs("You cannot both encrypt and decrypt.\n", stderr);
		return (EXIT_FAILURE);
	}


	if (NULL == alphabet || 0 == strlen(alphabet)) {
		fputs("No alphabet provided.\n", stderr);
		errors = true;
	}
	if (NULL == key || 0 == strlen(key)) {
		fputs("No key provided.\n", stderr);
		errors = true;
	}

	if (toUpper) {
		stoupper(alphabet);
		stoupper(key);
	} else if (toLower) {
		stolower(alphabet);
		stolower(key);
	}
	if (doesAlphabetHaveDuplicates(alphabet)) {
		fputs("Alphabet cannot have duplicate characters.\n", stderr);
		errors = true;
	}

	errors |= applyCipher(alphabet, key, encrypt && !decrypt,
			passThroughInvalidInput, toUpper, toLower);
	if (true == errors) {
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}
