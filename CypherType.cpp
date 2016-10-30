/*
Implementation of two block cipher algorithms(AES and DES) using OOP methods 
and VernamCipher(OTP).
AES and DES in ECB mode.
Key length in AES is 128 bits, block length is 128 bits
Key length in DES is 64 bits(meaningfull is 56 bits), block length is 64 bits
Key length in VernamCipher is equal to length of the encrypted text.
Abstract class helps to create hierarhy of classes
Protected inheritance is used for security of the programm
Library for DES was made by means of openssl
Library for AES was created from source code: https://github.com/kokke/tiny-AES128-C
*/
#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <cstdlib>
#include <windows.h>
#include <openssl/des.h>
#include "aes.h"

using namespace std;

//abstact class for three types of ciphers
class CipherType{
private:
//protected:
	//int block_len;
	int key_len;
	vector<char> plain_text;
	vector<char> enc_text;
	vector<char> dec_text;
	vector<char> ciph_key;
protected:
//public:
	//Setters
	void SetEncText(vector<char> e){ enc_text = e; }
	void SetDecText(vector<char> d){ dec_text = d; }
	void SetCiphKey(vector<char> k){ ciph_key = k; }
	void SetKeyLen(int k_len){ key_len = k_len; }
	//Getters
	vector<char> GetPlainText(){ return plain_text; }
	vector<char> GetEncText(){ return enc_text;}
	int GetKeyLen();
	int GetTextLen();
	vector<char> GetCiphKey(){ return ciph_key; };
	//Other
	void ReadFile(string file_name);//read file with text for encryption
	void WriteToFile(string file_name);//write deciphered text to file
	void WriteEncTextToFile(string file_name);
	//pure virtual functions 
	virtual void GenerateCipherKey()=0;//generate cipher key with certain length
	virtual void Encrypt()=0;//encrypt plain text
	virtual void Decrypt()=0;//decrypt encrypted text
};

void CipherType::WriteEncTextToFile(string file_name)
{
	ofstream output_file(file_name);
	vector<char>::iterator it;
	if (output_file){
		for (it = enc_text.begin(); it < enc_text.end(); it++){
			output_file << *it;
		}
		output_file << "\n";
	}
}

int CipherType::GetTextLen(){
	
	return plain_text.size();
}

int CipherType::GetKeyLen(){
	if (key_len){
		return key_len;
	}
	else{
		return 0;
	}
}

void CipherType::ReadFile(string file_name)
{
	char ch;
	ifstream input_file(file_name);
	if (input_file){
		while (input_file.get(ch)){
			plain_text.push_back(ch);
		}
	}
	else{
		return;

	}
}

void CipherType::WriteToFile(string file_name)
{
	ofstream output_file(file_name);
	vector<char>::iterator it;
	if (output_file){
		for (it = dec_text.begin(); it < dec_text.end(); it++){
			output_file << *it;
		}
		output_file << "\n";
	}
}

//child class number one
class VernamCipher: public CipherType{
protected:
//public:
	void GenerateCipherKey();
	void Encrypt();
	void Decrypt();
public:
	void EncryptOTP(){ Encrypt(); }
	void DecryptOTP(){ Decrypt(); }
	void GenerateCipherKeyOTP(){ GenerateCipherKey(); }
	void ReadFileOTP(string file_name){ ReadFile(file_name); }
	void WriteToFileOTP(string file_name){ WriteToFile(file_name); }
	int GetTextLenOTP(){ return GetTextLen(); }
	void SetKeyLenOTP(int ln){ SetKeyLen(ln); }
};

void VernamCipher::GenerateCipherKey()
{
	vector<char> c_key;
	c_key = GetCiphKey();
	srand(time(0));//initializing of random generator
	for (int i = 0; i < GetKeyLen(); i++){
		c_key.push_back((char)(rand() % 92 + 33));
	}
	SetCiphKey(c_key);
}

void VernamCipher::Encrypt()
{
	vector<char> pl_text;
	vector<char> c_key;
	vector<char> e_text;
	c_key = GetCiphKey();
	pl_text = GetPlainText();
	for (int i = 0; i < pl_text.size(); i++){
		e_text.push_back((char)((int)c_key[i] ^ (int)pl_text[i]));
	}
	SetEncText(e_text);

}

void VernamCipher::Decrypt()
{
	vector<char> e_text;
	vector<char> c_key;
	vector<char> d_text;
	e_text = GetEncText();
	c_key = GetCiphKey();
	for (int i = 0; i < e_text.size(); i++)
		d_text.push_back((char)((int)c_key[i] ^ (int)e_text[i]));
	SetDecText(d_text);
}


class DES_Cipher : public CipherType{
private:
	DES_key_schedule key;
	int b_part;//part for padding with 0
//public:
protected:
	
	void SetPaddingPart(int b_p){ b_part = b_p; }
	int GetPaddingPart(){ return b_part; }
	void SetKeySchedule(DES_key_schedule key_s){ key = key_s; }
	void GenerateCipherKey();
	void Encrypt();
	void Decrypt();
	int PerformTest();
	void PrintResult();
public:
	DES_Cipher(){ b_part = 0; }
	void EncryptDES(){ Encrypt(); }
	void DecryptDES(){ Decrypt(); }
	void GenerateCipherKeyDES(){ GenerateCipherKey(); }
	void ReadFileDES(string file_name){ ReadFile(file_name); }
	void WriteToFileDES(string file_name){ WriteToFile(file_name); }
};

void DES_Cipher::Decrypt()
{
	vector<char> e_text;
	vector<char> dec_text_pad;//decrypted text with padding
	vector<char> dec_text;//decrypted text without padding
	DES_cblock buf;
	DES_cblock dec_block;
	int block_part;
	block_part = GetPaddingPart();
	e_text = GetEncText();
	for (int i = 0; i <=e_text.size(); i++){
		if (i % 8 == 0 && i>0){
			DES_ecb_encrypt(&buf, &dec_block, &key, 0);
			for (int j = 0; j < 8; j++){
				dec_text_pad.push_back(dec_block[j]);
				//buf[j] = 0;
			}
			//continue;
		}
		if (i != e_text.size()){
			buf[i % 8] = e_text[i];
		}
		
	}
	
	
	for (int i = 0; i < dec_text_pad.size() - (8-block_part); i++){
		dec_text.push_back(dec_text_pad[i]);
	}
	SetDecText(dec_text);//decrypted text without padding
}

void DES_Cipher::Encrypt()
{
	vector<char> text;
	vector<char> cipher_text;
	DES_cblock buf;
	DES_cblock cipher_block;
	text = GetPlainText();
	int block_part=0;
	if (text.size() % 8 != 0){
		block_part = text.size() % 8;
		SetPaddingPart(block_part);
		for (int j = block_part; j < 8; j++){
			text.push_back(0);//padding with 0
		}

	}
	for (int i = 0; i <=text.size(); i++){
		/*
		if ((text.size()==i) && ((i%8)!=0)){//the last block
			block_part = i % 8;//how many bytes there are
			for (int j = 0; j < block_part; j++){
				
				cipher_text.push_back(0);
			}
			break;
		}
		*/
		if (i % 8 == 0 && i>0){//if we have block of 64 bits
			DES_ecb_encrypt(&buf, &cipher_block, &key, 1);
			for (int j = 0; j < 8; j++){//copy new key
				cipher_text.push_back(cipher_block[j]);
				//buf[j] = 0;
				
			}
			//continue;//to new iteration
		}
		if (i != text.size()){
			buf[i % 8] = text[i];
		}
		
	}
	SetEncText(cipher_text);
}

void DES_Cipher::GenerateCipherKey()
{
	DES_key_schedule key;
	DES_cblock key_1;
	vector<char> key_vect;
	vector<char> c_key;
	c_key = GetCiphKey();
	srand(time(NULL));
	do{
		srand(time(NULL));
		for (int i = 0; i < 8; i++){
			key_1[i] = rand() % 92 + 33;
		}
		Sleep(20);
	} while (DES_set_key(&key_1, &key) < 0);
	//DES_cblock userkey = { 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xf0, 0x0d };
	if (DES_set_key(&key_1, &key) > 0){
		for (int i = 0; i < 8; i++)
			c_key.push_back(key_1[i]);
	}
	SetKeySchedule(key);
	SetCiphKey(c_key);
}


int DES_Cipher::PerformTest()
{
	DES_cblock userkey = { 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xf0, 0x0d };
	DES_cblock plaintext = { 'e', 't', 'a', 'o', 'n', 'r', 'i', 's' };

	DES_key_schedule key;
	DES_cblock ciphertext;
	DES_cblock buf;

	//ERR_clear_error();
	if (DES_set_key(&userkey, &key) < 0)
		return 0;
	DES_ecb_encrypt(&plaintext, &ciphertext, &key, 1);
	DES_ecb_encrypt(&ciphertext, &buf, &key, 0);
	if (memcmp(buf, plaintext, sizeof(buf)))
		return 0;
	return 1;

}


class AES_Cipher: public CipherType{
private:
	//vector<char> plain_text;
	//vector<char> enc_text;
	//vector<char> dec_text;
	//vector<char> ciph_key;
	//int key_len;
	int b_part;
protected:
	void SetKeyLenAES(int ln){ SetKeyLen(ln); }
	void GetKey(uint8_t *key);
	//int GetKeyLen(){ return key_len; }
	//void SetEncText(vector<char> e){ enc_text = e; }
	//void SetDecText(vector<char> d){ dec_text = d; }
	//vector<char> GetPlainText(){ return plain_text; }
	//vector<char> GetEncText(){ return enc_text; }
	void SetPaddingPart(int b_p){ b_part = b_p; }
	int GetPaddingPart(){ return b_part; }
	//void ReadFile(string file_name);
	//void WriteToFile(string file_name);
	void Encrypt();
	void Decrypt();
	void GenerateCipherKey();
public:
	AES_Cipher(){ SetKeyLenAES(16); b_part = 0; }
	void EncryptAES(){ Encrypt(); }
	void DecryptAES(){ Decrypt(); }
	void GenerateCipherKeyAES(){ GenerateCipherKey(); }
	void ReadFileAES(string file_name){ ReadFile(file_name); }
	void WriteToFileAES(string file_name){ WriteToFile(file_name); }
};

void AES_Cipher::GetKey(uint8_t *key)
{
	vector<char> c_key;
	c_key = GetCiphKey();
	for (int i = 0; i < 16; i++){
		key[i] = (uint8_t)c_key[i];
	}
}

void AES_Cipher::GenerateCipherKey()
{
	srand(time(0));//initializing of random generator
	vector<char> c_key;
	c_key = GetCiphKey();
	for (int i = 0; i < GetKeyLen(); i++){
		c_key.push_back((char)(rand() % 92 + 33));
	}
	SetCiphKey(c_key);
}

void AES_Cipher::Decrypt()
{

	vector<char> enc_text;
	vector<char> dec_text;
	vector<char> dec_text_pad;//decrypted text with padding
	uint8_t key[16];
	uint8_t input[16];
	//uint8_t buf[16];
	uint8_t dec_block[16];
	//DES_cblock buf;
	//DES_cblock cipher_block;
	enc_text = GetEncText();
	GetKey(key);
	int block_part = GetPaddingPart();
	for (int i = 0; i <= enc_text.size(); i++){
		if (i % 16 == 0 && i>0){//if we have block of 128 bits
			AES128_ECB_decrypt(input, key, dec_block);
			for (int j = 0; j < 16; j++){//copy new key
				dec_text_pad.push_back(dec_block[j]);
				//buf[j] = 0;

			}
			//continue;//to new iteration
		}
		if (i != enc_text.size()){
			input[i % 16] = enc_text[i];
		}

	}
	for (int i = 0; i < dec_text_pad.size() - (16 - block_part); i++){
		dec_text.push_back(dec_text_pad[i]);
	}
	SetDecText(dec_text);//decrypted text without padding
}

void AES_Cipher::Encrypt()
{
	vector<char> text;
	vector<char> cipher_text;
	uint8_t key[16];
	uint8_t input[16];
	uint8_t cipher_block[16];
	text = GetPlainText();
	GetKey(key);
	int block_part = 0;
	if (text.size() % 16 != 0){
		block_part = text.size() % 16;
		SetPaddingPart(block_part);
		for (int j = block_part; j < 16; j++){
			text.push_back(0);//padding with 0
		}

	}
	for (int i = 0; i <= text.size(); i++){
		if (i % 16 == 0 && i>0){//if we have block of 128 bits
			AES128_ECB_encrypt(input, key, cipher_block);
			for (int j = 0; j < 16; j++){//copy new key
				cipher_text.push_back(cipher_block[j]);
			}
		}
		if (i != text.size()){
			input[i % 16] = text[i];
		}
	}
	SetEncText(cipher_text);
}




int _tmain(int argc, _TCHAR* argv[])
{
	//Create three instances of classes
	VernamCipher v_ciph;
	DES_Cipher d_ciph;
	AES_Cipher a_ciph;
	//Using AES
	a_ciph.ReadFileAES("input.txt");
	a_ciph.GenerateCipherKeyAES();
	a_ciph.EncryptAES();
	a_ciph.DecryptAES();
	a_ciph.WriteToFileAES("aes_output.txt");
	//Using DES
	d_ciph.ReadFileDES("input.txt");
	d_ciph.GenerateCipherKeyDES();
	d_ciph.EncryptDES();
	d_ciph.DecryptDES();
	d_ciph.WriteToFileDES("des_output.txt");
	//d_ciph.PerformTest();
	//Using OTP
	int len;//text length
	v_ciph.ReadFileOTP("input.txt");
	len = v_ciph.GetTextLenOTP();
	v_ciph.SetKeyLenOTP(len);
	v_ciph.GenerateCipherKeyOTP();
	v_ciph.EncryptOTP();
	v_ciph.DecryptOTP();
	v_ciph.WriteToFileOTP("otp_output.txt");
	return 0;
}
//доступ к private - членам можно получить через (имя_класса)::(переменная_член). Но верно ли это с точки зрения ООП?
//всё сложнее. Нужно делать огромное кол-во вспомогательных методов.
